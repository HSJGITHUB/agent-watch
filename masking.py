"""Mask every display string before it leaves the process."""
from __future__ import annotations

import html
import os
import re
import unicodedata
from urllib.parse import unquote, urlsplit

PRIVATE = "(private)"
MASK = "[MASK]"

# User-configured title denylist.
TITLE_DENYLIST: tuple[str, ...] = ()
_DENY_FOLDED: tuple[str, ...] = ()


def configure_title_denylist(terms=()) -> None:
    """Replace title terms with stripped, nonempty case-insensitive substrings."""
    global TITLE_DENYLIST, _DENY_FOLDED
    TITLE_DENYLIST = tuple(term.strip() for term in terms if term.strip())
    _DENY_FOLDED = tuple(term.casefold() for term in TITLE_DENYLIST)


configure_title_denylist(os.environ.get("AGENT_WATCH_TITLE_DENYLIST", "").split(","))


def _c(pattern: str, flags: int = 0) -> re.Pattern:
    # Compile in ASCII mode so word boundaries work when Korean adjoins secret values.
    return re.compile(pattern, flags | re.ASCII)


# Allow plural and environment/version suffixes such as passwords, db_password_prod, and client_secret_v2, but not arbitrary names like password_field.
# Exclude plural token to avoid max_tokens; allow compound access_tokens separately. Do not suffix pass, which overlaps compass and bypass.
_NAME_TAIL = (
    r"(?:(?<![nN])s)?(?:[_-](?:prod|production|prd|dev|development|stg|staging|stage|test|qa|uat|local|live|sandbox"
    r"|old|new|prev|previous|backup|bak|primary|secondary|v?[0-9]+))*"
)
_SECRET_NAMES = (
    r"(?:api[_-]?key|apikey|(?:access|refresh|auth|api|bearer)[_-]?tokens|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret"
    r"|secret[_-]?key|private[_-]?key|token|secret|password|passwd|pwd|credentials?)" + _NAME_TAIL + r"|pass"
)

_HEADER_NAMES = r"authorization|cookie|session[_-]?id|x-api-key"
_BOUNDED_NAMES = r"bearer|signature|sig|session|pat"  # Use a left boundary for names that overlap common words.
_HEADER_RULE_NAMES = r"(?:proxy-)?authorization|(?:set-)?cookie|api-key|private-token|x-[a-z0-9-]*(?:token|key|auth|secret)[a-z0-9-]*"

# Quoted values extend through closing quotes, skipping escaped quotes and crossing newlines.
# Without a closing quote, mask to the end. A trailing backslash conservatively prevents closure.
# For nested JSON, match closing quotes with the same escape depth as the opening quote.
_QV = r"(?P<esc>\\*)(?P<q>[\"'`])[\s\S]*?(?:(?<!\\)(?P=esc)(?P=q)|\Z)"
# Include concatenated strings after the closing quote, including adjacent literals and trailing identifiers.
_QUOTED = r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|`[^`\r\n]*`)"
_CONCAT = (
    r"(?:[ \t]+" + _QUOTED
    + r"|[ \t]*(?:\+|\.|\|\|)[ \t]*(?:" + _QUOTED + r"|[A-Za-z_][A-Za-z0-9_.]*(?:\([^()\r\n]*\))?))*"
)
_EOL = r"(?:\r\n?|\n)"
_SHELL_NL = r"(?:\\\r?\n[ \t]*)"  # Shell line continuation.
# An indented sibling key or code line is not part of the preceding value.
_SIBLING = r"(?:-[ \t]+)?[\"'`]?[A-Za-z0-9_.-]+[\"'`]?[ \t]*[:=](?:\s|\Z)"
_CODE = (
    r"(?:return|if|elif|else|for|while|def|class|import|from|try|except|finally|with|await|async|yield|raise"
    r"|const|let|var|function|print)\b|\#|//|[)\]}]|[^\r\n]*[A-Za-z0-9_]\("
)
_NOT_VALUE = r"(?![ \t]*(?:" + _SIBLING + "|" + _CODE + r"))"
# Allow a value on the next line, but do not cross into sibling keys or code.
_GAP = r"[ \t]*(?:\\?" + _EOL + r"\s*" + _NOT_VALUE + r")?"
_KEY_END = r"\\*[\"'`]?\s*[:=]" + _GAP
# Headers extend to end of line and folded whitespace-prefixed continuations, excluding sibling keys or code.
_CONT = _EOL + r"(?=[ \t]+\S)" + _NOT_VALUE + r"[^\r\n]*"
# Empty, boolean, null-like, and closed quoted values do not fold.
_NO_FOLD = r"(?!(?:true|false|none|null|nil|undefined|~)[,;]?[ \t]*(?:[\r\n]|\Z))"
_HEADER_VALUE = r"(?:" + _QV + r"[^\r\n]*|\S[^\r\n]*(?:" + _CONT + r")*|(?:" + _CONT + r")+)"

# Mask bare values through whitespace; include ampersands, commas, and semicolons unless they introduce another key.
_BARE = r"(?:(?!&[A-Za-z0-9_.%-]+=|[,;](?:\s|\"|\Z))\S)+"

# Skip fully masked values; characters directly after the mask mean some value remains.
_DONE = r"(?!\\\r?\n)(?![\"\']*\[MASK\][\"\']*(?:[\s,;&})\]]|\Z))"

# Order defines priority: headers and quoted values precede general rules.
PATTERNS: list[tuple[re.Pattern, str]] = [
    (_c(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)"), "[KEY]"),
    # YAML block values include all lines indented deeper than their key.
    (
        _c(
            r"^((?P<yi>[ \t]*)(?:-[ \t]+)?[\"']?[A-Za-z0-9_.-]*?(?:" + _SECRET_NAMES + "|" + _HEADER_NAMES + "|" + _HEADER_RULE_NAMES + r")"
            r"[\"']?[ \t]*:[ \t]*)[|>][+-]?[0-9]?[+-]?[ \t]*(?:\#[^\r\n]*)?"
            r"(?:" + _EOL + r"(?:(?P=yi)[ \t]+[^\r\n]*|[ \t]*(?=" + _EOL + r")))+",
            re.I | re.M,
        ),
        r"\1[MASK]",
    ),
    # Mask complete header values, including additional Cookie pairs.
    (
        _c(r"\b(" + _HEADER_RULE_NAMES + r")(\\*[\"']?\s*[:=][ \t]*)" + _NO_FOLD + _HEADER_VALUE, re.I),
        r"\1\2[MASK]",
    ),
    (_c(r"\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@", re.I), r"\1[MASK]@"),
    # Command-line credentials.
    (_c(r"(\bcurl\b[^\r\n]*?\s(?:-u\s*|--user[= ]\s*)" + _SHELL_NL + r"?)(?:" + _QV + r"|\S+)", re.I), r"\1[MASK]"),
    # Handle user:password but exclude numeric uid:gid, identical pairs, and URLs.
    (
        _c(
            r"(?<![A-Za-z0-9_-])((?:-u|--user)(?:[ \t]+|=)" + _SHELL_NL + r"?)"
            r"(?![0-9]+:[0-9]+(?:\s|\Z))(?!(?P<uu>[^\s:\"']+):(?P=uu)(?:\s|\Z))(?![\"']?[A-Za-z0-9+.-]+://)"
            r"(?:[\"'][^\"'\r\n:]+:[^\"'\r\n]*[\"']|[^\s:\"']+:\S*)"
        ),
        r"\1[MASK]",
    ),
    (_c(r"(\bsshpass\s+-p\s*)(?:" + _QV + r"|\S+)", re.I), r"\1[MASK]"),
    (_c(r"(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\r\n]*?\s-p)(?=\S)(?:" + _QV + r"|\S+)", re.I), r"\1[MASK]"),
    # Mask complete quoted values, including spaces.
    (_c(r"((?:" + _SECRET_NAMES + "|" + _HEADER_NAMES + r")" + _KEY_END + r")" + _QV + _CONCAT, re.I), r'\1"[MASK]"'),
    (_c(r"((?<![A-Za-z0-9_-])(?:" + _BOUNDED_NAMES + r")" + _KEY_END + r")" + _QV + _CONCAT, re.I), r'\1"[MASK]"'),
    # Known token prefixes.
    (_c(r"xox[a-z]-[A-Za-z0-9-]{10,}"), MASK),
    (_c(r"xapp-[A-Za-z0-9-]{10,}"), MASK),
    (_c(r"sk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_-]{16,}"), MASK),
    (_c(r"gh[pousr]_[A-Za-z0-9]{20,}"), MASK),
    (_c(r"github_pat_[A-Za-z0-9_]{20,}"), MASK),
    (_c(r"EAA[A-Za-z0-9]{20,}"), MASK),
    (_c(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), MASK),
    (_c(r"AIza[0-9A-Za-z_-]{30,}"), MASK),
    (_c(r"ya29\.[0-9A-Za-z_-]{20,}"), MASK),
    (_c(r"1//[0-9A-Za-z_-]{20,}"), MASK),
    (_c(r"GOCSPX-[A-Za-z0-9_-]{10,}"), MASK),
    (_c(r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"), MASK),
    (_c(r"hooks\.slack\.com/services/[A-Za-z0-9/_-]+"), "hooks.slack.com/services/" + MASK),
    (_c(r"shp(?:at|ss|ca|pa)_[A-Fa-f0-9]{20,}"), MASK),
    (_c(r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}"), MASK),
    (_c(r"Atz[ar]\|[A-Za-z0-9_\-|=+/]{20,}"), MASK),
    (_c(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), MASK),
    # Generic token prefixes, including pk_, hf_, and whsec_.
    (_c(r"\b[a-z]{2,8}_[A-Za-z0-9]{24,}"), MASK),
    (_c(r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", re.I), r"\1 [MASK]"),
    (
        _c(
            r"(?<![A-Za-z0-9_-])(--?(?:[a-z0-9]+[-_])*(?:token|password|passwd|pass|pwd|secret|key|auth|credentials?|bearer)"
            r"(?:[= \t]+" + _SHELL_NL + r"?|[\"']\s*,\s*(?=[\"'][^-])))"
            r"(?:" + _QV + r"|\S+)",
            re.I,
        ),
        r"\1[MASK]",
    ),
    (
        _c(
            r"\b([A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|PASS|PWD|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|KEY|AUTH|CRED)"
            r"[A-Za-z0-9_]*=" + _SHELL_NL + r"?)(?:" + _QV + _CONCAT + r"|\S+)"
        ),
        r"\1[MASK]",
    ),
    (
        _c(
            r"(" + _SECRET_NAMES + "|" + _HEADER_NAMES + r")"
            r"(\\*[\"']?\s*[:=]" + _GAP + r"\\*[\"']?)" + _DONE + _BARE,
            re.I,
        ),
        r"\1\2[MASK]",
    ),
    # Require left boundaries for common-word keys, leaving design and obsession untouched.
    (_c(r"(?<![A-Za-z0-9_-])(" + _BOUNDED_NAMES + r")(\\*[\"']?\s*[:=]" + _GAP + r"\\*[\"']?)" + _DONE + _BARE, re.I), r"\1\2[MASK]"),
    (_c(r"(비밀번호|패스워드|암호|토큰|시크릿)\s*(값은|은|는|:|=)\s*(?:" + _QV + r"|\S+)"), r"\1 \2 [MASK]"),
    (_c(r"([?&](?:key|sig|signature|code|auth|token|access_token|api_key|apikey|secret|password)=)[^&\s#\"']+", re.I), r"\1[MASK]"),
    (_c(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
    (_c(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32,}(?![A-Fa-f0-9])"), "[HEX]"),
]

_RUN_RE = _c(r"[A-Za-z0-9+/_=-]{24,}")
_UUID_RE = _c(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_SUBTOKEN_SPLIT = _c(r"[_\-=+]+")
_TRAILING_DIGITS = _c(r"\d+$")


def _natural_token(tok: str) -> bool:
    """Recognize human-readable fragments; frequent case transitions or mixed digits suggest randomness."""
    if not tok or tok.isdigit():
        return True
    body = _TRAILING_DIGITS.sub("", tok)
    if not body or not body.isalpha():
        return False
    transitions = sum(1 for i in range(1, len(body)) if body[i - 1].islower() and body[i].isupper())
    return transitions <= 2


def _natural_fragment(fragment: str) -> bool:
    return all(_natural_token(t) for t in _SUBTOKEN_SPLIT.split(fragment))


def _has_classes(s: str) -> tuple[bool, bool, bool]:
    return (any(c.isdigit() for c in s), any(c.isupper() for c in s), any(c.islower() for c in s))


def _random_like(p: str) -> bool:
    """Detect case and digit mixtures unlikely to be human-readable names."""
    for t in _SUBTOKEN_SPLIT.split(p):
        if len(t) < 6:
            continue
        d, u, l = _has_classes(t)
        if not (d and u and l):
            continue
        trans = sum(1 for a, b in zip(t, t[1:]) if (a.islower() and b.isupper()) or (a.isdigit() != b.isdigit()))
        if trans >= max(3, len(t) // 3):
            return True
    return False


def _mask_run(m: re.Match) -> str:
    run = m.group(0)
    if _UUID_RE.match(run):
        return run
    if "/" in run:
        parts = run.split("/")
        real = [p for p in parts if p]
        natural = sum(1 for p in real if _natural_fragment(p))
        if natural * 2 < len(real) or any(_random_like(p) for p in real):
            return MASK  # Mask slash-separated secrets unless most fragments look like natural names.
        out = []
        for p in parts:
            d, u, l = _has_classes(p)
            out.append(MASK if len(p) >= 24 and d and u and l else p)
        return "/".join(out)
    if _natural_fragment(run):
        return run
    d, u, l = _has_classes(run)
    if d and u and l:
        return MASK
    if len(run) >= 40 and d and (u or l):
        return MASK
    if u and l and sum(1 for a, b in zip(run, run[1:]) if a.islower() and b.isupper()) >= len(run) // 5:
        return MASK
    return run


_ZERO_WIDTH = "\u00ad\u200b-\u200f\u2060\ufeff"  # Soft hyphen and zero-width characters.
_ZERO_WIDTH_RE = re.compile(f"[{_ZERO_WIDTH}]")
_ENC_HINT_RE = re.compile(f"[%\\\\&{_ZERO_WIDTH}\uff01-\uff5e]")
_ENC_TOKEN_RE = _c(
    r"(?:[A-Za-z0-9_-]|\\+u[0-9a-fA-F]{4}|\\+u\{[0-9a-fA-F]{1,6}\}|\\+U[0-9a-fA-F]{8}|\\+x[0-9a-fA-F]{2}|\\+[0-3][0-7]{2}"
    r"|%[0-9a-fA-F]{2}|&\#[0-9]{1,7};|&\#[xX][0-9a-fA-F]{1,6};|&[A-Za-z]{2,8};|"
    + _SHELL_NL + "|[" + _ZERO_WIDTH + "\uff01-\uff5e])+"
)
_ENC_ESC_RE = _c(r"\\+(?:u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\}|U([0-9a-fA-F]{8})|x([0-9a-fA-F]{2})|([0-3][0-7]{2}))")
_SHELL_NL_RE = _c(_SHELL_NL)
# Use word boundaries. Alphanumeric neighbors belong to other words; common names such as session also treat underscores and hyphens as word characters.
_ENC_NAME_RE = _c(
    r"(?<![A-Za-z0-9])(?:" + _SECRET_NAMES + "|" + _HEADER_NAMES + r")(?![A-Za-z0-9])"
    r"|(?<![A-Za-z0-9_-])(?:" + _BOUNDED_NAMES + r")(?![A-Za-z0-9_-])"
    r"|[?&](?:key|code|auth)=",
    re.I,
)
_ENC_SEP_RE = _c(r"\\*[\"'`]?\s*[:=]")
_ENT_QUOTE = r"&(?:quot|apos|\#0*3[49]|\#[xX]0*2[27]);"
_ENT_QUOTE_RE = _c(_ENT_QUOTE)
_ENT_AFTER_KEY_RE = _c(r"(?:" + _SECRET_NAMES + "|" + _HEADER_NAMES + r")(?:" + _ENT_QUOTE + r")?\s*[:=]\s*" + _ENT_QUOTE, re.I)


def _escape_char(m: re.Match) -> str:
    code = int(m.group(5), 8) if m.group(5) else int(m.group(1) or m.group(2) or m.group(3) or m.group(4), 16)
    return chr(code) if code <= 0x10FFFF else ""


def _decoded_key(token: str) -> str:
    """Decode only to recognize keys. Use decoded text for display only when masking a value."""
    for _ in range(3):  # Handle up to three encoding layers.
        plain = html.unescape(unquote(_ENC_ESC_RE.sub(_escape_char, _SHELL_NL_RE.sub("", token))))
        if plain == token:
            break
        token = plain
    return _CTRL_RE.sub("", _ZERO_WIDTH_RE.sub("", unicodedata.normalize("NFKC", token)))


def _is_key(plain: str, after: str) -> bool:
    """Check decoded tokens for credential keys followed by values; names alone must not change display text."""
    text = plain + after
    for m in _ENC_NAME_RE.finditer(plain):
        if m.group(0).endswith("=") or _ENC_SEP_RE.match(text, m.end()):
            return True
    return False


def _reveal_encoded_keys(s: str) -> str:
    """Decode hidden credential keys for subsequent masking rules. Leave display text unchanged when no value needs masking."""
    if not _ENC_HINT_RE.search(s):
        return s
    revealed = False

    def reveal(m: re.Match) -> str:
        nonlocal revealed
        token = m.group(0)
        if token.isascii() and "%" not in token and "\\" not in token and "&" not in token:
            return token
        plain = _decoded_key(token)
        if not _is_key(plain, s[m.end(): m.end() + 8]):
            return token
        revealed = True
        return plain

    out = _ENC_TOKEN_RE.sub(reveal, s)
    # Decode entity quotes around values so the entire value is masked.
    if revealed or _ENT_AFTER_KEY_RE.search(out):
        out = _ENT_QUOTE_RE.sub(lambda m: html.unescape(m.group(0)), out)
    return out


def mask_patterns(s: str) -> str:
    s = _reveal_encoded_keys(s)
    for rx, rep in PATTERNS:
        s = rx.sub(rep, s)
    return _RUN_RE.sub(_mask_run, s)


# Hide the host and share of UNC paths without matching URL scheme separators.
_UNC_BACK = re.compile(r"\\\\[^\\/\r\n\t\"'<>|]+\\[^\\/\r\n\t\"'<>|]+")
_UNC_FWD = re.compile(r"(?<![:/A-Za-z0-9])//[^/\\\r\n\t\"'<>|]+/[^/\\\r\n\t\"'<>|]+")
_HOME_RE = re.compile(r"[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s\"']+(?=$|[\\/\s\"'])", re.I)
_WINPATH_RE = re.compile(r"(?:(?<![A-Za-z0-9])[A-Za-z]:|~|UNC:)\\[^\s\"'<>|]*")
_SCRATCH_RE = re.compile(r"~/AppData/Local/Temp/claude/[^\s\"']*?/scratchpad(?:/[^\s\"']*)?", re.I)
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\ud800-\udfff]")


def shorten_paths(s: str) -> str:
    s = _UNC_BACK.sub(lambda m: "UNC:" if s[m.end():m.end()+1] == "\\" else "UNC:/", s)
    s = _UNC_FWD.sub(lambda m: "UNC:" if s[m.end():m.end()+1] == "/" else "UNC:/", s)
    s = _HOME_RE.sub("~", s)
    s = _WINPATH_RE.sub(lambda m: m.group(0).replace("\\", "/"), s)
    return _SCRATCH_RE.sub("(scratchpad)", s)


def path_display(path: object) -> str:
    """Convert a source path to a display path with forward-slash separators."""
    s = str(path).replace("\\", "/")
    return shorten_paths(mask_patterns(s))


def is_denied(s: object) -> bool:
    if not isinstance(s, str) or not s:
        return False
    if s == PRIVATE:
        return True
    t = s.casefold()
    return any(d in t for d in _DENY_FOLDED)


def safe_text(raw: object, limit: int, first_line: bool = False) -> str:
    """Convert raw text to display text, masking before truncation."""
    if not isinstance(raw, str) or not raw:
        return ""
    cap = max(limit * 4, 512)
    cut = len(raw) > cap
    s = _CTRL_RE.sub("", raw[:cap])
    s = mask_patterns(s)
    if cut:
        # Discard the pre-truncation tail so partial secrets cannot enter the visible range after masking.
        s = s[:-64] if len(s) > 64 else ""
    s = shorten_paths(s)
    if first_line:
        for line in s.splitlines():
            if line.strip():
                s = line
                break
        else:
            s = ""
    s = " ".join(s.split())
    return s[:limit] + ("…" if len(s) > limit else "")


def field(raw: object, limit: int, first_line: bool = False) -> str | None:
    """Display field with title-denylist filtering; None when empty."""
    if not isinstance(raw, str) or not raw.strip():
        return None
    if is_denied(raw):
        return PRIVATE
    return safe_text(raw, limit, first_line) or None


_ENV_ASSIGN = _c(r"^[A-Za-z_][A-Za-z0-9_]*=")
_EXE_NAME = _c(r"[A-Za-z0-9._+-]{1,40}")


def command_first_token(command: object) -> str | None:
    """Display only the executable name for Claude Bash commands, structurally excluding secrets in arguments."""
    if not isinstance(command, str):
        return None
    for line in command.splitlines():
        line = line.strip()
        if not line:
            continue
        for tok in line.split():
            tok = tok.strip("\"'`()")
            if not tok or _ENV_ASSIGN.match(tok):
                continue
            name = tok.replace("\\", "/").rsplit("/", 1)[-1]
            # Validate before truncating; long values and assignments cannot be executable names.
            return name if _EXE_NAME.fullmatch(name) else "(command)"
        return None
    return None


def _basename(p: object) -> str | None:
    if not isinstance(p, str) or not p:
        return None
    return p.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or None


def _host_only(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    try:
        return urlsplit(url).hostname or None
    except ValueError:
        return None


_ARG_LIMIT = 80


def summarize_tool_input(name: object, inp: object) -> str | None:
    """Allowlisted tool fields; unknown tools display only their names."""
    if not isinstance(name, str):
        return None
    d = inp if isinstance(inp, dict) else {}
    if name in ("Bash", "PowerShell"):
        raw = d.get("description")
        text = field(raw, 60, first_line=True) if isinstance(raw, str) and raw.strip() else None
        if text is None:
            token = command_first_token(d.get("command"))
            text = field(token, 60) if token else None
        if d.get("run_in_background") and text:
            return "[bg] " + text
        return text
    if name in ("Read", "Edit", "Write"):
        return field(_basename(d.get("file_path")), _ARG_LIMIT)
    if name == "NotebookEdit":
        return field(_basename(d.get("notebook_path")), _ARG_LIMIT)
    if name in ("Grep", "Glob"):
        return field(d.get("pattern"), 60, first_line=True)
    if name in ("Agent", "Task"):
        desc = field(d.get("description"), _ARG_LIMIT, first_line=True)
        sub = field(d.get("subagent_type"), 32)
        if desc and sub and desc != PRIVATE:
            return f"{desc} ({sub})"[: _ARG_LIMIT + 1]
        return desc or sub
    if name == "WebFetch":
        return field(_host_only(d.get("url")), _ARG_LIMIT)
    if name in ("WebSearch", "ToolSearch"):
        return field(d.get("query"), 60, first_line=True)
    if name == "Skill":
        return field(d.get("skill"), _ARG_LIMIT)
    if name in ("TaskStop", "TaskOutput"):
        return field(d.get("task_id"), _ARG_LIMIT)
    if name == "SendMessage":
        return field(d.get("to"), _ARG_LIMIT)
    if name == "Monitor":
        return field(d.get("description"), _ARG_LIMIT, first_line=True)
    if name == "StructuredOutput":
        return "(submit final result)"
    if name in ("Artifact", "ArtifactData", "ArtifactComments"):
        return field(d.get("action"), _ARG_LIMIT)
    if name.startswith("mcp__"):
        rest = name[5:]
        server, _, tool = rest.partition("__")
        if tool:
            return safe_text(f"{server}/{tool}", _ARG_LIMIT)
    return None


_JS_ESC = re.compile(r"\\(.)", re.S)
_JS_MAP = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "'": "'", "\\": "\\", "/": "/", "`": "`"}


def js_unescape(s: str) -> str:
    """Unescape JavaScript strings in Codex custom_tool_call input before selecting the first line."""
    return _JS_ESC.sub(lambda m: _JS_MAP.get(m.group(1), m.group(0)), s)
