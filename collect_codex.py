"""Collect Codex rollouts and weekly usage. File mtime is never used for status decisions."""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime

import model
import status as st
from claude_parse import parse_ts
from collect_claude import NullLog, Stats
from config import (
    CODEX_DAY_FOLDERS,
    CODEX_EVENTS_KEEP,
    CODEX_GAP_TICK_CAP,
    CODEX_OUTPUT_SCAN,
    CODEX_PENDING_MAX,
    CODEX_RUNS_MAX,
    CODEX_USAGE_FALLBACK_DAYS,
    CODEX_USAGE_FALLBACK_FILES,
    CODEX_WINDOW_H,
    FINISHED_KEEP_S,
    INIT_TAIL,
    PER_FILE_TICK_CAP,
    STALE_KEEP_S,
    Paths,
)
from masking import field, js_unescape, path_display, safe_text
from tailreader import Budget, IncrementalReader, read_head, read_tail
from winproc import open_shared

ROLLOUT_RE = re.compile(r"^rollout-(\d{4})-(\d{2})-(\d{2})T(\d{2})-(\d{2})-(\d{2})-([0-9a-fA-F-]{36})\.jsonl$")
# Keys may be quoted; values may be strings or template literals.
CMD_RE = re.compile(r'"?\bcmd"?\s*:\s*(?:"((?:[^"\\]|\\.)*)"|`((?:[^`\\]|\\.)*)`)')
CHARS_RE = re.compile(r'"?\bchars"?\s*:\s*"((?:[^"\\]|\\.)*)"')
TOOL_NAME_RE = re.compile(r"tools\.([A-Za-z_][A-Za-z0-9_]*)\s*\(")
CWD_HEAD_RE = re.compile(r'"cwd"\s*:\s*"((?:[^"\\]|\\.)*)"')
THREAD_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEAVY_HEADS = (b'"type":"world_state"',)
TURN_START_MARK = b'"type":"task_started"'
TURN_DONE_MARK = b'"type":"task_complete"'
CONTEXT_MARK = b'"type":"turn_context"'
# A running exec_command returns session_id instead of exit_code.
LIVE_SESSION_RE = re.compile(r'"session_id"\s*:\s*\d+')
SCRIPT_RUNNING = "Script running"
SCRIPT_SHAPED = "(script-generated command)"


def filename_start_ms(name: str) -> int | None:
    m = ROLLOUT_RE.match(name)
    if not m:
        return None
    y, mo, d, h, mi, s = (int(x) for x in m.groups()[:6])
    try:
        return int(datetime(y, mo, d, h, mi, s).timestamp() * 1000)
    except ValueError:
        return None


class CodexRec:
    """State for one rollout file; retain only masked display strings."""

    __slots__ = (
        "path", "name", "reader", "thread_id", "cwd", "packet", "originator", "cli_version", "source_kind",
        "parent_thread_id", "model", "effort", "sandbox", "started_ms", "last_record_ms", "last_growth_ms",
        "finished_ms", "turns_started", "turns_completed", "turn_open", "outcome", "desktop", "tokens",
        "running", "last_done", "pending_wait", "pending_wait_ids", "last_message", "events", "head_done",
        "first_done", "dormant", "file_start_ms", "turns_exact", "gap_pos", "gap_end", "open_cells", "gen",
        "head_pending", "ev_key", "ev_snap",
    )

    def __init__(self, path: str, name: str, file_start_ms: int | None):
        self.path = path
        self.name = name
        self.reader = IncrementalReader(path, tail=INIT_TAIL)
        self.thread_id: str | None = None
        self.cwd: str | None = None
        self.packet: str | None = None
        self.originator: str | None = None
        self.cli_version: str | None = None
        self.source_kind: str | None = None
        self.parent_thread_id: str | None = None
        self.model: str | None = None
        self.effort: str | None = None
        self.sandbox: str | None = None
        self.started_ms: int | None = file_start_ms
        self.last_record_ms: int | None = None
        self.last_growth_ms: int | None = None
        self.finished_ms: int | None = None
        self.turns_started = 0
        self.turns_completed = 0
        self.turn_open = True
        self.outcome: str | None = None
        self.desktop = False
        self.tokens: dict | None = None
        self.running: list[dict] = []
        self.last_done: dict | None = None
        self.pending_wait: str | None = None
        self.pending_wait_ids: dict[str, str] = {}
        self.last_message: str | None = None
        self.events = model.EventLog(CODEX_EVENTS_KEEP)
        self.head_done = False
        self.first_done = False
        self.dormant = False
        self.file_start_ms = file_start_ms
        self.turns_exact = True  # Whether the whole file or the gap between head and tail has been counted.
        self.gap_pos = 0
        self.gap_end = 0
        self.open_cells: set[str] = set()  # Calls whose script cells are still running.
        self.gen = 0  # File generation read by this state.
        self.head_pending = False  # Head skipped because the run was dormant.
        self.ev_key = None
        self.ev_snap: tuple = ()

    @property
    def running_cmd_since_ms(self) -> int | None:
        return self.running[-1]["since_ms"] if self.running else None

    def feed(self, rec: dict, rate_cb) -> None:
        ts = parse_ts(rec.get("timestamp"))
        if ts is not None and (self.last_record_ms is None or ts > self.last_record_ms):
            self.last_record_ms = ts
        t = rec.get("type")
        p = rec.get("payload")
        if not isinstance(p, dict):
            return
        if t == "session_meta":
            self._session_meta(p, ts)
        elif t == "turn_context":
            self._turn_context(p)
        elif t == "event_msg":
            self._event(p, ts, rate_cb)
        elif t == "response_item":
            self._response_item(p, ts)

    def _session_meta(self, p: dict, ts: int | None) -> None:
        self.head_done = True
        tid = p.get("id") or p.get("session_id")
        if isinstance(tid, str) and THREAD_RE.match(tid):
            self.thread_id = tid
        cwd = p.get("cwd")
        if isinstance(cwd, str):
            self.cwd = cwd
            self.packet = cwd.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or None
        if isinstance(p.get("originator"), str):
            self.originator = p["originator"]
            if "desktop" in p["originator"].lower():
                self.desktop = True
        if isinstance(p.get("cli_version"), str):
            self.cli_version = p["cli_version"]
        src = p.get("source")
        if isinstance(src, str):
            self.source_kind = src if src in ("exec", "vscode") else "other"
            if src == "vscode":
                self.desktop = True
        elif isinstance(src, dict):
            sub = src.get("subagent")
            if isinstance(sub, dict):
                spawn = sub.get("thread_spawn")
                if isinstance(spawn, dict):
                    self.source_kind = "subagent"
                    parent = spawn.get("parent_thread_id")
                    if isinstance(parent, str) and THREAD_RE.match(parent):
                        self.parent_thread_id = parent
                elif sub.get("other") == "guardian":
                    self.source_kind = "guardian"
                else:
                    self.source_kind = "subagent"
            else:
                self.source_kind = "other"
        if ts is not None:
            self.started_ms = ts

    def _turn_context(self, p: dict) -> None:
        if isinstance(p.get("model"), str):
            self.model = p["model"]
        if isinstance(p.get("effort"), str):
            self.effort = p["effort"]
        sp = p.get("sandbox_policy")
        if isinstance(sp, dict) and isinstance(sp.get("type"), str):
            self.sandbox = sp["type"]
        if not self.cwd and isinstance(p.get("cwd"), str):
            self.cwd = p["cwd"]
            self.packet = self.cwd.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or None

    def _event(self, p: dict, ts: int | None, rate_cb) -> None:
        et = p.get("type")
        if et == "task_started":
            self.turns_started += 1
            self.turn_open = True
            self.outcome = None
            self.finished_ms = None
            self.events.append({"ts_ms": ts, "kind": "turn_start", "tool": None, "arg": None, "ok": None, "text": None})
        elif et == "task_complete":
            self.turns_completed += 1
            self.turn_open = False
            self.outcome = "completed"
            done = p.get("completed_at")
            # completed_at is a ten-digit timestamp in seconds.
            self.finished_ms = int(done * 1000) if isinstance(done, (int, float)) else ts
            self._close_pending()
            msg = p.get("last_agent_message")
            if isinstance(msg, str):
                self.last_message = field(msg, 120, first_line=True)
            self.events.append({"ts_ms": ts, "kind": "turn_end", "tool": None, "arg": None, "ok": None, "text": None})
        elif et == "token_count":
            info = p.get("info")
            if isinstance(info, dict):
                tu = info.get("total_token_usage")
                if isinstance(tu, dict):
                    self.tokens = {
                        "total": _num(tu.get("total_tokens")),
                        "input": _num(tu.get("input_tokens")),
                        "cached": _num(tu.get("cached_input_tokens")),
                        "output": _num(tu.get("output_tokens")),
                        "reasoning": _num(tu.get("reasoning_output_tokens")),
                    }
            rl = p.get("rate_limits")
            if isinstance(rl, dict) and ts is not None:
                rate_cb(ts, rl)
        elif et == "item_completed":
            item = p.get("item")
            if isinstance(item, dict):
                self._item_completed(item, p, ts)
        elif et == "turn_aborted":
            self.turn_open = False
            self.outcome = "other"
            self.finished_ms = ts
            self._close_pending()
            self.events.append({"ts_ms": ts, "kind": "turn_end", "tool": None, "arg": None, "ok": None, "text": None})
        elif isinstance(et, str) and ("abort" in et.lower() or "error" in et.lower()):
            self.outcome = "other"

    def _close_pending(self) -> None:
        self.running.clear()
        self.open_cells.clear()
        self.pending_wait = None
        self.pending_wait_ids.clear()

    def _item_completed(self, item: dict, p: dict, ts: int | None) -> None:
        it = item.get("type")
        if it == "CommandExecution":
            text = None
            parsed = item.get("parsed_cmd")
            if isinstance(parsed, list) and parsed and isinstance(parsed[-1], dict):
                text = parsed[-1].get("cmd")
            if not isinstance(text, str):
                cmd = item.get("command")
                if isinstance(cmd, list) and cmd and isinstance(cmd[-1], str):
                    text = cmd[-1]
            exit_code = item.get("exit_code")
            shown = safe_text(text, 80, first_line=True) if isinstance(text, str) else None
            cmd = item.get("command")
            raw = cmd[-1] if isinstance(cmd, list) and cmd and isinstance(cmd[-1], str) else None
            self._drop_finished({shown, safe_text(raw, 80, first_line=True) if raw else None})
            self.last_done = {
                "text": shown, "state": "done", "exit_code": exit_code if isinstance(exit_code, int) else None,
                "since_ms": p.get("started_at_ms") if isinstance(p.get("started_at_ms"), int) else ts,
            }
            self.events.append(
                {"ts_ms": ts, "kind": "tool_result", "tool": "exec", "arg": safe_text(text, 120, first_line=True) if isinstance(text, str) else None,
                 "ok": exit_code == 0 if isinstance(exit_code, int) else None, "text": None}
            )
        elif it == "AgentMessage":
            content = item.get("content")
            text = None
            if isinstance(content, list) and content and isinstance(content[0], dict):
                text = content[0].get("text")
            if isinstance(text, str) and text.strip():
                self.last_message = field(text, 120, first_line=True)
                self.events.append(
                    {"ts_ms": ts, "kind": "text", "tool": None, "arg": None, "ok": None, "text": self.last_message}
                )

    def _drop_finished(self, texts: set) -> None:
        """Remove one completed command, matching its text first and otherwise using launch order."""
        for i, r in enumerate(self.running):
            if r["text"] in texts:
                del self.running[i]
                return
        if self.running:
            self.running.pop(0)

    def _settle_output(self, call_ids: set, output: object) -> None:
        """Tool output ends its command unless it contains a long-running marker. Discard the body after checking markers."""
        text = _output_text(output)
        if text.lstrip().startswith(SCRIPT_RUNNING):
            self.open_cells |= call_ids  # Script is still running; check subsequent wait output.
            while len(self.open_cells) > CODEX_PENDING_MAX:
                self.open_cells.pop()
            return
        rows = [r for r in self.running if r.get("call_id") in call_ids]
        keep = len(LIVE_SESSION_RE.findall(text))
        done = rows[: len(rows) - keep] if keep < len(rows) else []
        if done:
            self.running = [r for r in self.running if not any(r is x for x in done)]
        self.open_cells -= call_ids

    def _response_item(self, p: dict, ts: int | None) -> None:
        pt = p.get("type")
        if pt == "custom_tool_call":
            self._custom_call(p, ts)
        elif pt == "function_call":
            name = p.get("name")
            cid = p.get("call_id")
            if isinstance(name, str) and isinstance(cid, str):
                self.pending_wait_ids[cid] = name
                while len(self.pending_wait_ids) > CODEX_PENDING_MAX:
                    self.pending_wait_ids.pop(next(iter(self.pending_wait_ids)))
                self.pending_wait = safe_text(name, 32)
        elif pt == "function_call_output":
            cid = p.get("call_id")
            if isinstance(cid, str):
                name = self.pending_wait_ids.pop(cid, None)
                self.pending_wait = safe_text(next(reversed(self.pending_wait_ids.values())), 32) if self.pending_wait_ids else None
                if name == "wait" and self.open_cells:
                    self._settle_output(set(self.open_cells), p.get("output"))
        elif pt == "custom_tool_call_output":
            cid = p.get("call_id")
            if isinstance(cid, str):
                self._settle_output({cid}, p.get("output"))

    def _custom_call(self, p: dict, ts: int | None) -> None:
        inp = p.get("input")
        if not isinstance(inp, str):
            return
        names = TOOL_NAME_RE.findall(inp)
        if "exec_command" in names:
            found = False
            for m in CMD_RE.finditer(inp):
                raw = m.group(1) if m.group(1) is not None else m.group(2)
                text = js_unescape(raw)  # Unescape before masking and taking the first line.
                shown = safe_text(text, 80, first_line=True)
                self.running.append({"text": shown, "since_ms": ts, "call_id": p.get("call_id")})
                found = True
            if not found:
                self.running.append({"text": SCRIPT_SHAPED, "since_ms": ts, "call_id": p.get("call_id")})
            del self.running[:-CODEX_PENDING_MAX]
            self.events.append({"ts_ms": ts, "kind": "tool_call", "tool": "exec", "arg": self.running[-1]["text"], "ok": None, "text": None})
            return
        if names == ["write_stdin"] or set(names) == {"write_stdin"}:
            # Empty polls do not replace the current command.
            m = CHARS_RE.search(inp)
            if m and m.group(1):
                self.events.append({"ts_ms": ts, "kind": "tool_call", "tool": "write_stdin", "arg": None, "ok": None, "text": None})
            return
        if names:
            self.last_done = {"text": safe_text(names[-1], 80), "state": "done", "exit_code": None, "since_ms": ts}
            self.events.append({"ts_ms": ts, "kind": "tool_call", "tool": safe_text(names[-1], 40), "arg": None, "ok": None, "text": None})

    def last_command(self) -> dict | None:
        if self.running:
            r = self.running[-1]
            return {"text": r["text"], "state": "running", "exit_code": None, "since_ms": r["since_ms"]}
        return dict(self.last_done) if self.last_done else None


class CodexCollector:
    def __init__(self, paths: Paths, stats: Stats | None = None, log=None):
        self.paths = paths
        self.stats = stats or Stats()
        self.log = log or NullLog()
        self.runs: dict[str, CodexRec] = {}
        self.sizes: dict[str, int] = {}  # Keep only files seen by the latest discovery.
        self.evicted: set[str] = set()  # Runs evicted by the cap; restore only when they grow.
        self.omitted = 0  # Rows omitted by the display cap.
        self.rate_ts = 0
        self.rate: dict | None = None
        self.fallback_done = False

    def _on_rate(self, ts: int, rl: dict) -> None:
        if ts >= self.rate_ts:
            self.rate_ts = ts
            self.rate = _pick_rate(rl)

    def _day_dirs(self) -> list[str]:
        out = []
        now = time.time()
        root = str(self.paths.codex_sessions_dir)
        for i in range(CODEX_DAY_FOLDERS):
            t = time.localtime(now - 86400 * i)
            out.append(os.path.join(root, f"{t.tm_year:04d}", f"{t.tm_mon:02d}", f"{t.tm_mday:02d}"))
        return out

    def discover(self, now_ms: int, budget: Budget) -> None:
        cutoff = now_ms - CODEX_WINDOW_H * 3600_000
        seen: dict[str, int] = {}
        for d in self._day_dirs():
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                entries = []
                for e in it:
                    if ROLLOUT_RE.match(e.name):
                        try:
                            entries.append((e.name, e.path, e.stat().st_size))
                        except OSError:
                            continue
            for name, path, size in entries:
                seen[path] = size
                if path in self.runs:
                    continue
                start = filename_start_ms(name)
                prev = self.sizes.get(path)
                grown = prev is not None and size > prev
                if grown:
                    self.evicted.discard(path)
                if (start is not None and start >= cutoff and path not in self.evicted) or grown:
                    self.runs[path] = CodexRec(path, name, start)
        self.sizes = seen
        self.evicted &= seen.keys()
        self._evict(now_ms)
        self._wake_dormant()  # Wake after cleanup, or the same pass may immediately put the run back to sleep.
        if not self.fallback_done:
            self.fallback_done = True
            if self.rate is None:
                self._usage_fallback()

    def _wake_dormant(self) -> None:
        """Stat dormant runs at discovery intervals, including files outside the three-day folders."""
        for r in self.runs.values():
            if not r.dormant:
                continue
            try:
                s = os.stat(r.path)
            except OSError:
                continue
            if r.reader.changed(s):
                r.dormant = False

    def _evict(self, now_ms: int) -> None:
        """Make expired runs dormant; evict dormant and oldest entries first when capped."""
        for r in self.runs.values():
            if r.first_done and not r.dormant and _past_window(r, st.codex_status(r, now_ms), now_ms):
                r.dormant = True
        over = len(self.runs) - CODEX_RUNS_MAX
        if over <= 0:
            return
        rows = sorted(self.runs.values(), key=lambda r: (not r.dormant, r.last_record_ms or r.file_start_ms or 0))
        for r in rows[:over]:
            self.runs.pop(r.path, None)
            self.evicted.add(r.path)

    def _usage_fallback(self) -> None:
        """If the initial three-day scan has no usage, scan the last 14 days in reverse filename order, reading at most five file tails."""
        now = time.time()
        root = str(self.paths.codex_sessions_dir)
        checked = 0
        for i in range(CODEX_USAGE_FALLBACK_DAYS):
            t = time.localtime(now - 86400 * i)
            d = os.path.join(root, f"{t.tm_year:04d}", f"{t.tm_mon:02d}", f"{t.tm_mday:02d}")
            try:
                names = sorted((n for n in os.listdir(d) if ROLLOUT_RE.match(n)), reverse=True)
            except OSError:
                continue
            for n in names:
                if checked >= CODEX_USAGE_FALLBACK_FILES:
                    return
                checked += 1
                p = os.path.join(d, n)
                try:
                    data = read_tail(p, os.stat(p).st_size, INIT_TAIL)
                except OSError:
                    continue
                for ln in data.split(b"\n")[1:]:
                    if b"rate_limits" in ln and b"used_percent" in ln:
                        rec = _loads(ln)
                        if not rec:
                            continue
                        pl = rec.get("payload")
                        ts = parse_ts(rec.get("timestamp"))
                        if isinstance(pl, dict) and isinstance(pl.get("rate_limits"), dict) and ts is not None:
                            self._on_rate(ts, pl["rate_limits"])
                if self.rate is not None:
                    return

    def tick(self, now_ms: int, budget: Budget) -> None:
        rows = list(self.runs.values())
        # HOT order uses observed growth time, not mtime.
        rows.sort(key=lambda r: (r.last_growth_ms or 0, r.file_start_ms or 0), reverse=True)
        for r in rows:
            if r.dormant:
                continue
            try:
                self._poll(r, now_ms, budget)
            except OSError as e:
                if not isinstance(e, (FileNotFoundError, PermissionError)):
                    self.log.error("codex_read", e)
        self._scan_gaps(budget)

    def _poll(self, r: CodexRec, now_ms: int, budget: Budget) -> None:
        s = os.stat(r.path)
        if not r.reader.changed(s) and r.first_done:
            return
        cap = budget.allow(PER_FILE_TICK_CAP)
        if cap <= 0:
            return
        was_started = r.reader.started
        lines = r.reader.poll(s, cap)
        got = r.reader.last_read
        budget.spend(got)
        if r.reader.generation != r.gen:
            r = self._replaced(r)
        if was_started and got > 0:
            r.last_growth_ms = now_ms
        self._feed(r, lines)
        if not r.first_done and r.reader.caught_up():
            r.first_done = True
            self._after_first_read(r, s, now_ms)
        elif r.head_pending:
            r.head_pending = False  # Woke from dormancy; read the skipped head.
            self._after_first_read(r, s, now_ms)

    def _replaced(self, r: CodexRec) -> CodexRec:
        """Replacement at the same path: discard completion, commands, and turn counts, retaining only the reader."""
        fresh = CodexRec(r.path, r.name, r.file_start_ms)
        fresh.reader = r.reader
        fresh.gen = r.reader.generation
        self.runs[r.path] = fresh
        return fresh

    def _after_first_read(self, r: CodexRec, s: os.stat_result, now_ms: int) -> None:
        """Read the tail first; skip heads for long-completed runs."""
        if not r.turn_open and r.finished_ms and (now_ms - r.finished_ms) / 1000 > FINISHED_KEEP_S:
            r.dormant = True
            r.head_pending = r.reader.first_start > 0
            return
        if r.reader.first_start == 0:
            return
        try:
            head = read_head(r.path, INIT_TAIL)
        except OSError:
            r.turns_exact = False
            return
        if not r.head_done:
            first = head.split(b"\n", 1)[0]
            rec = _loads(first)
            if rec is not None:
                r.feed(rec, self._on_rate)
            else:
                m = CWD_HEAD_RE.search(first.decode("utf-8", "replace"))
                if m:
                    try:
                        cwd = json.loads('"' + m.group(1) + '"')
                    except ValueError:
                        cwd = None
                    if isinstance(cwd, str):
                        r.cwd = cwd
                        r.packet = cwd.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or None
                r.head_done = True
        self._scan_head(r, head)

    def _scan_head(self, r: CodexRec, head: bytes) -> None:
        """Read only turn_context and turn counts before the tail. Feeding task_started into r.feed would revive completed turns."""
        end = min(len(head), r.reader.first_start)
        cut = head.rfind(b"\n", 0, end) + 1
        body = head[:cut]
        r.turns_started += body.count(TURN_START_MARK)
        r.turns_completed += body.count(TURN_DONE_MARK)
        if r.model is None or r.effort is None or r.sandbox is None:
            latest = None
            for ln in body.split(b"\n"):
                if CONTEXT_MARK in ln[:160]:
                    rec = _loads(ln)
                    if rec is not None and isinstance(rec.get("payload"), dict):
                        latest = rec["payload"]
            if latest is not None:
                prev = (r.model, r.effort, r.sandbox)
                r._turn_context(latest)
                r.model = prev[0] or r.model
                r.effort = prev[1] or r.effort
                r.sandbox = prev[2] or r.sandbox
        r.gap_pos = cut
        r.gap_end = r.reader.first_start
        r.turns_exact = r.gap_pos >= r.gap_end

    def _scan_gaps(self, budget: Budget) -> None:
        """Count turns in the head-tail gap using markers only, one file per tick up to a line boundary."""
        for r in self.runs.values():
            if r.gap_pos >= r.gap_end or r.dormant:
                continue
            cap = budget.allow(CODEX_GAP_TICK_CAP)
            if cap <= 0:
                return
            n = min(cap, r.gap_end - r.gap_pos)
            try:
                with open_shared(r.path) as f:
                    f.seek(r.gap_pos)
                    data = f.read(n)
            except OSError:
                r.gap_end = r.gap_pos  # Give up on unreadable files without changing exactness.
                return
            if not data:
                r.gap_end = r.gap_pos
                return
            budget.spend(len(data))
            if r.gap_pos + len(data) < r.gap_end:
                nl = data.rfind(b"\n")
                if nl >= 0:
                    data = data[: nl + 1]
            r.turns_started += data.count(TURN_START_MARK)
            r.turns_completed += data.count(TURN_DONE_MARK)
            r.gap_pos += len(data)
            if r.gap_pos >= r.gap_end:
                r.turns_exact = True
            return

    def _feed(self, r: CodexRec, lines: list[bytes]) -> None:
        for ln in lines:
            head = ln[:96]
            if any(h in head for h in HEAVY_HEADS):
                continue
            rec = _loads(ln)
            if rec is None:
                self.stats.bad_lines += 1
                continue
            try:
                r.feed(rec, self._on_rate)
            except Exception as e:
                self.stats.parse_errors += 1
                self.log.error("codex_feed", e)

    def build(self, now_ms: int) -> tuple[list[dict], dict, dict]:
        views: list[dict] = []
        recs: dict[str, CodexRec] = {}
        for r in self.runs.values():
            if not r.first_done or r.dormant:
                continue  # Do not classify unread runs.
            v = st.codex_status(r, now_ms)
            if _past_window(r, v, now_ms):
                continue
            thread = r.thread_id or _uuid_from_name(r.name)
            started = r.started_ms
            elapsed = None
            if v.status == st.FINISHED:
                elapsed = (r.finished_ms - started) if r.finished_ms and started else None
            elif started:
                elapsed = now_ms - started
            view = {
                "thread_id": thread,
                "short": (thread or "")[:8],
                "packet": field(r.packet, 80) or "(unknown)",
                "cwd_display": path_display(r.cwd) if r.cwd else None,
                "originator": field(r.originator, 32),
                "cli_version": field(r.cli_version, 32),
                "source_kind": r.source_kind or "other",
                "parent_thread_id": r.parent_thread_id,
                "model": field(r.model, 32),
                "effort": field(r.effort, 32),
                "sandbox": field(r.sandbox, 32),
                "status": v.status,
                "status_label": v.label,
                "outcome": v.outcome,
                "started_ms": started,
                "last_record_ms": r.last_record_ms,
                "last_growth_ms": r.last_growth_ms,
                "finished_ms": r.finished_ms,
                "elapsed_ms": elapsed,
                "turns": {
                    "started": r.turns_started if r.turns_exact else max(r.turns_started, r.turns_completed + (1 if r.turn_open else 0)),
                    "completed": r.turns_completed,
                    "exact": r.turns_exact,
                },
                "last_command": r.last_command(),
                "last_message": r.last_message,
                "tokens": r.tokens,
                "linked_claude": None,
                "private": False,
            }
            model.redact_codex_view(view)
            views.append(view)
            recs[thread] = r
        order = {"stalled": 0, "running": 1, "waiting": 1, "orphaned": 2, "finished": 3}
        views.sort(key=lambda x: (order.get(x["status"], 5), -(x["started_ms"] or 0)))
        self.omitted = max(0, len(views) - CODEX_RUNS_MAX)
        views = views[:CODEX_RUNS_MAX]
        # The detail API reads only this immutable copy, captured with the view privacy decision.
        index: dict[str, dict] = {}
        for view in views:
            r = recs[view["thread_id"]]
            index[view["thread_id"]] = {"view": view, "events": model.event_snapshot(r, r.events, bool(view.get("private")))}
        return views, self.usage_view(), index

    def usage_view(self) -> dict:
        if not self.rate:
            return {"windows": [], "snapshot_ms": None, "plan": None}
        return {"windows": self.rate["windows"], "snapshot_ms": self.rate_ts, "plan": self.rate["plan"]}


def _past_window(r: CodexRec, v: st.Verdict, now_ms: int) -> bool:
    age = (now_ms - (r.finished_ms or r.last_record_ms or r.file_start_ms or 0)) / 1000
    if v.status == st.FINISHED:
        return age > FINISHED_KEEP_S
    return v.status in (st.ORPHANED, st.STALLED) and age > STALE_KEEP_S


def _pick_rate(rl: dict) -> dict:
    windows = []
    for key in ("primary", "secondary"):
        w = rl.get(key)
        if not isinstance(w, dict):
            continue
        pct = w.get("used_percent")
        mins = w.get("window_minutes")
        if not isinstance(pct, (int, float)):
            continue
        if not isinstance(mins, int):
            mins = None
        tag = {10080: "WK", 300: "5H"}.get(mins, field(f"{mins}m", 32))
        resets = w.get("resets_at")
        windows.append(
            {
                "tag": tag,
                "used_percent": float(pct),
                "window_minutes": mins,
                "resets_at_ms": int(resets * 1000) if isinstance(resets, (int, float)) else None,
                "level": "crit" if pct >= 85 else "warn" if pct >= 50 else "ok",
            }
        )
    return {"windows": windows, "plan": field(rl.get("plan_type"), 32)}


def _output_text(o: object) -> str:
    """Extract only the tool-output prefix needed for markers; keep it local to the caller."""
    if isinstance(o, str):
        return o[:CODEX_OUTPUT_SCAN]
    if isinstance(o, list):
        return "\n".join(x["text"][:CODEX_OUTPUT_SCAN] for x in o if isinstance(x, dict) and isinstance(x.get("text"), str))
    return ""


def _num(v: object) -> int | float | None:
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _loads(line: bytes) -> dict | None:
    try:
        rec = json.loads(line.decode("utf-8", "replace"))
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def _uuid_from_name(name: str) -> str | None:
    m = ROLLOUT_RE.match(name)
    return m.group(7) if m else None
