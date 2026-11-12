"""Static repository policy tests. Build forbidden strings at runtime to avoid matching this file itself."""
import ast
import os
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PKG = HERE.parent
sys.path[:0] = [str(HERE), str(PKG)]


def j(*p):
    return "".join(p)


FILES = [
    p for p in PKG.rglob("*")
    if p.suffix in (".py", ".cmd", ".vbs") and "_scratch" not in p.parts and p.name != "test_policy.py"
] + [PKG / "static" / "index.html"]
SERVER_CODE = [p for p in PKG.glob("*.py")]

FORBIDDEN = [
    j("os.re", "move"), j("os.un", "link"), j(".un", "link("), j("rm", "tree"), j("rm", "dir"), j("os.ki", "ll"),
    j("task", "kill"), j("Terminate", "Process"), j("Temporary", "Directory"), j("get", "tempdir"), j("Remove", "-Item"),
]
POLICY_1 = [j("example", "_private_service"), j("EXAMPLE", "_PRIVATE_API_KEY"), j("private", "_integration")]
ENV_1 = [
    re.compile(j("timedelta\\(hours=-", "[78]")), re.compile(j('"UTC-', '7"')), re.compile(j("Etc/GM", "T\\+")),
    re.compile(j('"-0', '[78]:00"')), re.compile(j("(tz|offset)[a-z_]*\\s*=\\s*-", "[78]\\b")),
]


def code_strings_and_calls(path: Path) -> tuple[list[str], str]:
    """String literals excluding comments and docstrings."""
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src)
    doc_nodes = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant):
                doc_nodes.add(id(node.body[0].value))
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in doc_nodes]
    return strings, src


class Calls(unittest.TestCase):
    def test_forbidden_calls(self):
        for p in FILES:
            text = p.read_text(encoding="utf-8")
            for f in FORBIDDEN:
                self.assertNotIn(f, text, f"{p.name}: {f}")

    def test_no_tempfile_module(self):
        for p in SERVER_CODE:
            self.assertNotRegex(p.read_text(encoding="utf-8"), j(r"\bimport temp", "file\\b"), p.name)

    def test_subprocess_only_in_tests(self):
        for p in SERVER_CODE:
            self.assertNotIn(j("sub", "process"), p.read_text(encoding="utf-8"), p.name)

    def test_source_reads_go_through_open_shared(self):
        for name in ("tailreader.py", "claude_parse.py", "collect_claude.py", "collect_bg.py", "collect_codex.py", "model.py", "status.py", "masking.py", "config.py"):
            text = (PKG / name).read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"(?<![_\w])open\(", text), f"{name}: bare open()")
            self.assertNotIn(".read_bytes(", text, name)
            self.assertNotIn(".read_text(", text, name)

    def test_winproc_open_is_only_non_windows_fallback(self):
        text = (PKG / "winproc.py").read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r"(?<![_\w])open\(", text)), 1)

    def test_no_output_file_open(self):
        text = (PKG / "collect_bg.py").read_text(encoding="utf-8")
        self.assertNotIn("open_shared", text.replace("RangeScanner", ""))
        self.assertNotIn("read_tail", text)
        self.assertNotIn("read_head", text)

    def test_no_key_file_open(self):
        for p in SERVER_CODE:
            for s in code_strings_and_calls(p)[0]:
                self.assertFalse(s.endswith(".key"), f"{p.name}: {s}")

    def test_registry_filter_regex(self):
        text = (PKG / "collect_claude.py").read_text(encoding="utf-8")
        self.assertIn(r'REG_NAME_RE = re.compile(r"^\d+\.json$")', text)

    def test_ctypes_flags(self):
        text = (PKG / "winproc.py").read_text(encoding="utf-8")
        self.assertIn("use_last_error=True", text)
        self.assertIn("restype = wintypes.HANDLE", text)


class Literals(unittest.TestCase):
    def test_policy_1_in_code_literals(self):
        for p in FILES:
            if p.suffix != ".py":
                continue
            strings, _ = code_strings_and_calls(p)
            for s in strings:
                low = s.lower()
                for bad in POLICY_1:
                    self.assertNotIn(bad.lower(), low, f"{p.name}")

    def test_env_1(self):
        for p in FILES:
            text = p.read_text(encoding="utf-8")
            for rx in ENV_1:
                self.assertIsNone(rx.search(text), f"{p.name}: {rx.pattern}")

    def test_default_port_literal(self):
        text = (PKG / "server.py").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^DEFAULT_PORT = 8810$")


class Html(unittest.TestCase):
    def setUp(self):
        self.text = (PKG / "static" / "index.html").read_text(encoding="utf-8")

    def test_no_animation_or_heavy_css(self):
        for bad in ("@keyframes", "animation:", "backdrop-filter", "will-change", "filter:", "box-shadow"):
            self.assertNotIn(bad, self.text)

    def test_no_set_interval(self):
        self.assertNotIn("setInterval(", self.text)

    def test_no_external_urls(self):
        self.assertNotIn(j("http", "://"), self.text)
        self.assertNotIn(j("https", "://"), self.text)

    def test_no_inner_html(self):
        self.assertNotIn(j("inner", "HTML"), self.text)

    def test_no_inline_style_attribute(self):
        self.assertIsNone(re.search(r"<[a-z]+[^>]*\sstyle=", self.text))

    def test_no_inline_handlers(self):
        self.assertIsNone(re.search(r"<[a-z]+[^>]*\son[a-z]+=", self.text))

    def test_favicon_blocked(self):
        self.assertIn('<link rel="icon" href="data:,">', self.text)

    def test_nonce_placeholders(self):
        self.assertEqual(self.text.count('nonce="__NONCE__"'), 2)


class Layout(unittest.TestCase):
    def test_expected_files(self):
        for n in ("server.py", "config.py", "winproc.py", "tailreader.py", "masking.py", "claude_parse.py", "collect_claude.py", "collect_bg.py", "collect_codex.py", "status.py", "model.py", "static/index.html", "start_agent_watch.cmd", "stop_agent_watch.cmd", "AgentWatch_8810.vbs"):
            self.assertTrue((PKG / n).exists(), n)

    def test_sidebar_width_at_1366(self):
        text = (PKG / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn("@media (max-width: 1599px) { #layout { grid-template-columns: 260px", text)

    def test_cmd_uses_portable_python(self):
        text = (PKG / "start_agent_watch.cmd").read_text(encoding="utf-8")
        self.assertIn("where py", text)
        self.assertIn("py -3", text)
        self.assertIn("python", text)
        self.assertIn("%~dp0server.py", text)

    def test_vbs_pythonw(self):
        text = (PKG / "AgentWatch_8810.vbs").read_text(encoding="utf-8")
        self.assertIn("pythonw.exe", text)
        self.assertIn("--port 8810", text)


if __name__ == "__main__":
    unittest.main()
