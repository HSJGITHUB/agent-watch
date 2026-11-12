"""Synthetic public-release configuration and path-masking regressions."""
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]
import fixture_tree as ft
import masking
import server


class TitleConfiguration(unittest.TestCase):
    def setUp(self):
        self.previous = masking.TITLE_DENYLIST
        self.addCleanup(masking.configure_title_denylist, self.previous)

    def test_fresh_import_defaults_empty(self):
        env = dict(os.environ, AGENT_WATCH_TITLE_DENYLIST="")
        result = subprocess.run([sys.executable, "-X", "utf8", "-B", "-c",
                                 "import masking; assert masking.TITLE_DENYLIST == (); assert not masking.is_denied('client-x')"],
                                cwd=HERE.parent, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_environment_at_import(self):
        env = dict(os.environ, AGENT_WATCH_TITLE_DENYLIST=" client-x, , salary ")
        result = subprocess.run([sys.executable, "-X", "utf8", "-B", "-c",
                                 "import masking; assert masking.TITLE_DENYLIST == ('client-x', 'salary'); assert masking.is_denied('CLIENT-X notes')"],
                                cwd=HERE.parent, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_file_and_environment_combine(self):
        p = ft.scratch_dir("title_config") / "titles.txt"
        p.write_text("# Comment\n legal \n\nsalary # inline\n", encoding="utf-8-sig")
        with patch.dict(os.environ, {"AGENT_WATCH_TITLE_DENYLIST": " client-x, , "}):
            server.load_title_denylist(str(p))
        self.assertEqual(masking.TITLE_DENYLIST, ("client-x", "legal", "salary"))
        for title in ("CLIENT-X notes", "paralegal", "Salary plan"):
            self.assertEqual(masking.field(title, 80), masking.PRIVATE)
        self.assertFalse(masking.is_denied("Ordinary title"))

    def test_reconfiguration_clears_previous_terms(self):
        masking.configure_title_denylist(("client-x",))
        with patch.dict(os.environ, {"AGENT_WATCH_TITLE_DENYLIST": " , "}):
            server.load_title_denylist(None)
        self.assertEqual(masking.TITLE_DENYLIST, ())
        self.assertFalse(masking.is_denied("client-x"))

    def test_unreadable_file_fails_before_startup(self):
        p = ft.scratch_dir("missing_title_config") / "missing.txt"
        with patch.object(server, "App") as app, patch.object(sys, "stderr"):
            with self.assertRaises(SystemExit) as error:
                server.main(["--title-denylist-file", str(p)])
        self.assertEqual(error.exception.code, 2)
        app.assert_not_called()

    def test_invalid_utf8_fails_before_startup(self):
        p = ft.scratch_dir("invalid_title_config") / "titles.txt"
        p.write_bytes(b"\xff\xfe\xff")
        with patch.object(server, "App") as app, patch.object(sys, "stderr"):
            with self.assertRaises(SystemExit) as error:
                server.main(["--title-denylist-file", str(p)])
        self.assertEqual(error.exception.code, 2)
        app.assert_not_called()

    def test_cli_accepts_file_option(self):
        self.assertEqual(server.build_parser().parse_args(["--title-denylist-file", "titles.txt"]).title_denylist_file, "titles.txt")


class PortablePaths(unittest.TestCase):
    def test_unc_backslash_hosts_and_shares(self):
        for source in (r"\\files.example\shared\work\report.txt", r"\\storage\Team Share\work\report.txt"):
            self.assertEqual(masking.safe_text(source, 200), "UNC:/work/report.txt")
            self.assertEqual(masking.path_display(source), "UNC:/work/report.txt")

    def test_unc_forward_hosts_and_shares(self):
        for source in ("//files.example/shared/work/report.txt", "//storage/Team Share/work/report.txt"):
            self.assertEqual(masking.safe_text(source, 200), "UNC:/work/report.txt")
            self.assertEqual(masking.path_display(source), "UNC:/work/report.txt")

    def test_unc_root(self):
        for source in (r"\\files.example\shared", "//files.example/shared", "//files.example/shared/"):
            self.assertEqual(masking.path_display(source), "UNC:/")

    def test_urls_are_not_unc(self):
        for source in ("https://example.com/share/file.txt", "file://example.com/share/file.txt"):
            self.assertEqual(masking.safe_text(source, 200), source)

    def test_neutral_home_paths(self):
        self.assertEqual(masking.path_display(r"C:\Users\sample\.claude\x.txt"), "~/.claude/x.txt")
        self.assertEqual(masking.path_display(r"C:\work\task_x\file.txt"), "C:/work/task_x/file.txt")

    def test_task_heading_and_tooltip(self):
        html = (HERE.parent / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn('["Task", "Status", "Current activity", "Elapsed"]', html)
        self.assertIn('cell.title = "working folder name"', html)
        self.assertIn('<html lang="en">', html)


if __name__ == "__main__":
    unittest.main()
