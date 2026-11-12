"""Exercise the demo through the server scanner, with synthetic sources only."""
import io
import json
import os
from pathlib import Path
import sys
import unittest
from collections import Counter
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent)]

from fixture_tree import scratch_dir
from config import Paths, Settings
from masking import PRIVATE
from server import Log, Scanner
from tools.demo_data import generate, main


class DemoData(unittest.TestCase):
    def test_scene_and_filesystem_boundary(self):
        root = scratch_dir("demo data")
        touched = []

        def guarded(fn):
            def call(path, *args, **kwargs):
                resolved = Path(path).resolve()
                self.assertTrue(resolved.is_relative_to(root), str(path))
                touched.append(resolved)
                return fn(path, *args, **kwargs)
            return call

        # Guard every file open and filesystem mutation used by the generator.
        with patch("io.open", guarded(io.open)), patch("os.mkdir", guarded(os.mkdir)), \
                patch("os.utime", guarded(os.utime)), patch("builtins.open", guarded(open)), \
                patch("os.scandir", guarded(os.scandir)):
            with patch.object(sys, "argv", ["demo_data.py", str(root)]), patch("sys.stdout", new_callable=io.StringIO) as output:
                main()
        command = output.getvalue().strip()
        for flag, directory in (("--claude-home", "claude"), ("--codex-home", "codex"),
                                ("--temp-claude", "temp"), ("--state-dir", "state")):
            self.assertIn(flag, command)
            self.assertIn(str(root / directory), command)
        self.assertTrue(command.endswith("--port 8815"))
        self.assertGreater(len(touched), 30)
        before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
        paths = Paths(root / "claude", root / "codex", root / "temp", root / "state")
        scanner = Scanner(paths, Settings(), Log(paths.state_dir))
        for _ in range(3):
            scanner.tick_once()
        state = json.loads(scanner.snapshot.body)
        self.assertEqual(scanner.stats.parse_errors, 0)
        self.assertEqual(Counter(s["main"]["status"] for s in state["sessions"]),
                         {"running": 3, "waiting": 1, "stalled": 1, "closed": 1})
        agents = [a for s in state["sessions"] for a in s["agents"]]
        self.assertEqual(Counter(a["status"] for a in agents), {"running": 2, "waiting": 1, "finished": 1, "stalled": 1})
        checkout = next(s for s in state["sessions"] if s["title"] == "Ship checkout A/B test")
        self.assertEqual(len(checkout["agents"]), 3)
        self.assertEqual(state["counts"]["agents_stalled"], 1)
        workflows = [w for s in state["sessions"] for w in s["workflows"]]
        self.assertEqual(len(workflows), 1)
        self.assertEqual(workflows[0]["status"], "running")
        self.assertEqual(len(workflows[0]["agents"]), 3)
        self.assertEqual([p["title"] for p in workflows[0]["phases"]], ["Review", "Verify"])
        self.assertEqual(Counter(b["status"] for b in state["bg_tasks"]), {"running": 1, "waiting": 1, "finished": 1})
        self.assertEqual(Counter(r["status"] for r in state["codex_runs"]), {"running": 2, "finished": 1})
        self.assertEqual({r["packet"] for r in state["codex_runs"]}, {"billing_api_v2", "e2e_flake_triage", "docs_refresh"})
        self.assertEqual(state["codex_usage"]["windows"][0]["used_percent"], 47)
        self.assertNotIn(PRIVATE, scanner.snapshot.body.decode("utf-8"))

        def check_privacy(value):
            if isinstance(value, dict):
                self.assertFalse(value.get("private", False))
                for item in value.values():
                    check_privacy(item)
            elif isinstance(value, list):
                for item in value:
                    check_privacy(item)
        check_privacy(state)
        for relative, content in before.items():
            self.assertEqual((root / relative).read_bytes(), content)

    def test_existing_data_is_preserved(self):
        root = scratch_dir("demo_existing")
        sentinel = root / "keep.txt"
        sentinel.write_text("Keep this file", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "new or empty"):
            generate(root)
        self.assertEqual(list(root.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "Keep this file")

    def test_missing_parent_is_not_created(self):
        root = scratch_dir("demo_parent")
        with self.assertRaises(FileNotFoundError):
            generate(root / "missing" / "demo")
        self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()