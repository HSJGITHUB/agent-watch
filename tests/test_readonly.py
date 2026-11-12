"""After repeated ticks over synthetic source trees, sizes, mtimes, hashes, and file inventories must remain unchanged."""
import hashlib
import os
import sys
import time
import unittest
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import fixture_tree as ft  # noqa: E402
import server as srv  # noqa: E402
from collect_codex import CodexCollector  # noqa: E402
from config import Settings, TICK_READ_CAP  # noqa: E402
from fixture_tree import AID, RUN, SID, Tree, collector  # noqa: E402
from tailreader import Budget  # noqa: E402


def snapshot(root: Path) -> dict:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            st = p.stat()
            out[str(p)] = (st.st_size, st.st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest())
    return out


def populate(t: Tree) -> None:
    now = int(time.time() * 1000)
    t.add_registry(SID)
    t.add_main(SID, [
        {"type": "ai-title", "aiTitle": "Read-only check"},
        ft.r_assistant_tool(now - 1000, "m1", "t1", "Bash", {"description": "x", "run_in_background": True}),
        ft.r_tool_result(now - 900, "t1", "Command running in background with ID: bx1234567. x", tur={"backgroundTaskId": "bx1234567"}),
    ])
    t.add_agent(SID, AID, [ft.r_assistant_tool(now - 500, "m1", "t1", "Grep", {"pattern": "x"})])
    t.add_run(SID, RUN, [{"type": "launched"}, {"type": "started", "agentId": AID, "label": "l", "phase": "p"}], {AID: [ft.r_assistant_text(now, "m1", "x")]})
    t.add_terminal(SID, "wf_finished-abc", {"status": "killed", "workflowName": "n", "workflowProgress": []})
    t.add_output(SID, "bx1234567", b"output body")
    t.add_rollout([
        {"timestamp": ft.iso(now - 1000), "type": "session_meta", "payload": {"id": "x", "cwd": "c:\\x\\p", "source": "exec"}},
        {"timestamp": ft.iso(now - 900), "type": "event_msg", "payload": {"type": "task_started"}},
    ])


class ReadOnly(unittest.TestCase):
    def test_collectors_change_nothing(self):
        t = Tree("ro")
        populate(t)
        for src in (t.claude, t.codex, t.temp):
            self.assertTrue(any(src.rglob("*")) or src == t.temp)
        before = {r: snapshot(r) for r in (t.claude, t.codex, t.temp)}
        c = collector(t)
        x = CodexCollector(t.paths())
        for i in range(5):
            now = int(time.time() * 1000)
            c.discover(now, Budget(TICK_READ_CAP))
            x.discover(now, Budget(TICK_READ_CAP))
            c.tick(now, Budget(TICK_READ_CAP))
            x.tick(now, Budget(TICK_READ_CAP))
            c.backfill.run()
            c.build(now)
            x.build(now)
        for r, snap in before.items():
            self.assertEqual(snapshot(r), snap, str(r))

    def test_server_writes_only_state_dir(self):
        t = Tree("ro2")
        populate(t)
        before = {r: snapshot(r) for r in (t.claude, t.codex, t.temp)}
        app = srv.App(t.paths(), Settings(tick_s=0.5), port=0)
        app.bind()
        app.start()
        time.sleep(1.5)
        app.stop()
        for r, snap in before.items():
            self.assertEqual(snapshot(r), snap, str(r))
        self.assertTrue((t.state / "run.json").exists())


if __name__ == "__main__":
    unittest.main()
