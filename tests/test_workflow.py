import json
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import fixture_tree as ft  # noqa: E402
from fixture_tree import AID, AID2, RUN, SID, Tree, collector, run_ticks  # noqa: E402
from masking import PRIVATE  # noqa: E402


def now_ms():
    return int(time.time() * 1000)


def journal(*agents):
    out = [{"type": "launched"}]
    for aid, label, phase in agents:
        out.append({"type": "started", "key": "v2:x", "agentId": aid, "label": label, "phase": phase})
    return out


def terminal(status="completed", **kw):
    d = {
        "runId": RUN, "taskId": "wabc12345", "workflowName": "Terminal name", "status": status,
        "startTime": now_ms() - 60_000, "timestamp": ft.iso(now_ms() - 1000), "durationMs": 59_000,
        "agentCount": 2, "totalTokens": 300, "totalToolCalls": 7,
        "phases": [{"title": "Scout", "detail": "hidden"}],
        "workflowProgress": [
            {"type": "workflow_phase", "index": 1, "title": "Scout"},
            {"type": "workflow_agent", "index": 1, "label": "scout:a", "phaseIndex": 1, "phaseTitle": "Scout", "agentId": AID, "state": "done",
             "tokens": 100, "toolCalls": 3, "durationMs": 1000, "startedAt": now_ms() - 60_000, "lastToolName": "Bash",
             "promptPreview": "Hidden prompt", "resultPreview": "Hidden result", "lastToolSummary": "Hidden summary"},
            {"type": "workflow_agent", "index": 2, "label": "scout:b", "phaseIndex": 1, "phaseTitle": "Scout", "agentId": AID2, "state": "progress",
             "tokens": 200, "toolCalls": 4, "durationMs": 2000, "startedAt": now_ms() - 50_000},
        ],
        "script": "Hidden script", "result": {"x": "Hidden result"}, "summary": "Hidden summary", "logs": ["Hidden logs"],
    }
    d.update(kw)
    return d


class WorkflowTree(unittest.TestCase):
    def setUp(self):
        self.t = Tree("wf")
        self.now = now_ms()
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_text(self.now - 1000, "m1", "Progress", stop="tool_use")])

    def run_view(self):
        v = run_ticks(collector(self.t), now_ms())
        s = next(x for x in v["sessions"] if x["id"] == SID)
        return s, v

    def test_running_journal(self):
        self.t.add_main(SID, [ft.r_workflow_launch(self.now - 900, RUN)])
        self.t.add_run(SID, RUN, journal((AID, "scout:a", "Scout"), (AID2, "build:b", "Build")), {
            AID: [ft.r_assistant_tool(self.now - 1000, "m1", "t1", "Bash", {"description": "Check"})],
            AID2: [ft.r_assistant_text(self.now - 1000, "m1", "Done", stop="end_turn")],
        })
        s, _ = self.run_view()
        w = s["workflows"][0]
        self.assertEqual(w["status"], "running")
        self.assertEqual(w["agents_started"], 2)
        self.assertIsNone(w["agents_total"])
        self.assertFalse(w["total_is_exact"])
        self.assertEqual({p["title"] for p in w["phases"]}, {"Scout", "Build"})
        a = next(x for x in w["agents"] if x["agent_id"] == AID)
        self.assertEqual((a["description"], a["step"]["tool"], a["step"]["arg"]), ("scout:a", "Bash", "Check"))

    def test_journal_result_and_failed(self):
        j = journal((AID, "a", "P"), (AID2, "b", "P")) + [
            {"type": "result", "key": "x", "agentId": AID, "result": {"x": 1}},
            {"type": "failed", "key": "y", "agentId": AID2},
        ]
        self.t.add_run(SID, RUN, j, {
            AID: [ft.r_assistant_text(self.now - 500, "m1", "x")],
            AID2: [ft.r_assistant_text(self.now - 500, "m1", "x")],
        })
        s, _ = self.run_view()
        by = {a["agent_id"]: a for a in s["workflows"][0]["agents"]}
        self.assertEqual((by[AID]["outcome"], by[AID]["finish_source"]), ("completed", "journal"))
        self.assertEqual(by[AID2]["outcome"], "failed")

    def test_phase_order_follows_start_not_status(self):
        self.t.add_main(SID, [ft.r_workflow_launch(self.now - 900, RUN)])
        self.t.add_run(SID, RUN, journal((AID, "a", "First"), (AID2, "b", "Second")) + [{"type": "result", "agentId": AID, "result": {}}], {
            AID: [ft.r_assistant_text(self.now - 500, "m1", "x")],
            AID2: [ft.r_assistant_tool(self.now - 500, "m1", "t1", "Bash")],
        })
        s, _ = self.run_view()
        self.assertEqual([p["title"] for p in s["workflows"][0]["phases"]], ["First", "Second"])

    def test_terminal_keys(self):
        self.t.add_run(SID, RUN, journal((AID, "a", "Scout")))
        self.t.add_terminal(SID, RUN, terminal())
        s, _ = self.run_view()
        w = s["workflows"][0]
        self.assertEqual((w["tokens"]["value"], w["tokens"]["exact"]), (300, True))
        self.assertEqual((w["tool_calls"]["value"], w["tool_calls"]["exact"]), (7, True))
        self.assertEqual((w["agents_total"], w["total_is_exact"]), (2, True))
        self.assertEqual(w["name"], "Terminal name")

    def test_terminal_text_not_exposed(self):
        self.t.add_run(SID, RUN, journal((AID, "a", "Scout")))
        self.t.add_terminal(SID, RUN, terminal())
        s, v = self.run_view()
        body = json.dumps({"s": v["sessions"], "b": v["bg_tasks"]}, ensure_ascii=False)
        self.assertNotIn("Hidden", body)

    def test_killed_no_exception(self):
        self.t.add_run(SID, RUN, journal((AID, "a", "Scout")))
        self.t.add_terminal(SID, RUN, terminal(status="killed"))
        c = collector(self.t)
        v = run_ticks(c, now_ms())
        self.assertEqual(c.stats.parse_errors, 0)
        w = next(x for x in v["sessions"] if x["id"] == SID)["workflows"][0]
        self.assertEqual((w["status"], w["outcome"]), ("finished", "killed"))
        states = {a["agent_id"]: a for a in w["agents"]}
        self.assertEqual(states[AID]["outcome"], "completed")
        self.assertEqual(states[AID2]["outcome"], "killed")

    def test_unknown_status_no_exception(self):
        self.t.add_run(SID, RUN, journal((AID, "a", "Scout")))
        self.t.add_terminal(SID, RUN, terminal(status="exploded"))
        c = collector(self.t)
        v = run_ticks(c, now_ms())
        self.assertEqual(c.stats.parse_errors, 0)
        w = next(x for x in v["sessions"] if x["id"] == SID)["workflows"][0]
        self.assertEqual((w["status"], w["outcome"]), ("finished", "other"))

    def test_name_priority_launch_record(self):
        self.t.add_main(SID, [
            ft.r_assistant_tool(self.now - 900, "m2", "t9", "Workflow", {}),
            ft.r_tool_result(self.now - 800, "t9", "x", tur={"status": "async_launched", "taskId": "wabc12345", "taskType": "local_workflow", "runId": RUN, "workflowName": "Run name"}),
        ])
        self.t.add_run(SID, RUN, journal((AID, "a", "P")), {AID: [ft.r_assistant_text(self.now - 500, "m1", "x")]})
        s, _ = self.run_view()
        self.assertEqual(s["workflows"][0]["name"], "Run name")

    def test_name_priority_script_file(self):
        self.t.add_run(SID, RUN, journal((AID, "a", "P")), {AID: [ft.r_assistant_text(self.now - 500, "m1", "x")]})
        p = self.t.session_dir(SID) / "workflows" / "scripts" / f"ScriptName-{RUN}.js"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("// x", encoding="utf-8")
        s, _ = self.run_view()
        self.assertEqual(s["workflows"][0]["name"], "ScriptName")

    def test_name_unknown_is_private(self):
        self.t.add_run(SID, RUN, journal((AID, "a", "P")), {AID: [ft.r_assistant_text(self.now - 500, "m1", "x")]})
        s, _ = self.run_view()
        self.assertEqual(s["workflows"][0]["name"], PRIVATE)
        self.assertTrue(s["workflows"][0]["private"])

    def test_long_agent_keeps_run_alive_past_journal_age(self):
        d = self.t.add_run(SID, RUN, journal((AID, "a", "P")), {
            AID: [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Bash", {"description": "Takes a long time"})],
        })
        ft.set_mtime(d / "journal.jsonl", self.now - 20 * 60_000)
        s, _ = self.run_view()
        self.assertEqual(s["workflows"][0]["status"], "running")

    def test_notification_finishes_before_terminal(self):
        self.t.add_main(SID, [
            ft.r_assistant_tool(self.now - 900, "m2", "t9", "Workflow", {}),
            ft.r_tool_result(self.now - 800, "t9", "x", tur={"status": "async_launched", "taskId": "wabc12345", "taskType": "local_workflow", "runId": RUN, "workflowName": "Name"}),
            ft.r_notify_user(self.now - 100, ft.notification("wabc12345", "completed", 'Dynamic workflow "x" completed')),
        ])
        self.t.add_run(SID, RUN, journal((AID, "a", "P")), {AID: [ft.r_assistant_text(self.now - 500, "m1", "x")]})
        s, _ = self.run_view()
        self.assertEqual(s["workflows"][0]["status"], "finished")

    def test_denied_phase_propagates(self):
        self.t.add_run(SID, RUN, journal((AID, "client-x notes", "interview")), {AID: [
            ft.r_assistant_text(self.now - 500, "m1", "This text is ordinary"),
            ft.r_assistant_tool(self.now - 400, "m1", "t1", "Bash", {"description": "Ordinary"}),
        ]})
        s, _ = self.run_view()
        w = s["workflows"][0]
        a = w["agents"][0]
        self.assertEqual((a["description"], a["phase"], a["last_text"], a["step"]["arg"]), (PRIVATE,) * 4)
        self.assertEqual(w["phases"][0]["title"], PRIVATE)




# Privacy fixtures explicitly opt into neutral terms; production defaults stay empty.
def setUpModule():
    import masking
    global _previous_title_terms
    _previous_title_terms = masking.TITLE_DENYLIST
    masking.configure_title_denylist(("ProjectX", "client-x", "salary", "personnel", "interview", "legal", "🔒"))


def tearDownModule():
    import masking
    masking.configure_title_denylist(_previous_title_terms)

if __name__ == "__main__":
    unittest.main()
