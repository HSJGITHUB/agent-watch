"""Assemble sessions, agents, and background views from synthetic trees."""
import json
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import fixture_tree as ft  # noqa: E402
from config import TICK_READ_CAP  # noqa: E402
from fixture_tree import AID, AID2, SID, SID2, Tree, collector, run_ticks  # noqa: E402
from masking import PRIVATE  # noqa: E402
from tailreader import Budget  # noqa: E402


def now_ms():
    return int(time.time() * 1000)


class Base(unittest.TestCase):
    def setUp(self):
        self.t = Tree("col")
        self.now = now_ms()

    def view(self, sid=SID, c=None):
        c = c or collector(self.t)
        v = run_ticks(c, now_ms())
        self.v = v
        self.c = c
        return next(s for s in v["sessions"] if s["id"] == sid)

    def agent(self, s, aid=AID):
        return next(a for a in s["agents"] if a["agent_id"] == aid)


class Sessions(Base):
    def test_live_registry_session(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [{"type": "ai-title", "aiTitle": "Synthetic session"}, ft.r_assistant_tool(self.now - 100, "m1", "t1", "Bash", {"description": "Build"})])
        s = self.view()
        self.assertEqual((s["live"], s["state"], s["title"], s["title_source"]), (True, "busy", "Synthetic session", "ai"))
        self.assertEqual(s["main"]["step"]["tool"], "Bash")
        self.assertEqual(s["main"]["status"], "running")

    def test_key_file_not_touched_and_fields_dropped(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "x")])
        s = self.view()
        blob = json.dumps(s, ensure_ascii=False)
        self.assertNotIn("secret-pipe", blob)
        self.assertNotIn("synthetic-not-a-secret", blob)

    def test_dead_pid_closed(self):
        self.t.add_registry(SID, pid=4_000_000, proc_start="123")
        self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "x")])
        s = self.view()
        self.assertEqual((s["live"], s["state"], s["main"]["status"]), (False, "closed", "closed"))

    def test_reused_pid_closed(self):
        self.t.add_registry(SID, proc_start="123")
        self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "x")])
        self.assertIs(self.view()["live"], False)

    def test_headless_recent_null(self):
        self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "x")])
        s = self.view()
        self.assertIsNone(s["live"])
        self.assertEqual(s["live_source"], "mtime")

    def test_headless_within_orphan_window_is_null(self):
        p = self.t.add_main(SID, [ft.r_assistant_text(self.now - 1800_000, "m1", "x")])
        ft.set_mtime(p, self.now - 1800_000)  # Older than ten minutes but within one hour.
        self.assertIsNone(self.view()["live"])

    def test_headless_quiet_past_orphan_closed(self):
        p = self.t.add_main(SID, [ft.r_assistant_text(self.now - 7200_000, "m1", "x")])
        ft.set_mtime(p, self.now - 7200_000)
        self.assertIs(self.view()["live"], False)

    def test_outside_window_not_listed(self):
        p = self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "x")])
        ft.set_mtime(p, self.now - 30 * 3600_000)
        v = run_ticks(collector(self.t), now_ms())
        self.assertEqual(v["sessions"], [])

    def test_live_old_idle_session_included(self):
        self.t.add_registry(SID, status="idle")
        p = self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "x", stop="end_turn")])
        ft.set_mtime(p, self.now - 30 * 3600_000)
        s = self.view()
        self.assertEqual((s["live"], s["main"]["status"]), (True, "idle"))

    def test_registry_disappears_means_closed(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "x")])
        c = collector(self.t)
        self.assertIs(self.view(c=c)["live"], True)
        reg = next(p for p in (self.t.claude / "sessions").glob("*.json"))
        reg.write_text("{bad json", encoding="utf-8")
        self.assertIs(self.view(c=c)["live"], True)  # Parse failures retain the previous value.

    def test_live_transition_needs_two_confirmations(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "x")])
        c = collector(self.t)
        self.view(c=c)
        s = c.sessions[SID]
        c._set_live(s, False, "registry")
        self.assertIs(s.live, True)
        c._set_live(s, False, "registry")
        self.assertIs(s.live, False)

    def test_duplicate_session_in_two_slugs_newest_wins(self):
        other = self.t.claude / "projects" / "--192-168-0-31-x"
        other.mkdir()
        ft.write_jsonl(other / f"{SID}.jsonl", [ft.r_assistant_text(self.now - 5000, "m1", "Old copy")])
        ft.set_mtime(other / f"{SID}.jsonl", self.now - 3600_000)
        self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "Latest")])
        v = run_ticks(collector(self.t), now_ms())
        rows = [s for s in v["sessions"] if s["id"] == SID]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["main"]["last_text"], "Latest")

    def test_title_from_head_when_missing_in_tail(self):
        recs = [{"type": "ai-title", "aiTitle": "Title only in the head"}]
        pad = [ft.r_assistant_text(self.now - 1000, f"m{i}", "z" * 3000) for i in range(200)]
        self.t.add_registry(SID)
        self.t.add_main(SID, recs + pad)
        self.assertEqual(self.view()["title"], "Title only in the head")

    def test_registry_name_fallback(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "x")])
        s = self.view()
        self.assertEqual((s["title"], s["title_source"]), ("fixture-ab", "registry"))

    def test_dead_registry_with_old_transcript_not_listed(self):
        self.t.add_registry(SID, pid=4_000_002, proc_start="1")
        p = self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "x")])
        ft.set_mtime(p, self.now - 30 * 3600_000)
        v = run_ticks(collector(self.t), now_ms())
        self.assertEqual(v["sessions"], [])

    def test_registry_without_transcript_is_negative_cached(self):
        self.t.add_registry(SID)
        c = collector(self.t)
        now = now_ms()
        c.tick(now, Budget(TICK_READ_CAP))
        self.assertIn(SID, c.path_miss)
        first = c.path_miss[SID]
        c.tick(now, Budget(TICK_READ_CAP))
        self.assertEqual(c.path_miss[SID], first)
        self.assertNotIn(SID, c.sessions)

    def test_project_grouping(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "x")])
        self.view()
        self.assertEqual(self.v["projects"][0]["name"], "proj")
        self.assertEqual(self.v["projects"][0]["session_ids"], [SID])

    def test_tail_window_expands_without_assistant(self):
        huge = ft.r_tool_result(self.now, "t0", "y" * 300_000)
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_text(self.now - 1000, "m1", "Earlier message"), huge])
        s = self.view(c=collector(self.t))
        self.assertEqual(s["main"]["last_text"], "Earlier message")


class Agents(Base):
    def setUp(self):
        super().setUp()
        self.t.add_registry(SID)

    def main(self, *extra):
        self.t.add_main(SID, [ft.r_prompt(self.now - 5000), *extra])

    def test_running_with_step(self):
        self.main()
        self.t.add_agent(SID, AID, [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Grep", {"pattern": "foo"})])
        a = self.agent(self.view())
        self.assertEqual((a["status"], a["step"]["tool"], a["step"]["arg"]), ("running", "Grep", "foo"))
        self.assertEqual(a["description"], "Synthetic task")

    def test_last_tool_kept_after_result(self):
        self.main()
        self.t.add_agent(SID, AID, [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Read", {"file_path": "a/b.txt"}), ft.r_tool_result(self.now - 50, "t1")])
        a = self.agent(self.view())
        self.assertEqual(a["step"]["kind"], "model_wait")
        self.assertEqual((a["last_tool"]["name"], a["last_tool"]["arg"], a["last_tool"]["ok"]), ("Read", "b.txt", True))

    def test_meta_finished(self):
        self.main()
        p = self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now - 100, "m1", "Done", stop="end_turn")], {"agentType": "x", "description": "d", "finished": True, "requestShape": "background"})
        self.assertTrue(p.exists())
        a = self.agent(self.view())
        self.assertEqual((a["status"], a["outcome"], a["finish_source"]), ("finished", "completed", "meta"))

    def test_notification_exact_tokens_and_tools(self):
        self.main(ft.r_notify_user(self.now, ft.notification(AID, "completed", 'Agent "x" finished', usage="<subagent_tokens>4321</subagent_tokens><tool_uses>9</tool_uses><duration_ms>777</duration_ms>")))
        self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now - 100, "m1", "Done", stop="end_turn")])
        a = self.agent(self.view())
        self.assertEqual((a["tokens"]["value"], a["tokens"]["exact"], a["tokens"]["source"]), (4321, True, "notification"))
        self.assertEqual((a["tool_calls"]["value"], a["tool_calls"]["exact"]), (9, True))
        self.assertEqual(a["elapsed_ms"], 777)

    def test_sync_result_tokens(self):
        self.main(
            ft.r_assistant_tool(self.now - 1000, "mm", "tp", "Agent", {"description": "x"}),
            ft.r_tool_result(self.now - 100, "tp", "done", tur={"status": "completed", "agentId": AID, "totalTokens": 55, "totalToolUseCount": 2, "totalDurationMs": 10}),
        )
        self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now - 200, "m1", "Done", stop="end_turn")], {"toolUseId": "tp", "requestShape": "foreground", "description": "d"})
        a = self.agent(self.view())
        self.assertEqual((a["finish_source"], a["tokens"]["value"]), ("sync_result", 55))

    def test_tail_inference(self):
        self.main()
        self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now - 100, "m1", "Done", stop="end_turn")])
        a = self.agent(self.view())
        self.assertEqual((a["status"], a["confidence"], a["finish_source"]), ("finished", "inferred", "tail"))

    def test_refusal_finishes(self):
        self.main()
        self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now - 100, "m1", "Refused", stop="refusal")])
        self.assertEqual(self.agent(self.view())["status"], "finished")

    def test_resumed_agent_is_running_again(self):
        self.main(ft.r_notify_user(self.now - 80_000, ft.notification(AID, "completed", 'Agent "x" finished')))
        self.t.add_agent(SID, AID, [
            ft.r_assistant_text(self.now - 90_000, "m1", "First turn done", stop="end_turn"),
            ft.r_prompt(self.now - 1000, "coordinator", "Continue"),
            ft.r_api_request(self.now - 900),
        ], {"agentType": "x", "description": "d", "finished": True, "requestShape": "background"})
        ft.set_mtime(self.t.session_dir(SID) / "subagents" / f"agent-{AID}.meta.json", self.now - 90_000)
        a = self.agent(self.view())
        self.assertEqual((a["status"], a["outcome"]), ("running", None))

    def test_end_turn_with_own_bg_waits(self):
        self.main()
        self.t.add_agent(SID, AID, [
            ft.r_assistant_tool(self.now - 5000, "m1", "t1", "Bash", {"description": "Long-running"}),
            ft.r_tool_result(self.now - 4000, "t1", "Command running in background with ID: bx1234567. x"),
            ft.r_assistant_text(self.now - 3000, "m2", "Waiting", stop="end_turn"),
        ])
        a = self.agent(self.view())
        self.assertEqual((a["status"], a["status_label"], a["own_bg_pending"]), ("waiting", "Waiting for background jobs", 1))

    def test_end_turn_with_async_child_waits(self):
        self.main()
        self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now - 100, "m2", "Waiting for child", stop="end_turn")])
        self.t.add_agent(SID, AID2, [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Bash")], {"parentAgentId": AID, "requestShape": "background", "description": "Child", "spawnDepth": 2})
        s = self.view()
        self.assertEqual(self.agent(s, AID)["status_label"], "Waiting for background jobs")
        self.assertEqual(self.agent(s, AID2)["parent_agent_id"], AID)

    def test_end_turn_with_workflow_waits(self):
        self.main()
        self.t.add_agent(SID, AID, [
            ft.r_assistant_tool(self.now - 3000, "m1", "t1", "Workflow", {}),
            ft.r_tool_result(self.now - 2000, "t1", "x", tur={"status": "async_launched", "taskId": "wabc12345", "taskType": "local_workflow", "runId": ft.RUN, "workflowName": "n"}),
            ft.r_assistant_text(self.now - 1000, "m2", "Waiting", stop="end_turn"),
        ])
        self.assertEqual(self.agent(self.view())["status_label"], "Waiting for background jobs")

    def test_foreground_child_parent_resolved_without_signal(self):
        self.main(
            ft.r_assistant_tool(self.now - 3000, "mm", "tp", "Agent", {"description": "x"}),
            ft.r_tool_result(self.now - 2000, "tp", "error", is_error=True),
        )
        self.t.add_agent(SID, AID, [ft.r_assistant_tool(self.now - 2500, "m1", "t1", "Bash")], {"toolUseId": "tp", "requestShape": "foreground", "description": "d"})
        a = self.agent(self.view())
        self.assertEqual((a["status"], a["outcome"], a["finish_source"]), ("finished", "other", "parent"))

    def test_sync_parent_not_stalled_while_child_active(self):
        p = self.t.add_main(SID, [ft.r_assistant_tool(self.now - 900_000, "mm", "tp", "Agent", {"description": "x"})])
        ft.set_mtime(p, self.now - 900_000)
        self.t.add_agent(SID, AID, [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Bash")], {"toolUseId": "tp", "requestShape": "foreground", "description": "d"})
        s = self.view()
        self.assertEqual(s["main"]["status"], "running")
        self.assertGreater(s["main"]["effective_activity_ms"], self.now - 60_000)

    def test_main_waiting_on_workflow_is_not_stalled(self):
        p = self.t.add_main(SID, [
            ft.r_assistant_tool(self.now - 3000_000, "mm", "tw", "Workflow", {}),
            ft.r_tool_result(self.now - 2900_000, "tw", "x", tur={"status": "async_launched", "taskId": "wabc12345", "taskType": "local_workflow", "runId": ft.RUN, "workflowName": "n"}),
            ft.r_assistant_text(self.now - 2800_000, "m2", "Waiting", stop="end_turn"),
        ])
        ft.set_mtime(p, self.now - 2800_000)
        self.t.add_run(SID, ft.RUN, [{"type": "started", "agentId": AID, "label": "a", "phase": "P"}], {AID: [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Bash")]})
        s = self.view()
        self.assertEqual((s["main"]["status"], s["main"]["status_label"], s["main"]["own_bg_pending"]), ("waiting", "Waiting for background jobs", 1))

    def test_main_waiting_on_async_agent(self):
        p = self.t.add_main(SID, [ft.r_assistant_text(self.now - 900_000, "m2", "Waiting", stop="end_turn")])
        ft.set_mtime(p, self.now - 900_000)
        self.t.add_agent(SID, AID, [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Bash")])
        self.assertEqual(self.view()["main"]["status"], "waiting")

    def test_main_turn_ended_nothing_pending_idle(self):
        p = self.t.add_main(SID, [ft.r_assistant_text(self.now - 900_000, "m2", "Done", stop="end_turn")])
        ft.set_mtime(p, self.now - 900_000)
        self.assertEqual(self.view()["main"]["status"], "idle")

    def test_stalled_agent(self):
        self.main()
        p = self.t.add_agent(SID, AID, [ft.r_assistant_tool(self.now - 800_000, "m1", "t1", "Bash")])
        ft.set_mtime(p, self.now - 800_000)
        s = self.view()
        self.assertEqual(self.agent(s)["status"], "stalled")
        self.assertEqual(s["counts"]["stalled"], 1)

    def test_old_finished_agent_not_read(self):
        self.main()
        p = self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now - 7200_000, "m1", "Done", stop="end_turn")], {"finished": True, "description": "d", "requestShape": "background"})
        ft.set_mtime(p, self.now - 7200_000)
        c = collector(self.t)
        s = self.view(c=c)
        self.assertEqual(s["agents"], [])
        self.assertNotIn(AID, c.sessions[SID].agents)  # Retire the tracker, retaining only its tombstone.
        self.assertIn(AID, c.sessions[SID].gone)

    def test_outside_window_agent_ignored(self):
        self.main()
        p = self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now, "m1", "x")])
        ft.set_mtime(p, self.now - 30 * 3600_000)
        c = collector(self.t)
        self.view(c=c)
        self.assertNotIn(AID, c.sessions[SID].agents)

    def test_new_agent_seen_same_tick_after_tool_use(self):
        self.main()
        c = collector(self.t)
        self.view(c=c)
        self.t.add_main(SID, [ft.r_assistant_tool(now_ms(), "m9", "t9", "Agent", {"description": "New", "run_in_background": True})])
        self.t.add_agent(SID, AID, [ft.r_assistant_tool(now_ms(), "m1", "t1", "Bash")])
        now = now_ms()
        c.tick(now, Budget(TICK_READ_CAP))
        c.tick(now, Budget(TICK_READ_CAP))
        self.assertIn(AID, c.sessions[SID].agents)

    def test_tool_call_count_backfill_exact(self):
        tools = [ft.r_assistant_tool(self.now - 1000, f"m{i}", f"toolu_{i}", "Read", {"file_path": "a" * 3000}) for i in range(150)]
        results = [ft.r_tool_result(self.now - 1000, f"toolu_{i}") for i in range(150)]
        recs = [x for pair in zip(tools, results) for x in pair]
        self.main()
        p = self.t.session_dir(SID) / "subagents" / f"agent-{AID}.jsonl"
        ft.write_jsonl(p, [])
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            for r in recs:
                f.write(json.dumps(r, separators=(",", ":")) + "\n")
        ft.write_json(p.with_name(f"agent-{AID}.meta.json"), {"description": "d", "requestShape": "background"})
        self.assertGreater(p.stat().st_size, 256 * 1024)
        a = self.agent(self.view())
        self.assertEqual(a["tool_calls"], {"value": 150, "exact": True})


class Bg(Base):
    def setUp(self):
        super().setUp()
        self.t.add_registry(SID)

    def bg(self, tid):
        return next(b for b in self.v["bg_tasks"] if b["task_id"] == tid)

    def start(self, tid="bx1234567", ts=None):
        ts = ts or self.now - 5000
        return [
            ft.r_assistant_tool(ts, "m1", "t1", "Bash", {"description": "Server", "run_in_background": True}),
            ft.r_tool_result(ts + 10, "t1", f"Command running in background with ID: {tid}. x", tur={"backgroundTaskId": tid}),
        ]

    def test_start_and_quiet(self):
        self.t.add_main(SID, self.start())
        self.view()
        b = self.bg("bx1234567")
        self.assertEqual((b["status"], b["status_label"], b["description"], b["owner_label"]), ("waiting", "Running quietly", "Server", "Main"))

    def test_output_stat_active(self):
        self.t.add_main(SID, self.start())
        self.t.add_output(SID, "bx1234567", b"secret output body")
        self.view()
        b = self.bg("bx1234567")
        self.assertEqual((b["status"], b["output_bytes"]), ("running", 18))
        self.assertNotIn("secret output body", json.dumps(self.v["bg_tasks"]))

    def test_notification_finish_with_exit(self):
        self.t.add_main(SID, self.start() + [ft.r_notify_user(self.now, ft.notification("bx1234567", "completed", 'Background command "x" completed (exit code 2)'))])
        self.view()
        b = self.bg("bx1234567")
        self.assertEqual((b["status"], b["outcome"], b["exit_code"]), ("finished", "completed", 2))

    def test_taskstop(self):
        self.t.add_main(SID, self.start() + [
            ft.r_assistant_tool(self.now - 100, "m2", "t2", "TaskStop", {"task_id": "bx1234567"}),
            ft.r_tool_result(self.now - 50, "t2", "x", tur={"task_id": "bx1234567", "task_type": "local_bash", "message": "m"}),
        ])
        self.view()
        self.assertEqual(self.bg("bx1234567")["outcome"], "stopped")

    def test_owner_agent_finished(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        self.t.add_agent(SID, AID, self.start() + [ft.r_assistant_text(self.now - 100, "m9", "Done", stop="end_turn")], {"description": "Owner", "finished": True, "requestShape": "background"})
        s = self.view()
        self.assertEqual(self.agent(s)["status"], "finished")
        b = self.bg("bx1234567")
        self.assertEqual((b["status"], b["status_label"], b["owner_label"]), ("finished", "Ended with agent (inferred)", "Owner"))

    def test_session_closed_orphans(self):
        self.t.add_main(SID2, self.start())
        self.t.add_registry(SID2, pid=4_000_001, proc_start="1")
        self.view(SID2)
        self.assertEqual(self.bg("bx1234567")["status"], "orphaned")

    def test_inventory_without_start_after_backfill_is_no_record(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        self.t.add_output(SID, "bnostart1")
        c = collector(self.t)
        self.view(c=c)
        self.view(c=c)  # Rows without launch records appear after two discoveries.
        b = self.bg("bnostart1")
        self.assertEqual((b["status"], b["status_label"]), ("orphaned", "No record"))
        self.assertEqual(self.v["sessions"][0]["counts"]["bg_running"], 0)

    def test_inventory_unknown_before_backfill(self):
        pad = [ft.r_assistant_text(self.now - 1000, f"m{i}", "z" * 3000) for i in range(200)]
        self.t.add_main(SID, pad)
        self.t.add_output(SID, "bnostart1")
        c = collector(self.t)
        now = now_ms()
        c.discover(now, Budget(TICK_READ_CAP))
        c.discover(now, Budget(TICK_READ_CAP))
        c.tick(now, Budget(TICK_READ_CAP))
        self.assertTrue(c.backfill.pending())
        v = c.build(now)
        b = next(x for x in v["bg_tasks"] if x["task_id"] == "bnostart1")
        self.assertEqual((b["status"], b["status_label"]), ("unknown", "Checking"))
        self.assertEqual(v["sessions"][0]["counts"]["bg_running"], 0)

    def test_dormant_agent_start_found_before_no_record_verdict(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        p = self.t.add_agent(SID, AID, self.start(ts=self.now - 7200_000) + [ft.r_assistant_text(self.now - 7100_000, "m9", "Done", stop="end_turn")], {"finished": True, "description": "Owner", "requestShape": "background"})
        ft.set_mtime(p, self.now - 7000_000)
        self.t.add_output(SID, "bx1234567")
        self.view()
        b = self.bg("bx1234567")
        self.assertTrue(b["start_seen"])
        self.assertEqual(b["status"], "finished")

    def test_workflow_agent_start_found_after_terminal(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        self.t.add_run(SID, ft.RUN, [{"type": "started", "agentId": AID, "label": "a", "phase": "P"}], {AID: self.start()})
        self.t.add_terminal(SID, ft.RUN, {"status": "completed", "workflowName": "n", "workflowProgress": [{"type": "workflow_agent", "agentId": AID, "label": "a", "state": "done"}]})
        self.t.add_output(SID, "bx1234567")
        self.view()
        b = self.bg("bx1234567")
        self.assertTrue(b["start_seen"])
        self.assertEqual(b["status_label"], "Ended with agent (inferred)")

    def test_old_output_without_start_not_in_inventory(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        p = self.t.add_output(SID, "bnostart2")
        ft.set_mtime(p, self.now - 25 * 3600_000)
        self.view()
        self.assertFalse([b for b in self.v["bg_tasks"] if b["task_id"] == "bnostart2"])

    def test_start_outside_tail_recovered_by_backfill(self):
        head = self.start()
        pad = [ft.r_assistant_text(self.now - 1000, f"m{i}", "z" * 3000) for i in range(200)]
        self.t.add_main(SID, head + pad)
        self.t.add_output(SID, "bx1234567")
        self.view()
        b = self.bg("bx1234567")
        self.assertTrue(b["start_seen"])
        self.assertIn("Server", b["description"])


class Privacy(Base):
    def test_title_hides_whole_session(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [{"type": "ai-title", "aiTitle": "ProjectX strategy"}, ft.r_assistant_text(self.now - 1, "m1", "Body text"), ft.r_assistant_tool(self.now, "m2", "t1", "Bash", {"description": "Ordinary description"})])
        self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now, "m1", "Agent body")], {"description": "Ordinary", "requestShape": "background"})
        s = self.view()
        self.assertTrue(s["title_hidden"])
        self.assertEqual((s["title"], s["main"]["last_text"], s["main"]["step"]["arg"]), (PRIVATE,) * 3)
        a = self.agent(s)
        self.assertEqual((a["description"], a["last_text"]), (PRIVATE, PRIVATE))
        self.assertEqual(s["main"]["step"]["tool"], "Bash")

    def test_agent_description_hides_agent(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now)])
        self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now, "m1", "Body"), ft.r_assistant_tool(self.now, "m1", "t1", "Bash", {"description": "Ordinary"})], {"description": "interview notes", "requestShape": "background"})
        a = self.agent(self.view())
        self.assertEqual((a["description"], a["last_text"], a["step"]["arg"]), (PRIVATE,) * 3)
        self.assertTrue(a["private"])

    def test_cwd_denied_hides_session(self):
        self.t.add_registry(SID, cwd="c:\\legal\\folder")
        self.t.add_main(SID, [ft.r_assistant_text(self.now, "m1", "Body")])
        self.t.claude.joinpath("projects", "c-----", "x").parent.mkdir(exist_ok=True)
        s = self.view()
        self.assertEqual((s["cwd_display"], s["main"]["last_text"]), (PRIVATE, PRIVATE))
        self.assertEqual(self.v["projects"][0]["name"], PRIVATE)

    def test_bg_description_hidden(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [
            {"type": "custom-title", "customTitle": "salary case"},
            ft.r_assistant_tool(self.now, "m1", "t1", "Bash", {"description": "Ordinary", "run_in_background": True}),
            ft.r_tool_result(self.now, "t1", "Command running in background with ID: bx1234567. x"),
        ])
        self.view()
        self.assertEqual(self.v["bg_tasks"][0]["description"], PRIVATE)




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
