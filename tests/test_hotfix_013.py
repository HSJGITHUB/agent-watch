"""Synthetic regressions for 0.1.3 fixes, covering parser, collector, snapshot, and HTTP responses. Exceed real caps except when reducing constants avoids excessive fixture files."""
import json
import os
import select
import socket
import sys
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import claude_parse as cp  # noqa: E402
import collect_bg  # noqa: E402
import fixture_tree as ft  # noqa: E402
import masking  # noqa: E402
import server as srv  # noqa: E402
from claude_parse import SessionIndex, TranscriptState  # noqa: E402
from collect_claude import SessionRec  # noqa: E402
from config import FINISHED_KEEP_S, MAX_HANDLERS, NOTIFS_MAX, ORPHAN_QUIET_S, STOPS_MAX, TICK_READ_CAP, WORKFLOWS_MAX  # noqa: E402
from fixture_tree import AID, RUN, SID, Tree, collector  # noqa: E402
from masking import PRIVATE  # noqa: E402
from tailreader import Budget  # noqa: E402
from test_review_012 import Base, j, now_ms  # noqa: E402

V = "ZZSYNTHVALUEZZ"
HOUR = 3600_000
TID = "bmon12345"
PERSIST = f"Monitor started (task {TID}, persistent, runs until TaskStop or session end). You will be notified on each event."


def ended_notice(tid=TID, status="completed"):
    """Final Monitor notification containing both status and event."""
    return (
        f"<task-notification>\n<task-id>{tid}</task-id>\n<tool-use-id>toolu_x</tool-use-id>\n<output-file>C:/x/{tid}.output</output-file>\n"
        f'<status>{status}</status>\n<summary>Monitor "x" stream ended</summary>\n<event>line one\nsmoke rc=0</event>\n</task-notification>'
    )


def event_notice(tid=TID, text="line"):
    return f'<task-notification>\n<task-id>{tid}</task-id>\n<summary>Monitor event: "x"</summary>\n<event>{text}</event>\n</task-notification>'


def monitor_start(ts, text=PERSIST, tool_id="tm"):
    return [
        ft.r_assistant_tool(ts, "mm", tool_id, "Monitor", {"description": "Watch logs", "command": "tail -f x"}),
        ft.r_tool_result(ts + 10, tool_id, text),
    ]


def bash_start(ts, tid, tool_id="tb", desc="Server"):
    return [
        ft.r_assistant_tool(ts, f"m{tool_id}", tool_id, "Bash", {"description": desc, "run_in_background": True}),
        ft.r_tool_result(ts + 1, tool_id, f"Command running in background with ID: {tid}", tur={"backgroundTaskId": tid}),
    ]


def rows(state, tid):
    return [b for b in state["bg_tasks"] if b["task_id"] == tid]


class Hot(Base):
    def registry(self, age_ms=HOUR):
        self.t.add_registry(SID, startedAt=self.now - age_ms)

    def publish(self, *args):
        server = self.live(*args)
        server.publish()
        return server


# ---- H1 ----
class H1Monitor(Hot):
    def test_status_wins_over_event_text(self):
        n = cp.parse_notifications(ended_notice())[0]
        self.assertEqual((n["status"], n["is_event"]), ("completed", False))
        for status in ("failed", "killed"):
            self.assertFalse(cp.parse_notifications(ended_notice(status=status))[0]["is_event"])

    def test_ordinary_event_stays_event(self):
        n = cp.parse_notifications(event_notice())[0]
        self.assertEqual((n["status"], n["is_event"]), (None, True))
        n = cp.parse_notifications(ft.notification("b1", status=None, summary='Monitor event: "x"'))[0]
        self.assertTrue(n["is_event"])

    def test_tag_text_inside_event_is_not_structure(self):
        n = cp.parse_notifications(event_notice(text="log says <status>completed</status>"))[0]
        self.assertEqual((n["status"], n["is_event"]), (None, True))

    def test_stream_end_closes_row_and_main_and_shows_once(self):
        self.registry()
        text = ended_notice()
        self.t.add_main(SID, [
            *monitor_start(self.now - 5000),
            ft.r_notify_queue(self.now - 3000, text, "enqueue"),
            ft.r_notify_attachment(self.now - 2000, text),
            ft.r_notify_user(self.now - 1000, text),
            ft.r_assistant_text(self.now - 500, "m2", "Done", stop="end_turn"),
        ])
        self.t.add_output(SID, TID)
        server = self.publish()
        state = server.state()
        b = rows(state, TID)[0]
        s = self.session(state)
        self.assertEqual((b["status"], b["outcome"], b["kind"]), ("finished", "completed", "monitor"))
        self.assertEqual(s["counts"]["bg_running"], 0)
        self.assertEqual(s["main"]["own_bg_pending"], 0)
        events = json.loads(server.agent()[1])["events"]
        self.assertEqual(len([e for e in events if e["kind"] == "notification"]), 1)

    def test_queued_event_after_stream_end_does_not_reopen(self):
        # Queued events can appear after the completion notification.
        self.registry()
        self.t.add_main(SID, [
            *monitor_start(self.now - 5000),
            ft.r_notify_queue(self.now - 3000, ended_notice()),
            ft.r_notify_queue(self.now - 2000, event_notice(), "remove"),
            ft.r_notify_user(self.now - 1000, event_notice()),
        ])
        self.t.add_output(SID, TID)
        b = rows(self.publish().state(), TID)[0]
        self.assertEqual((b["status"], b["outcome"]), ("finished", "completed"))

    def test_stream_end_without_start_record_is_still_a_monitor(self):
        idx = SessionIndex()
        idx.add_notification(cp.parse_notifications(ended_notice())[0], self.now)
        self.assertEqual(idx.bg[TID]["kind"], "monitor")

    def test_ordinary_event_keeps_monitor_open(self):
        self.registry()
        self.t.add_main(SID, [*monitor_start(self.now - 5000), ft.r_notify_queue(self.now - 1000, event_notice())])
        self.t.add_output(SID, TID)
        state = self.publish().state()
        self.assertIn(rows(state, TID)[0]["status"], ("running", "waiting"))

    def test_persistent_monitor_closes_with_session(self):
        self.t.add_main(SID, monitor_start(self.now - 5000))
        self.t.add_output(SID, TID)
        self.t.add_registry(SID, pid=999999, proc_start="1")  # Dead process.
        c = collector(self.t)
        for _ in range(3):
            self.view(c=c)
        b = rows(self.v, TID)[0]
        self.assertEqual((b["status"], b["status_label"]), ("finished", "Ended with session (inferred)"))
        self.assertEqual(self.session(self.v)["counts"]["bg_running"], 0)

    def test_persistent_monitor_closes_with_owner_agent(self):
        self.registry()
        self.t.add_main(SID, [ft.r_prompt(self.now - 9000)])
        self.t.add_agent(SID, AID, monitor_start(self.now - 5000), {"agentType": "x", "description": "Watch", "requestShape": "background", "finished": True})
        self.t.add_output(SID, TID)
        self.view()
        b = rows(self.v, TID)[0]
        self.assertEqual((b["status"], b["status_label"]), ("finished", "Ended with agent (inferred)"))

    def test_quiet_persistent_monitor_does_not_hold_owner_open(self):
        old = self.now - 2 * HOUR
        self.registry(3 * HOUR)
        self.t.add_main(SID, [ft.r_prompt(self.now - 9000)])
        recs = [*monitor_start(old), ft.r_assistant_text(old + 100, "m2", "Waiting", stop="end_turn")]
        self.t.add_agent(SID, AID, recs, {"agentType": "x", "description": "Watch", "requestShape": "background"})
        p = self.t.add_output(SID, TID)
        ft.set_mtime(p, old)
        ft.set_mtime(self.t.session_dir(SID) / "subagents" / f"agent-{AID}.jsonl", old)
        s = self.view()
        # Completed two hours ago, outside the display window; it must not remain waiting.
        self.assertEqual((s["counts"]["waiting"], s["counts"]["bg_running"]), (0, 0))
        self.assertEqual(rows(self.v, TID), [])

    def test_dead_owner_mid_turn_closes_quiet_persistent_monitor(self):
        old = self.now - 2 * HOUR
        self.registry(3 * HOUR)
        self.t.add_main(SID, [ft.r_prompt(self.now - 9000)])
        recs = [*monitor_start(old), ft.r_assistant_tool(old + 100, "m2", "t2", "Bash", {"description": "x"})]
        self.t.add_agent(SID, AID, recs, {"agentType": "x", "description": "Watch", "requestShape": "background"})
        p = self.t.add_output(SID, TID)
        ft.set_mtime(p, old)
        ft.set_mtime(self.t.session_dir(SID) / "subagents" / f"agent-{AID}.jsonl", old)
        s = self.view()
        self.assertEqual(s["agents"][0]["status"], "orphaned")
        self.assertEqual((s["counts"]["waiting"], s["counts"]["stalled"], s["counts"]["bg_running"]), (0, 0, 0))
        self.assertEqual(rows(self.v, TID), [])  # Ended with its owner and last output is outside the display window.

    def test_monitor_with_recent_event_still_holds_owner(self):
        old = self.now - 2 * HOUR
        self.registry(3 * HOUR)
        self.t.add_main(SID, [ft.r_prompt(self.now - 9000)])
        recs = [*monitor_start(old), ft.r_assistant_text(old + 100, "m2", "Waiting", stop="end_turn"), ft.r_notify_queue(self.now - 2000, event_notice())]
        self.t.add_agent(SID, AID, recs, {"agentType": "x", "description": "Watch", "requestShape": "background"})
        self.t.add_output(SID, TID)
        s = self.view()
        self.assertEqual(s["agents"][0]["status"], "waiting")
        self.assertIn(rows(self.v, TID)[0]["status"], ("running", "waiting"))

    def test_quiet_persistent_monitor_does_not_hold_main(self):
        old = self.now - 2 * HOUR
        self.registry(3 * HOUR)
        self.t.add_main(SID, [*monitor_start(old), ft.r_assistant_text(old + 100, "m2", "Done", stop="end_turn")])
        ft.set_mtime(self.t.add_output(SID, TID), old)
        s = self.view()
        self.assertEqual(s["main"]["own_bg_pending"], 0)
        self.assertEqual(s["main"]["status"], "idle")
        # The job continues while the session remains live.
        self.assertEqual(rows(self.v, TID)[0]["status"], "waiting")


# ---- H2 ----
class H2Eviction(Hot):
    def stale_bg(self, closing):
        """Quiet background job started after its session process; losing completion would immediately create a ghost row."""
        ts = self.now - 1800_000
        self.registry(5 * HOUR)
        self.t.add_main(SID, [
            ft.r_prompt(ts), *bash_start(ts, "bx1234567"), closing(ts + 2),
            ft.r_assistant_text(ts + 3, "m2", "Done", stop="end_turn"),
        ])
        ft.set_mtime(self.t.add_output(SID, "bx1234567"), ts)
        return self.live()

    def assert_stays_closed(self, server, flood, label, attr, cap):
        server.publish()
        before = rows(server.state(), "bx1234567")[0]
        self.assertEqual(before["status"], "finished")
        ft.write_jsonl(self.t.main_path(SID), [*flood, ft.r_assistant_text(now_ms(), "m3", "Done", stop="end_turn")])
        server.publish()
        rec = server.sc.claude.sessions[SID]
        self.assertFalse("bx1234567" in getattr(rec.idx, attr))  # Actually evicted from the index.
        self.assertEqual(len(getattr(rec.idx, attr)), cap)
        state = server.state()
        after = rows(state, "bx1234567")[0]
        s = self.session(state)
        self.assertEqual((after["status"], after["status_label"]), ("finished", label))
        self.assertEqual(after["finished_ms"], before["finished_ms"])
        self.assertEqual((s["counts"]["bg_running"], s["main"]["own_bg_pending"]), (0, 0))
        self.assertEqual(s["main"]["status"], "idle")

    def test_notification_eviction_does_not_resurrect(self):
        server = self.stale_bg(lambda ts: ft.r_notify_user(ts, ft.notification("bx1234567", "completed", "done (exit code 0)")))
        flood = [ft.r_notify_user(now_ms(), ft.notification(f"a{i:016x}", "completed", "x")) for i in range(NOTIFS_MAX + 50)]
        self.assert_stays_closed(server, flood, "Completed", "notifs", NOTIFS_MAX)

    def test_taskstop_eviction_does_not_resurrect(self):
        server = self.stale_bg(lambda ts: ft.r_tool_result(ts, "toolu_stop", "Successfully stopped task: bx1234567"))
        flood = [ft.r_tool_result(now_ms(), f"toolu_s{i}", f"Successfully stopped task: x{i}") for i in range(STOPS_MAX + 50)]
        self.assert_stays_closed(server, flood, "Stopped", "stops", STOPS_MAX)

    def test_terminal_signal_read_before_start_survives_eviction(self):
        # Tail completion arrives first; backfill then evicts notifications before reaching the launch record.
        old = self.now - 1800_000
        self.t.add_registry(SID, startedAt=self.now - 5 * HOUR)
        early = [ft.r_notify_user(old, ft.notification(f"a{i:016x}", "completed", "x")) for i in range(NOTIFS_MAX + 50)]
        pad = [ft.r_assistant_text(old + 2, f"p{i}", "z" * 3000) for i in range(100)]
        self.t.add_main(SID, [
            *early, *bash_start(old + 1, "bx1234567"), *pad,
            ft.r_notify_user(old + 3, ft.notification("bx1234567", "completed", "done")),
            ft.r_assistant_text(old + 4, "m2", "Done", stop="end_turn"),
        ])
        ft.set_mtime(self.t.add_output(SID, "bx1234567"), old)
        server = self.publish()
        rec = server.sc.claude.sessions[SID]
        self.assertFalse("bx1234567" in rec.idx.notifs)
        self.assertTrue(rec.idx.bg["bx1234567"]["start_seen"])
        b = rows(server.state(), "bx1234567")[0]
        self.assertEqual(b["status"], "finished")

    def test_placeholder_survives_task_scan_until_start_arrives(self):
        idx = SessionIndex()
        idx.add_notification(cp.parse_notifications(ft.notification("bx1234567", "completed"))[0], self.now)
        self.assertEqual(collect_bg.scan_tasks_dir(self.t.root, idx, self.now), 0)
        self.assertFalse(idx.bg["bx1234567"]["start_seen"])
        idx.bg_start("bx1234567", None, self.now - 100, False, "bash", None)
        self.assertEqual(idx.bg["bx1234567"]["final"]["status"], "completed")

    def test_later_status_less_notice_does_not_reopen(self):
        idx = SessionIndex()
        idx.bg_start("bx1234567", None, self.now - 100, False, "bash", None)
        idx.add_notification(cp.parse_notifications(ft.notification("bx1234567", "completed"))[0], self.now)
        idx.add_notification(cp.parse_notifications(ft.notification("bx1234567", status=None, summary="no state"))[0], self.now + 10)
        self.assertEqual(idx.bg["bx1234567"]["final"]["status"], "completed")
        self.assertEqual(collect_bg.bg_open_by_owner(idx, None, self.now), {})


# ---- H3 ----
class H3WorkflowNames(Hot):
    def launch(self, ts, run_id, name, task, tool):
        return [ft.r_assistant_tool(ts, f"m{tool}", tool, "Workflow", {}), ft.r_workflow_launch(ts + 1, run_id, name, task, tool)]

    def open_run(self, label="Label"):
        self.t.add_run(SID, RUN, [{"type": "started", "agentId": AID, "label": label, "phase": "P"}], {AID: [ft.r_assistant_text(self.now - 500, "m1", V)]})

    def test_open_launch_survives_cap_and_keeps_run_private(self):
        ts = self.now - 5000
        self.registry()
        recs = self.launch(ts, RUN, "legal review", "wprivate1", "t0")
        for i in range(WORKFLOWS_MAX + 40):  # Everything fits in the tail window and is read in file order.
            recs.append(ft.r_workflow_launch(ts, f"wf_done{i}", "Ordinary", f"wdone{i}", f"td{i}"))
            recs.append(ft.r_notify_user(ts + 2, ft.notification(f"wdone{i}", "completed", "x")))
        self.t.add_main(SID, recs)
        self.open_run()
        server = self.publish()
        idx = server.sc.claude.sessions[SID].idx
        self.assertIn(RUN, idx.workflows)
        self.assertEqual(idx.workflows[RUN]["name"], PRIVATE)
        self.assertLessEqual(len(idx.workflows), WORKFLOWS_MAX)
        body = server.get("/api/state")[1]
        self.assertNotIn(V.encode(), body)
        self.assertEqual(self.session(json.loads(body))["workflows"][0]["name"], PRIVATE)
        self.assertNotIn(V.encode(), server.agent(aid=AID)[1])

    def test_lost_notification_does_not_reopen_finished_run(self):
        ts = self.now - 5000
        self.registry()
        self.t.add_main(SID, [*self.launch(ts, RUN, "Ordinary", "wabc12345", "t0"), ft.r_notify_user(ts + 2, ft.notification("wabc12345", "completed", "x"))])
        self.open_run()
        server = self.publish()
        self.assertEqual(self.session(server.state())["workflows"][0]["status"], "finished")
        ft.write_jsonl(self.t.main_path(SID), [
            *[ft.r_notify_user(now_ms(), ft.notification(f"a{i:016x}", "completed", "x")) for i in range(NOTIFS_MAX + 20)],
            ft.r_assistant_text(now_ms(), "m2", "Done", stop="end_turn"),
        ])
        server.publish()
        rec = server.sc.claude.sessions[SID]
        self.assertFalse("wabc12345" in rec.idx.notifs)
        s = self.session(server.state())
        self.assertEqual(s["workflows"][0]["status"], "finished")
        self.assertEqual(s["main"]["own_bg_pending"], 0)

    def test_terminal_runs_leave_first(self):
        idx = SessionIndex()
        with mock.patch.object(cp, "WORKFLOWS_MAX", 4):
            for i in range(4):
                idx.workflow(f"wf_{i}", None, self.now)["terminal"] = i % 2 == 0
            idx.workflow("wf_4", None, self.now)
            idx.workflow("wf_5", None, self.now)
        self.assertEqual(list(idx.workflows), ["wf_1", "wf_3", "wf_4", "wf_5"])

    def test_open_runs_are_not_evicted_by_the_cap(self):
        idx = SessionIndex()
        with mock.patch.object(cp, "WORKFLOWS_MAX", 4):
            for i in range(20):
                idx.workflow(f"wf_{i}", None, self.now)["name"] = f"Name{i}"
        self.assertEqual(len(idx.workflows), 20)
        self.assertEqual(idx.workflows["wf_0"]["name"], "Name0")

    def test_terminal_flag_comes_from_notification_and_terminal_file(self):
        self.registry()
        self.t.add_main(SID, self.launch(self.now - 5000, RUN, "Ordinary", "wabc12345", "t0"))
        self.t.add_run(SID, RUN, [{"type": "started", "agentId": AID, "label": "Label", "phase": "P"}], {AID: [ft.r_assistant_text(self.now - 500, "m1", "x")]})
        c = collector(self.t)
        self.view(c=c)
        idx = c.sessions[SID].idx
        self.assertFalse(idx.workflows[RUN]["terminal"])
        self.t.add_terminal(SID, RUN, {"status": "completed", "workflowName": "Ordinary", "workflowProgress": []})
        self.view(c=c)
        self.assertTrue(idx.workflows[RUN]["terminal"])

    def test_unknown_name_is_private_until_known(self):
        self.registry()
        self.t.add_main(SID, [ft.r_prompt(self.now - 9000)])
        self.open_run()
        server = self.publish()
        body = server.get("/api/state")[1]
        w = self.session(json.loads(body))["workflows"][0]
        self.assertEqual((w["name"], w["private"], w["agents"][0]["description"]), (PRIVATE, True, PRIVATE))
        self.assertNotIn(V.encode(), body)
        self.assertNotIn(V.encode(), server.agent(aid=AID)[1])
        ft.write_jsonl(self.t.main_path(SID), self.launch(now_ms(), RUN, "Ordinary name", "wabc12345", "t0"))
        server.publish()
        body = server.get("/api/state")[1]
        w = self.session(json.loads(body))["workflows"][0]
        self.assertEqual((w["name"], w["private"], w["agents"][0]["description"]), ("Ordinary name", False, "Label"))
        self.assertIn(V.encode(), server.agent(aid=AID)[1])

    def test_script_file_written_late_is_found(self):
        self.registry()
        self.t.add_main(SID, [ft.r_prompt(self.now - 9000)])
        self.open_run()
        server = self.publish()
        self.assertEqual(self.session(server.state())["workflows"][0]["name"], PRIVATE)
        p = self.t.session_dir(SID) / "workflows" / "scripts" / f"LateName-{RUN}.js"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("// x", encoding="utf-8")
        server.publish()
        self.assertEqual(self.session(server.state())["workflows"][0]["name"], "LateName")

    def test_spilled_launch_stays_private(self):
        ts = self.now - 5000
        self.registry()
        recs = self.launch(ts, RUN, "Ordinary", "wfirst123", "t0")
        recs += [r for i in range(6) for r in self.launch(ts, f"wf_open{i}", "Other", f"wopen{i}", f"to{i}")]
        self.t.add_main(SID, recs)
        self.open_run()
        with mock.patch.object(cp, "WORKFLOWS_MAX", 3), mock.patch.object(cp, "WORKFLOWS_OPEN_MAX", 3):
            server = self.publish()
        self.assertNotIn(RUN, server.sc.claude.sessions[SID].idx.workflows)
        w = self.session(server.state())["workflows"][0]
        self.assertEqual((w["name"], w["private"]), (PRIVATE, True))


# ---- H4 ----
class H4Reappear(Hot):
    def stale_run(self):
        ts = self.now - 60_000
        self.registry()
        self.t.add_main(SID, [ft.r_prompt(ts), ft.r_workflow_launch(ts + 1, RUN, "Resume target", "wabc12345")])
        d = self.t.add_run(SID, RUN, [{"type": "started", "agentId": AID, "label": "Label", "phase": "P"}], {AID: [ft.r_assistant_text(ts, "m1", "In progress")]})
        return d

    def age_all(self, d, hours):
        old = self.now - hours * HOUR
        for p in d.iterdir():
            ft.set_mtime(p, old)

    def test_expired_run_reappears_on_new_activity_with_name(self):
        d = self.stale_run()
        c = collector(self.t)
        self.assertEqual(len(self.view(c=c)["workflows"]), 1)
        self.age_all(d, 25)
        self.view(c=c)
        s = self.view(c=c)
        self.assertEqual(s["workflows"], [])
        rec = c.sessions[SID]
        self.assertIn(RUN, rec.runs_skip)
        self.assertNotIn(RUN, rec.idx.workflows)
        ft.write_jsonl(d / "journal.jsonl", [{"type": "started", "agentId": "a1111111111111111", "label": "New agent", "phase": "P"}])
        ft.write_jsonl(d / "agent-a1111111111111111.jsonl", [ft.r_assistant_text(now_ms(), "m2", "Resumed work")])
        s = self.view(c=c)
        self.assertNotIn(RUN, rec.runs_skip)
        self.assertEqual(len(s["workflows"]), 1)
        self.assertEqual(s["workflows"][0]["name"], "Resume target")
        self.assertIn("a1111111111111111", [a["agent_id"] for a in s["workflows"][0]["agents"]])

    def test_append_to_existing_agent_file_is_activity(self):
        d = self.stale_run()
        c = collector(self.t)
        self.view(c=c)
        self.age_all(d, 25)
        self.view(c=c)
        self.view(c=c)
        ft.write_jsonl(d / f"agent-{AID}.jsonl", [ft.r_assistant_text(now_ms(), "m2", "Resumed work")])
        self.assertEqual(len(self.view(c=c)["workflows"]), 1)

    def test_no_new_activity_stays_skipped(self):
        d = self.stale_run()
        c = collector(self.t)
        self.view(c=c)
        self.age_all(d, 25)
        self.view(c=c)
        self.view(c=c)
        rec = c.sessions[SID]
        entry = rec.runs_skip[RUN]
        for _ in range(3):
            self.assertEqual(self.view(c=c)["workflows"], [])
        self.assertIs(rec.runs_skip[RUN], entry)

    def test_finished_run_reappears_when_terminal_is_rewritten(self):
        d = self.stale_run()
        term = {"status": "completed", "workflowName": "Resume target", "timestamp": ft.iso(self.now - 3 * HOUR), "workflowProgress": []}
        p = self.t.add_terminal(SID, RUN, term)
        self.age_all(d, 3)
        ft.set_mtime(p, self.now - 3 * HOUR)
        c = collector(self.t)
        s = self.view(c=c)
        self.assertEqual(s["workflows"], [])
        self.assertIn(RUN, c.sessions[SID].runs_skip)
        self.t.add_terminal(SID, RUN, dict(term, timestamp=ft.iso(now_ms())))
        s = self.view(c=c)
        self.assertEqual([w["status"] for w in s["workflows"]], ["finished"])

    def test_old_terminal_with_new_agent_activity_reappears(self):
        d = self.stale_run()
        p = self.t.add_terminal(SID, RUN, {"status": "completed", "workflowName": "Resume target", "timestamp": ft.iso(self.now - 3 * HOUR), "workflowProgress": []})
        self.age_all(d, 3)
        ft.set_mtime(p, self.now - 3 * HOUR)
        c = collector(self.t)
        self.assertEqual(self.view(c=c)["workflows"], [])
        ft.write_jsonl(d / f"agent-{AID}.jsonl", [ft.r_assistant_text(now_ms(), "m2", "More")])
        self.assertEqual(len(self.view(c=c)["workflows"]), 1)
        self.assertEqual(len(self.view(c=c)["workflows"]), 1)  # The next discovery must not retire it again.


# ---- H5 ----
class H5Distortion(Hot):
    def test_paths_are_not_decoded(self):
        rows_ = {
            r"C:\build\x64_session\app.exe": "C:/build/x64_session/app.exe",
            r"C:\build\x64_token\app.exe": "C:/build/x64_token/app.exe",
            r"C:\temp\x41password\a.txt": "C:/temp/x41password/a.txt",
            r"D:\src\u0041pp\session\x.py": "D:/src/u0041pp/session/x.py",
        }
        for raw, want in rows_.items():
            with self.subTest(raw):
                self.assertEqual(masking.safe_text(raw, 200), want)

    def test_name_regex_uses_word_boundaries(self):
        for s in ("d_session", "obsession", "tokenizer", "passwordless", "mypat", "sigma"):
            self.assertIsNone(masking._ENC_NAME_RE.search(s), s)
        for s in ("password", "db_password", "a-token", "session", "session_id", "?key="):
            self.assertIsNotNone(masking._ENC_NAME_RE.search(s), s)

    def test_percent_stays_as_written(self):
        for raw in ("https://example.com/a%20b?page=2&sort=asc", "docs/how%20to%20deploy.md", "token%20count.md", "session%20notes.txt", "C:/a%20password%20policy.md"):
            with self.subTest(raw):
                self.assertEqual(masking.safe_text(raw, 200), raw)

    def test_decoding_changes_display_only_when_a_value_is_hidden(self):
        self.assertEqual(masking.safe_text("%74oken%20count", 200), "%74oken%20count")
        self.assertEqual(masking.safe_text("https://x.io/?%74oken=abc", 200), "https://x.io/?token=[MASK]")

    def test_encoded_keys_are_still_found(self):
        for raw in ('{"pass\\u0077ord":"' + V + '"}', "https://example.test/?%74oken=" + V, "https://example.test/?%2574oken=" + V, "x?redirect=https%3A%2F%2Fa.b%2Fcb%3Fcode%3D" + V):
            with self.subTest(raw):
                self.assertNotIn(V, masking.safe_text(raw, 300))

    def test_fold_keeps_siblings_after_nullish_or_empty(self):
        cases = {
            "cookie: false\n  next_key: 1": "next_key: 1",
            "cookie = None\n    next_code()": "next_code()",
            "x-api-key:\n  required: true": "required: true",
            "x-api-key:\n    return value(1)": "return value(1)",
            "set-cookie:\n  - name: x": "- name: x",
            '"cookie": null,\n  "other": 2': '"other": 2',
        }
        for raw, keep in cases.items():
            with self.subTest(raw):
                self.assertIn(keep, masking.mask_patterns(raw))

    def test_fold_keeps_siblings_after_clean_value(self):
        cases = {
            'cookie: "a=1"\n    sibling: 1': "sibling: 1",
            "Authorization: Bearer abcdefgh12\n  Content-Type: json": "Content-Type: json",
            "X-Auth-Token: abc\n    def build(x):": "def build(x):",
            "token: abc\n  next: 2": "next: 2",
            "password: abc\n  print(1)": "print(1)",
        }
        for raw, keep in cases.items():
            with self.subTest(raw):
                out = masking.mask_patterns(raw)
                self.assertIn(keep, out)
                self.assertIn("[MASK]", out)

    def test_generic_keys_do_not_take_the_next_key_as_value(self):
        for raw in ("password:\n  username: x", "token:\n  - name: y", 'session:\n  "id": 1'):
            with self.subTest(raw):
                self.assertEqual(masking.mask_patterns(raw), raw)

    def test_real_continuations_stay_hidden(self):
        for raw in (
            j("Authorization: Bearer ", "abcdefgh12345678\n  ", V),
            "Cookie: a=1;\n  b=" + V,
            "x-api-key:\n    " + V,
            "token:\n  " + V,
            "cookie: |\n  " + V,
        ):
            with self.subTest(raw):
                self.assertNotIn(V, masking.mask_patterns(raw))


# ---- H6 ----
class H6StatRotation(Hot):
    def tree(self, n):
        recs = [ft.r_prompt(self.now - 9000)]
        for i in range(n):
            recs += bash_start(self.now - 5000, f"bt{i:06d}", f"tb{i}")
            self.t.add_output(SID, f"bt{i:06d}")
        self.registry()
        self.t.add_main(SID, recs)
        c = collector(self.t)
        self.view(c=c)
        idx = c.sessions[SID].idx
        for rec in idx.bg.values():
            rec["output_bytes"] = None  # Clear discovery stat values to exercise only the tick path.
            rec.pop("stat_seq", None)
        return c, idx

    def test_every_open_task_is_checked_within_bound(self):
        c, idx = self.tree(200)
        now = now_ms()
        seen = []
        for _ in range(4):  # ceil(200/64)
            c.tick(now, Budget(TICK_READ_CAP))
            seen.append(sum(1 for r in idx.bg.values() if r["output_bytes"] is not None))
        self.assertEqual(seen, [64, 128, 192, 200])

    def test_rotation_continues_after_a_full_pass(self):
        idx = SessionIndex()
        for i in range(100):
            idx.bg_start(f"bt{i:06d}", None, self.now, False, "bash", None)
        d = str(self.t.root)
        last = {}
        for tick in range(1, 7):
            collect_bg.stat_open_tasks(d, idx)
            for t, r in idx.bg.items():
                self.assertGreaterEqual(tick - r.get("stat_seq", 0), 0)
                if r.get("stat_seq") == tick:
                    last.setdefault(t, []).append(tick)
        # 100 jobs require two ticks per round; no job should wait more than three ticks across six ticks.
        self.assertEqual(len(last), 100)
        for ticks in last.values():
            self.assertTrue(all(b - a <= 3 for a, b in zip(ticks, ticks[1:])), ticks)

    def test_bound_holds_when_tasks_finish_between_ticks(self):
        idx = SessionIndex()
        for i in range(130):
            idx.bg_start(f"bt{i:06d}", None, self.now, False, "bash", None)
        d = str(self.t.root)
        collect_bg.stat_open_tasks(d, idx)
        for i in range(0, 64):
            idx.settle_bg(f"bt{i:06d}", stop_ms=self.now)
        collect_bg.stat_open_tasks(d, idx)  # 64 of the remaining 66.
        collect_bg.stat_open_tasks(d, idx)
        self.assertTrue(all(r.get("stat_seq") for r in idx.bg.values()))

    def test_closed_tasks_are_not_stat_checked(self):
        idx = SessionIndex()
        idx.bg_start("bt1", None, self.now, False, "bash", None)
        idx.settle_bg("bt1", stop_ms=self.now)
        collect_bg.stat_open_tasks(str(self.t.root), idx)
        self.assertNotIn("stat_seq", idx.bg["bt1"])


# ---- H7 ----
class H7Refuse(Hot):
    def full(self):
        server = self.live()
        held = [socket.create_connection(("127.0.0.1", server.port), timeout=5) for _ in range(MAX_HANDLERS)]
        self.addCleanup(lambda: [s.close() for s in held])
        for _ in range(200):
            if server.app.server.slots._value == 0:
                break
            time.sleep(0.01)
        self.assertEqual(server.app.server.slots._value, 0)
        return server

    def read_all(self, sock):
        sock.settimeout(5)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                return data
            data += chunk

    def test_real_request_gets_503_not_reset(self):
        server = self.full()
        for _ in range(30):
            s = socket.create_connection(("127.0.0.1", server.port), timeout=5)
            s.sendall(b"GET /api/state HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: " + b"x" * 2000 + b"\r\n\r\n")
            self.assertTrue(self.read_all(s).startswith(b"HTTP/1.1 503 "))
            s.close()

    def test_request_sent_just_after_connect_gets_503(self):
        server = self.full()
        for _ in range(10):
            s = socket.create_connection(("127.0.0.1", server.port), timeout=5)
            time.sleep(0.03)
            s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            self.assertTrue(self.read_all(s).startswith(b"HTTP/1.1 503 "))
            s.close()

    def test_silent_client_costs_at_most_the_budget(self):
        self.full()
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        server = self.servers[0].app.server
        t0 = time.perf_counter()
        server._refuse(a)
        elapsed = time.perf_counter() - t0
        self.assertLess(elapsed, srv.REFUSE_WAIT_S + 0.1)
        self.assertGreaterEqual(elapsed, srv.REFUSE_WAIT_S * 0.8)
        self.assertTrue(self.read_all(b).startswith(b"HTTP/1.1 503 "))

    def test_ready_client_does_not_wait(self):
        self.full()
        a, b = socket.socketpair()
        self.addCleanup(b.close)
        b.sendall(b"GET / HTTP/1.1\r\n\r\n")
        select.select([a], [], [], 1)
        t0 = time.perf_counter()
        self.servers[0].app.server._refuse(a)
        self.assertLess(time.perf_counter() - t0, 0.05)
        self.assertTrue(self.read_all(b).startswith(b"HTTP/1.1 503 "))


# ---- H8 ----
class H8DetailSnapshot(Hot):
    def finished_run(self, private_label=None):
        self.registry()
        self.t.add_main(SID, [ft.r_prompt(self.now - 9000), ft.r_workflow_launch(self.now - 8000, RUN, "Ordinary")])
        self.t.add_run(SID, RUN, [{"type": "started", "agentId": AID, "label": "Label", "phase": "P"}], {AID: [ft.r_assistant_text(self.now - 5000, "m1", "Body before completion")]})
        self.t.add_terminal(SID, RUN, {
            "status": "completed", "workflowName": "Ordinary", "timestamp": ft.iso(self.now - 1000), "startTime": self.now - 9000, "durationMs": 8000,
            "workflowProgress": [{"type": "workflow_agent", "agentId": AID, "label": private_label or "Label", "state": "done", "phaseTitle": "P"}],
        })
        return self.t.session_dir(SID) / "subagents" / "workflows" / RUN / f"agent-{AID}.jsonl"

    def test_events_up_to_finish_are_served(self):
        self.finished_run()
        server = self.publish()
        code, body, _ = server.agent(aid=AID)
        self.assertEqual(code, 200)
        self.assertIn("Body before completion", [e["text"] for e in json.loads(body)["events"]])

    def test_record_written_after_finish_is_not_served(self):
        for label, ts in (("New timestamp", now_ms() + 1000), ("Old timestamp", self.now - 4000)):  # Limit by bytes regardless of timestamp.
            with self.subTest(label):
                self.t = Tree("h8")
                self.servers = []
                p = self.finished_run()
                server = self.publish(self.t)
                ft.write_jsonl(p, [ft.r_assistant_text(ts, "m2", V)])
                code, body, _ = server.agent(aid=AID)
                self.assertEqual(code, 200)
                self.assertNotIn(V.encode(), body)
                self.assertIn("Body before completion".encode(), body)
                server.close()

    def test_late_write_with_snapshot_republish_is_still_cut(self):
        p = self.finished_run()
        server = self.publish()
        ft.write_jsonl(p, [ft.r_assistant_text(now_ms() + 1000, "m2", V)])
        server.publish()
        time.sleep(1.1)  # Force a fresh read independently of rate limits.
        self.assertNotIn(V.encode(), server.agent(aid=AID)[1])

    def test_private_snapshot_still_redacts(self):
        self.finished_run("client-x notes")
        server = self.publish()
        d = json.loads(server.agent(aid=AID)[1])
        self.assertTrue(d["header"]["private"])
        self.assertEqual({e["text"] for e in d["events"] if e["kind"] == "text"}, {PRIVATE})

    def test_terminal_agent_without_file_at_finish_has_no_events(self):
        p = self.finished_run()
        server = self.publish()
        rec = server.sc.claude.sessions[SID].runs[RUN]
        self.assertEqual(rec.final_sizes[AID], os.path.getsize(p))


# ---- H9 ----
class H9Variants(Hot):
    GROUP_A = [
        "passwords: " + V,
        "access_tokens: " + V,
        "refresh_tokens = " + V,
        '"auth_tokens": "' + V + '"',
        "db_password_prod=" + V,
        "client_secret_v2: " + V,
        "DB_PASSWORD_PROD: " + V,
        "{&quot;password&quot;:&quot;a " + V + "&quot;}",
        "password=&quot;a " + V + "&quot;",
        "&#116;oken=" + V,
        "&#x74;oken=" + V,
        "\\164oken=" + V,
        "\\u{74}oken=" + V,
        "\\U00000074oken=" + V,
        "%252574oken=" + V,
        "pass\u200bword=" + V,
        "pass\u00adword=" + V,
        "\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44=" + V,
        "pa%73\\u0073word=" + V,
        '{\\"pass\\\\u0077ord\\":\\"' + V + '\\"}',  # JSON inside JSON.
    ]
    GROUP_B = [
        "export API_TOKEN=\\\n  " + V,
        "password=\\\n  " + V,
        "--password \\\n  " + V,
        "curl -u \\\n  alice:" + V,
        "pass\\\nword=" + V,
        "password: |\n    line1\n    " + V + "\nnext: 1",
        "token: >-\n  " + V + "\n  more" + V,
        "  private_key: |-\n      " + V + "\n  other: 1",
        "--password " + V,
        "--token\t" + V,
        '["--token","' + V + '"]',
        "-u alice:" + V,
        "--user alice:" + V,
        "wget -u 'alice:" + V + "' x",
        "Api-Key: abc\n    " + V,
        "Private-Token: abc\n    " + V,
        'password = "abc" + "' + V + '"',
        "token: 'abc' . '" + V + "'",
        'password = "abc" "' + V + '"',
        'password = "abc" + ' + V,
        'MY_TOKEN="abc"+"' + V + '"',
    ]

    def test_variants_never_reach_api(self):
        for name, group in (("a", self.GROUP_A), ("b", self.GROUP_B)):
            with self.subTest(name):
                t = Tree("h9")
                t.add_registry(SID)
                t.add_main(SID, [ft.r_assistant_text(self.now - 1000 + i, f"m{i}", raw) for i, raw in enumerate(group)])
                server = self.publish(t)
                state_body = server.get("/api/state")[1]
                code, detail, _ = server.agent()
                self.assertEqual(code, 200)
                self.assertNotIn(V.encode(), state_body)
                self.assertNotIn(V.encode(), detail)
                self.assertEqual(len([e for e in json.loads(detail)["events"] if e["kind"] == "text"]), len(group))  # Guard against vacuous success.
                server.close()

    def test_each_variant_alone(self):
        for raw in [*self.GROUP_A, *self.GROUP_B]:
            with self.subTest(raw):
                out = masking.safe_text(raw, 300)
                self.assertNotIn(V, out)
                self.assertIn("[MASK]", out)

    def test_block_scalar_ends_at_sibling(self):
        out = masking.mask_patterns("password: |\n    a\n    b\nuser: kim\n")
        self.assertEqual(out, "password: [MASK]\nuser: kim\n")

    def test_no_false_positive_on_near_names(self):
        rows_ = [
            "password_field = form.find('input')", "password_reset_url = make()", "token_count = 5", "max_tokens: 4096", "tokens = text.split()",
            "input_tokens: 123", "access_token_ttl = 3600", "secret_santa_list = []", "api_key_required = True", "session_id_map = {}",
            "compass_v2: north", "pass_1: ok", "passes: 3", "passkey_enabled = True",
            "git push -u origin main", "git push -u origin feature:main", "docker run -u 1000:1000 image", "docker run -u root:root image",
            "ffuf -u https://example.com/FUZZ", "sqlmap -u 'http://a.b/c'",
            "Tom &amp; Jerry", "a &lt; b &gt; c", "\\u00e9 \\x41 \\101 %41", "100% &amp; 50%",
            "폭 없는\u200b문자가 있는 문장", "\uff21\uff22\uff23 전각 문자",
            'label = "a" + "b"', "total = 1 + 2",
        ]
        for raw in rows_:
            with self.subTest(raw):
                self.assertEqual(masking.mask_patterns(raw), raw)




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
