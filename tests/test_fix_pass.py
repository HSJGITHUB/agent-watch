"""Synthetic regression tests for fixes from an independent code review."""
import json
import os
import socket
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import collect_bg  # noqa: E402
import fixture_tree as ft  # noqa: E402
import masking  # noqa: E402
import model  # noqa: E402
import server as srv  # noqa: E402
import status as st  # noqa: E402
from claude_parse import SessionIndex, TranscriptState, loads_line, scan_backfill_line  # noqa: E402
from collect_codex import CodexCollector  # noqa: E402
from config import INIT_TAIL, STATE_JSON_MAX, TICK_READ_CAP, Settings  # noqa: E402
from fixture_tree import AID, AID2, RUN, SID, Tree, collector, iso, run_ticks, scratch_dir  # noqa: E402
from masking import MASK, PRIVATE, command_first_token, safe_text  # noqa: E402
from tailreader import Budget, IncrementalReader, RangeScanner  # noqa: E402
from test_codex import UUID, cmd_done, complete, ev, exec_call, meta, started, turn_ctx  # noqa: E402


def now_ms():
    return int(time.time() * 1000)


T = now_ms() - 60_000


def pad_lines(ts, n, size=30_000):
    return [ev(ts, type="brand_new", pad="y" * size) for _ in range(n)]


def tool_out(ts, call, text):
    return {"timestamp": iso(ts), "type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": call, "output": [{"type": "input_text", "text": text}]}}


def fn_call(ts, call, name="wait"):
    return {"timestamp": iso(ts), "type": "response_item", "payload": {"type": "function_call", "call_id": call, "name": name, "arguments": "{}"}}


def fn_out(ts, call, text):
    return {"timestamp": iso(ts), "type": "response_item", "payload": {"type": "function_call_output", "call_id": call, "output": text}}


class CodexBase(unittest.TestCase):
    def setUp(self):
        self.t = Tree("fix")
        self.c = CodexCollector(self.t.paths())

    def ticks(self, n=1):
        now = now_ms()
        self.c.discover(now, Budget(TICK_READ_CAP))
        for _ in range(n):
            self.c.tick(now, Budget(TICK_READ_CAP))
        return self.c.build(now)[0][0]


class CodexHead(CodexBase):
    """Runs larger than 256KB."""

    def big(self, tail):
        # Head: metadata, context, first turn start. Middle: completion and second turn. Tail: caller-supplied lines.
        head = [meta(), turn_ctx(), started(T)]
        mid = pad_lines(T + 1, 15) + [complete(T + 2), started(T + 3), complete(T + 4)] + pad_lines(T + 5, 15)
        return head + mid + tail

    def test_model_effort_sandbox_from_head(self):
        self.t.add_rollout(self.big([started(T + 6), exec_call(T + 7, "ls")]))
        r = self.ticks()
        self.assertEqual((r["model"], r["effort"], r["sandbox"]), ("gpt-6-astra", "high", "workspace-write"))

    def test_turns_counted_across_gap(self):
        p = self.t.add_rollout(self.big([started(T + 6), exec_call(T + 7, "ls")]))
        self.assertGreater(p.stat().st_size, INIT_TAIL * 2)
        r = self.ticks(4)
        self.assertEqual(r["turns"], {"started": 3, "completed": 2, "exact": True})

    def test_head_task_started_does_not_reopen_finished_turn(self):
        self.t.add_rollout(self.big([started(T + 6), complete(T + 7)]))
        r = self.ticks(4)
        self.assertEqual(r["status"], "finished")
        self.assertEqual((r["turns"]["started"], r["turns"]["completed"]), (3, 3))

    def test_turns_lower_bound_before_gap_done(self):
        self.t.add_rollout(self.big([started(T + 6), exec_call(T + 7, "ls")]))
        now = now_ms()
        self.c.discover(now, Budget(TICK_READ_CAP))
        rec = next(iter(self.c.runs.values()))
        self.c._poll(rec, now, Budget(TICK_READ_CAP))
        r = self.c.build(now)[0][0]
        self.assertFalse(r["turns"]["exact"])
        self.assertGreaterEqual(r["turns"]["started"], r["turns"]["completed"] + 1)

    def test_tail_context_beats_head(self):
        tail = [{"timestamp": iso(T + 6), "type": "turn_context", "payload": {"model": "gpt-new", "effort": "low", "sandbox_policy": {"type": "read-only"}}}, started(T + 7)]
        self.t.add_rollout(self.big(tail))
        r = self.ticks()
        self.assertEqual((r["model"], r["effort"], r["sandbox"]), ("gpt-new", "low", "read-only"))

    def test_last_message_while_running(self):
        msg = ev(T + 5, type="item_completed", item={"type": "AgentMessage", "content": [{"type": "Text", "text": "Fixing tests"}]})
        self.t.add_rollout([meta(), started(), msg])
        self.assertEqual(self.ticks()["last_message"], "Fixing tests")


class CodexOutput(CodexBase):
    """M6: custom_tool_call_output."""

    def test_output_without_session_clears_command(self):
        self.t.add_rollout([meta(), started(), exec_call(T + 1, "ls"), tool_out(T + 2, "c1", 'Script completed\nWall time 1.0 seconds\nOutput:\n{"exit_code":0}')])
        r = self.ticks()
        self.assertIsNone(r["last_command"])
        self.assertNotIn("Running command", r["status_label"])

    def test_session_marker_keeps_long_command(self):
        self.t.add_rollout([meta(), started(), exec_call(T + 1, "sleep 500"), tool_out(T + 2, "c1", 'Script completed\nOutput:\n{"wall_time_seconds":1.0,"session_id":42}')])
        self.assertEqual(self.ticks()["last_command"]["state"], "running")

    def test_two_commands_one_still_running(self):
        inp = 'text(await tools.exec_command({cmd:"first"}));text(await tools.exec_command({cmd:"second"}));'
        rec = {"timestamp": iso(T + 1), "type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c1", "input": inp}}
        self.t.add_rollout([meta(), started(), rec, tool_out(T + 2, "c1", '{"exit_code":0}\n{"session_id":7}')])
        lc = self.ticks()["last_command"]
        self.assertEqual((lc["state"], lc["text"]), ("running", "second"))

    def test_script_running_waits_for_wait_output(self):
        recs = [meta(), started(), exec_call(T + 1, "sleep 9"), tool_out(T + 2, "c1", "Script running with cell ID 3\nWall time 1.0 seconds\nOutput:\n")]
        self.t.add_rollout(recs)
        self.assertEqual(self.ticks()["last_command"]["state"], "running")

    def test_wait_output_settles_cell(self):
        self.t.add_rollout([
            meta(), started(), exec_call(T + 1, "sleep 9"), tool_out(T + 2, "c1", "Script running with cell ID 3\nOutput:\n"),
            fn_call(T + 3, "w1"), fn_out(T + 4, "w1", "Script completed\nOutput:\n"),
        ])
        self.assertIsNone(self.ticks()["last_command"])

    def test_completion_matches_by_text_not_order(self):
        inp = 'text(await tools.exec_command({cmd:"first"}));text(await tools.exec_command({cmd:"second"}));'
        rec = {"timestamp": iso(T + 1), "type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c1", "input": inp}}
        self.t.add_rollout([meta(), started(), rec, cmd_done(T + 2, "second")])
        lc = self.ticks()["last_command"]
        self.assertEqual((lc["state"], lc["text"]), ("running", "first"))

    def test_output_body_never_stored(self):
        secret = "This body must not be stored"
        self.t.add_rollout([meta(), started(), exec_call(T + 1, "ls"), tool_out(T + 2, "c1", secret)])
        self.ticks()
        rec = next(iter(self.c.runs.values()))
        self.assertNotIn(secret, json.dumps([list(rec.events), rec.running, rec.last_done], ensure_ascii=False))

    def test_turn_aborted_closes_turn(self):
        self.t.add_rollout([meta(), started(), exec_call(T + 1, "ls"), ev(T + 2, type="turn_aborted", reason="interrupted")])
        r = self.ticks()
        self.assertEqual((r["status"], r["outcome"]), ("finished", "other"))
        self.assertIsNone(r["last_command"])


class CodexIds(CodexBase):
    """Invalid values must not be exported."""

    def test_bad_thread_id_uses_filename(self):
        self.t.add_rollout([meta(id="../../evil", session_id="AKIA" + "ABCDEFGHIJKLMNOP"), started()])
        self.assertEqual(self.ticks()["thread_id"], UUID)

    def test_bad_parent_thread_dropped(self):
        self.t.add_rollout([meta(source={"subagent": {"thread_spawn": {"parent_thread_id": "AKIA" + "ABCDEFGHIJKLMNOP"}}}), started()])
        self.assertIsNone(self.ticks()["parent_thread_id"])

    def test_rate_fields_masked(self):
        fake = "AKIA" + "ABCDEFGHIJKLMNOP"
        rl = {"primary": {"used_percent": 1.0, "window_minutes": fake, "resets_at": 1}, "plan_type": fake}
        self.t.add_rollout([meta(), started(), ev(T + 1, type="token_count", rate_limits=rl)])
        self.ticks()
        u = self.c.usage_view()
        self.assertNotIn(fake, json.dumps(u))


class ClaudeBase(unittest.TestCase):
    def setUp(self):
        self.t = Tree("fixc")
        self.now = now_ms()

    def view(self, sid=SID, c=None):
        c = c or collector(self.t)
        v = run_ticks(c, now_ms())
        self.v = v
        self.c = c
        return next(s for s in v["sessions"] if s["id"] == sid)

    def agent(self, s, aid=AID):
        return next(a for a in s["agents"] if a["agent_id"] == aid)

    def bg(self, tid):
        return next((b for b in self.v["bg_tasks"] if b["task_id"] == tid), None)

    def start(self, tid="bx1234567", ts=None):
        ts = ts or self.now - 5000
        return [
            ft.r_assistant_tool(ts, "m1", "t1", "Bash", {"description": "Server", "run_in_background": True}),
            ft.r_tool_result(ts + 10, "t1", f"Command running in background with ID: {tid}. x", tur={"backgroundTaskId": tid}),
        ]


class ElapsedM2(ClaudeBase):
    def test_finished_agent_elapsed_uses_start_not_tail_window(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        later = self.now + 1500_000
        recs = [ft.r_assistant_text(self.now, "m0", "Start")]
        recs += [ft.r_assistant_text(later - 1000, f"p{i}", "z" * 3000) for i in range(120)]
        recs += [ft.r_assistant_text(later, "m9", "Done", stop="end_turn")]
        self.t.add_agent(SID, AID, recs, {"description": "Long task", "requestShape": "background", "finished": True})
        a = self.agent(self.view())
        self.assertEqual(a["status"], "finished")
        self.assertGreater(a["elapsed_ms"], 1000_000)


class BgGhostM3(ClaudeBase):
    def setUp(self):
        super().setUp()
        self.t.add_registry(SID)  # startedAt is one hour ago.

    def test_task_older_than_process_is_not_running(self):
        self.t.add_main(SID, self.start(ts=self.now - 2 * 3600_000))
        self.t.add_output(SID, "bother")
        s = self.view()
        self.assertEqual(s["counts"]["bg_running"], 0)
        self.assertEqual(s["main"]["own_bg_pending"], 0)
        self.assertIsNone(self.bg("bx1234567"))

    def test_older_task_with_recent_output_stays_alive(self):
        self.t.add_main(SID, self.start(ts=self.now - 2 * 3600_000))
        self.t.add_output(SID, "bx1234567", b"x")
        self.assertEqual(self.view()["counts"]["bg_running"], 1)
        self.assertEqual(self.bg("bx1234567")["status"], "running")

    def test_output_gone_in_known_tasks_dir_is_not_running(self):
        self.t.add_main(SID, self.start())
        self.t.add_output(SID, "bother")
        s = self.view()
        self.assertEqual(s["counts"]["bg_running"], 0)
        self.assertEqual((self.bg("bx1234567")["status"], self.bg("bx1234567")["status_label"]), ("orphaned", "Output file missing (inferred ended)"))

    def test_owner_wait_uses_same_rule(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        recs = self.start(ts=self.now - 2 * 3600_000) + [ft.r_assistant_text(self.now - 60_000, "m9", "Done", stop="end_turn")]
        self.t.add_agent(SID, AID, recs, {"description": "Owner", "requestShape": "background"})
        self.t.add_output(SID, "bother")
        self.assertEqual(self.agent(self.view())["status"], "finished")

    def test_pure_rule(self):
        now = 10_000_000
        kw = dict(notification=None, stop_ms=None, session_live=True, owner_finished=False, start_seen=True, backfill_done=True, now_ms=now)
        v = st.bg_status(output_mtime_ms=None, started_ms=1000, process_started_ms=9_000_000, **kw)
        self.assertEqual((v.status, v.finish_source, v.confidence), (st.FINISHED, "process", "inferred"))
        v = st.bg_status(output_mtime_ms=None, started_ms=8_996_000, process_started_ms=9_000_000, **kw)
        self.assertEqual(v.status, st.WAITING)  # Within the five-second slack.
        v = st.bg_status(output_mtime_ms=now - 1000, started_ms=1000, process_started_ms=9_000_000, **kw)
        self.assertEqual(v.status, st.RUNNING)


class ToolCountM4(ClaudeBase):
    def test_duplicate_ids_counted_once(self):
        self.t.add_registry(SID)
        ids = [f"toolu_{i:03d}" for i in range(5)]
        recs = [ft.r_assistant_tool(self.now - 900, f"m{i}", t, "Grep", {"pattern": "x"}) for i, t in enumerate(ids)]
        recs += [ft.r_assistant_text(self.now - 800, f"p{i}", "z" * 3000) for i in range(120)]
        recs += [ft.r_assistant_tool(self.now - 700, f"r{i}", t, "Grep", {"pattern": "x"}) for i, t in enumerate(ids)]
        self.t.add_main(SID, recs)
        tc = self.view()["main"]["tool_calls"]
        self.assertEqual(tc, {"value": 5, "exact": True})

    def test_reader_moves_first_start_to_line_boundary(self):
        d = scratch_dir("fixc")
        p = d / "f.jsonl"
        lines = [json.dumps({"i": i, "p": "x" * 90}).encode() + b"\n" for i in range(100)]
        p.write_bytes(b"".join(lines))
        r = IncrementalReader(p, tail=555)
        tail = r.poll()
        scanner = RangeScanner(p, r.first_start)
        head = []
        while not scanner.done:
            head.extend(scanner.step())
        seen = [json.loads(x)["i"] for x in head + tail]
        self.assertEqual(seen, list(range(100)))

    def test_boundary_when_tail_starts_on_line_start(self):
        d = scratch_dir("fixc")
        p = d / "f.jsonl"
        lines = [json.dumps({"i": i}).encode() + b"\n" for i in range(50)]
        data = b"".join(lines)
        p.write_bytes(data)
        r = IncrementalReader(p, tail=len(b"".join(lines[-10:])))
        tail = r.poll()
        scanner = RangeScanner(p, r.first_start)
        head = []
        while not scanner.done:
            head.extend(scanner.step())
        self.assertEqual([json.loads(x)["i"] for x in head + tail], list(range(50)))

    def test_backfill_unique_ids(self):
        idx = SessionIndex()
        ids = set()
        rec = ft.r_assistant_tool(1, "m", "toolu_abc", "Grep")
        raw = json.dumps(rec, separators=(",", ":")).encode()
        self.assertEqual(scan_backfill_line(raw, idx, None, ids), 1)
        self.assertEqual(scan_backfill_line(raw, idx, None, ids), 0)
        self.assertEqual(scan_backfill_line(raw, idx, None), 1)


class MonitorM5(ClaudeBase):
    EXPIRES = "Monitor started (task bmon12345, expires in 20m unless the source ends first; you get one notice at expiry \u2014 re-arm if you still need the watch). You will be notified on each event."
    PERSIST = "Monitor started (task bmon12345, persistent \u2014 runs until TaskStop or session end). You will be notified on each event."
    TIMEOUT = "Monitor started (task bmon12345, timeout 300000ms). You will be notified on each event."

    def setUp(self):
        super().setUp()
        self.t.add_registry(SID)

    def recs(self, text, ts=None, tur=None):
        ts = ts or self.now - 5000
        return [
            ft.r_assistant_tool(ts, "m1", "t1", "Monitor", {"description": "Watch logs", "command": "tail -f x"}),
            ft.r_tool_result(ts + 10, "t1", text, tur=tur),
        ]

    def test_start_recognized(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 9000)] + self.recs(self.EXPIRES))
        self.t.add_output(SID, "bmon12345")
        self.view()
        b = self.bg("bmon12345")
        self.assertEqual((b["kind"], b["start_seen"], b["description"], b["status"]), ("monitor", True, "Watch logs", "running"))

    def test_agent_waiting_on_monitor_is_not_finished(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 9000)])
        recs = self.recs(self.EXPIRES) + [ft.r_assistant_text(self.now - 1000, "m9", "Waiting", stop="end_turn")]
        self.t.add_agent(SID, AID, recs, {"description": "Watcher", "requestShape": "background"})
        self.t.add_output(SID, "bmon12345")
        a = self.agent(self.view())
        self.assertEqual((a["status"], a["own_bg_pending"]), ("waiting", 1))

    def test_expired_monitor_closes(self):
        ts = self.now - 30 * 60_000
        self.t.add_main(SID, [ft.r_prompt(self.now - 40 * 60_000)] + self.recs(self.EXPIRES, ts))
        p = self.t.add_output(SID, "bmon12345")
        ft.set_mtime(p, ts)
        s = self.view()
        b = self.bg("bmon12345")
        self.assertEqual((b["status"], b["status_label"], b["outcome"]), ("finished", "Expired", "other"))
        self.assertEqual(s["counts"]["bg_running"], 0)
        self.assertEqual(b["finished_ms"], ts + 10 + 20 * 60_000)

    def test_persistent_has_no_expiry(self):
        ts = self.now - 30 * 60_000
        tur = {"persistent": True, "taskId": "bmon12345", "timeoutMs": 300000}
        self.t.add_main(SID, [ft.r_prompt(self.now - 40 * 60_000)] + self.recs(self.PERSIST, ts, tur))
        p = self.t.add_output(SID, "bmon12345")
        ft.set_mtime(p, ts)
        self.view()
        self.assertEqual(self.bg("bmon12345")["status"], "waiting")

    def test_timeout_form_uses_phrase(self):
        ts = self.now - 30 * 60_000
        self.t.add_main(SID, [ft.r_prompt(self.now - 40 * 60_000)] + self.recs(self.TIMEOUT, ts))
        p = self.t.add_output(SID, "bmon12345")
        ft.set_mtime(p, ts)
        self.view()
        self.assertEqual(self.bg("bmon12345")["finished_ms"], ts + 10 + 300_000)

    def test_stream_ended_notification_closes(self):
        recs = self.recs(self.EXPIRES) + [ft.r_notify_user(self.now - 1000, ft.notification("bmon12345", summary="Monitor \"log\" stream ended"))]
        self.t.add_main(SID, [ft.r_prompt(self.now - 9000)] + recs)
        self.t.add_output(SID, "bmon12345")
        self.view()
        self.assertEqual((self.bg("bmon12345")["status"], self.bg("bmon12345")["outcome"]), ("finished", "completed"))

    def test_backfill_finds_start_and_description(self):
        pad = [ft.r_assistant_text(self.now - 1000, f"p{i}", "z" * 3000) for i in range(120)]
        self.t.add_main(SID, [ft.r_prompt(self.now - 9000)] + self.recs(self.EXPIRES) + pad)
        self.t.add_output(SID, "bmon12345")
        self.view()
        b = self.bg("bmon12345")
        self.assertEqual((b["kind"], b["start_seen"], b["description"]), ("monitor", True, "Watch logs"))


class FreshnessPerf1(ClaudeBase):
    def test_tick_updates_agent_status(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        p = self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now - 100_000, "m1", "Quiet")], {"description": "Task", "requestShape": "background"})
        ft.set_mtime(p, self.now - 100_000)
        c = collector(self.t)
        s = self.view(c=c)
        self.assertEqual(self.agent(s)["status"], "waiting")
        ft.write_jsonl(p, [ft.r_assistant_text(now_ms(), "m2", "Resumed")])
        now = now_ms()
        c.tick(now, Budget(TICK_READ_CAP))
        v = c.build(now)
        a = self.agent(next(x for x in v["sessions"] if x["id"] == SID))
        self.assertEqual(a["status"], "running")
        self.assertEqual(a["last_write_ms"], p.stat().st_mtime_ns // 1_000_000)


class Privacy(ClaudeBase):
    def setUp(self):
        super().setUp()
        self.t.add_registry(SID)

    def test_sec3_private_agent_redacts_owned_bg(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        self.t.add_agent(SID, AID, self.start(), {"description": "client-x notes", "requestShape": "background"})
        self.t.add_output(SID, "bx1234567")
        self.view()
        b = self.bg("bx1234567")
        self.assertEqual(b["description"], PRIVATE)

    def test_sec3_main_owned_bg_not_redacted_by_terminal_agents(self):
        self.t.add_main(SID, self.start())
        self.t.add_output(SID, "bx1234567")
        self.view()
        self.assertEqual(self.bg("bx1234567")["description"], "Server")

    def test_sec3_title_hit_hides_project_name(self):
        self.t.add_main(SID, [{"type": "ai-title", "aiTitle": "client-x draft"}, ft.r_prompt(self.now - 1000)])
        s = self.view()
        self.assertEqual((s["title"], s["project_name"]), (PRIVATE, PRIVATE))

    def test_sec2_free_strings_masked(self):
        fake = "AKIA" + "ABCDEFGHIJKLMNOP"
        rec = ft.r_assistant_tool(self.now - 500, "m1", "t1", "Grep", {"pattern": "x"})
        rec["message"]["model"] = fake
        rec["effort"] = fake
        self.t.add_registry(SID, cwd=f"c:\\fixture\\{fake}", status=fake)
        self.t.add_main(SID, [rec])
        body = json.dumps(self.view(), ensure_ascii=False)
        self.assertNotIn(fake, body)

    def test_sec2_well_formed_canary_not_shown_as_id(self):
        fake = "AKIA" + "ABCDEFGHIJKLMNOP"
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now - 500, "m1", "x")], {"description": "Task", "requestShape": "background", "toolUseId": fake, "parentAgentId": fake})
        self.assertNotIn(fake, json.dumps(self.agent(self.view())))

    def test_sec10_backfill_runs_for_unregistered_recent_session(self):
        recs = [ft.r_assistant_text(self.now - 1000, f"p{i}", "z" * 3000) for i in range(80)]
        recs += [{"type": "custom-title", "customTitle": "client-x consultation record"}]
        recs += [ft.r_assistant_text(self.now - 1000, f"q{i}", "z" * 3000) for i in range(120)]
        self.t.add_main(ft.SID2, recs)
        s = self.view(ft.SID2)
        self.assertEqual(s["title"], PRIVATE)

    def test_sec2_bad_meta_ids_dropped(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        fake = "AKIA" + "ABCDEFGHIJKLMNOP!"
        self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now - 500, "m1", "x")], {"description": "Task", "requestShape": "background", "toolUseId": fake, "parentAgentId": fake})
        a = self.agent(self.view())
        self.assertIsNone(a["parent_tool_use_id"])
        self.assertIsNone(a["parent_agent_id"])

    def test_sec4_cut_agents_leave_index(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        for i in range(105):
            self.t.add_agent(SID, f"a{i:016x}", [ft.r_assistant_text(self.now - 500 + i, "m1", "x")], {"description": f"Task {i}", "requestShape": "background"})
        s = self.view()
        shown = {a["agent_id"] for a in s["agents"]}
        self.assertEqual(len(shown), 100)
        keys = {k[1] for k in self.v["index"] if k[0] == SID}
        self.assertEqual(keys - {"main"}, shown)

    def test_sec9_registry_sid_must_be_uuid(self):
        self.t.add_registry("..\\..\\evil", pid=os.getpid() + 7)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        c = collector(self.t)
        self.assertNotIn("..\\..\\evil", c.scan_registry())

    def test_sec9_journal_agent_id_must_match(self):
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        self.t.add_run(SID, RUN, [{"type": "started", "agentId": "..\\..\\..\\secret", "label": "x"}], {})
        s = self.view()
        self.assertEqual(s["workflows"][0]["agents"], [])

    def test_sec9_bad_background_id_ignored(self):
        idx = SessionIndex()
        state = TranscriptState(None, idx)
        state.feed(ft.r_assistant_tool(self.now, "m1", "t1", "Bash", {"run_in_background": True}))
        state.feed(ft.r_tool_result(self.now, "t1", "x", tur={"backgroundTaskId": "..\\..\\x"}))
        self.assertEqual(idx.bg, {})

    def test_sec10_title_between_windows_found_by_backfill(self):
        recs = [ft.r_assistant_text(self.now - 1000, f"p{i}", "z" * 3000) for i in range(80)]
        recs += [{"type": "custom-title", "customTitle": "client-x consultation record"}]
        recs += [ft.r_assistant_text(self.now - 1000, f"q{i}", "z" * 3000) for i in range(120)]
        self.t.add_main(SID, recs)
        s = self.view()
        self.assertEqual(s["title"], PRIVATE)
        self.assertTrue(s["title_hidden"])


class GhostRowsM1(ClaudeBase):
    def setUp(self):
        super().setUp()
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])

    def test_zero_byte_temp_output_hidden(self):
        self.t.add_output(SID, "bghost123", b"")
        c = collector(self.t)
        self.view(c=c)
        self.view(c=c)
        self.assertIsNone(self.bg("bghost123"))

    def test_vanished_output_removed_from_index(self):
        p = self.t.add_output(SID, "bghost123", b"x")
        c = collector(self.t)
        self.view(c=c)
        self.assertIn("bghost123", next(iter(c.sessions.values())).idx.bg)
        os.replace(p, p.with_name("moved.txt"))
        self.view(c=c)
        self.assertNotIn("bghost123", next(iter(c.sessions.values())).idx.bg)

    def test_one_scan_is_not_enough(self):
        self.t.add_output(SID, "bghost123", b"x")
        c = collector(self.t)
        self.view(c=c)
        self.assertIsNone(self.bg("bghost123"))
        self.view(c=c)
        self.assertIsNotNone(self.bg("bghost123"))


class Sorting(unittest.TestCase):
    def test_running_and_waiting_share_rank(self):
        from collect_claude import _agent_sort_key
        rows = [{"status": "waiting", "started_ms": 1}, {"status": "running", "started_ms": 2}, {"status": "stalled", "started_ms": 3}, {"status": "finished", "started_ms": 0}]
        rows.sort(key=_agent_sort_key)
        self.assertEqual([r["started_ms"] for r in rows], [3, 1, 2, 0])

    def test_stalled_session_sorts_first(self):
        from collect_claude import _session_sort_key
        base = {"state": "busy", "live": True}
        quiet = dict(base, counts={"running": 1, "waiting": 0, "stalled": 0, "bg_running": 0}, main={"status": "running"}, last_activity_ms=100)
        stuck = dict(base, counts={"running": 0, "waiting": 0, "stalled": 1, "bg_running": 0}, main={"status": "idle"}, last_activity_ms=1)
        main_stuck = dict(base, counts={"running": 0, "waiting": 0, "stalled": 0, "bg_running": 0}, main={"status": "stalled"}, last_activity_ms=2)
        rows = sorted([quiet, stuck, main_stuck], key=_session_sort_key)
        self.assertIs(rows[-1], quiet)


class ShrinkPerf3(unittest.TestCase):
    def state(self, agents, bg):
        a = [{"agent_id": f"a{i}", "status": "running", "pad": "x" * 2000} for i in range(agents)]
        return {
            "server": {"truncated": False},
            "sessions": [{"agents": a, "workflows": [{"status": "running", "agents": list(a)}]}],
            "bg_tasks": [{"status": "finished" if i % 2 else "running", "task_id": str(i), "pad": "y" * 500} for i in range(bg)],
            "codex_runs": [],
        }

    def test_hard_limit_when_everything_active(self):
        s = self.state(400, 0)
        self.assertLess(len(model.finalize_json(s)), STATE_JSON_MAX)
        self.assertTrue(s["server"]["truncated"])
        self.assertEqual((len(s["sessions"][0]["agents"]), s["sessions"][0]["agents_omitted"]), (50, 350))
        self.assertEqual(s["sessions"][0]["workflows"][0]["agents_omitted"], 350)

    def test_bg_keeps_active_first(self):
        s = self.state(300, 3000)
        for i, b in enumerate(s["bg_tasks"]):
            b["status"] = "running" if i >= 2500 else "orphaned"
        model.finalize_json(s)
        self.assertEqual(s["bg_omitted"], 2800)
        self.assertTrue(all(b["status"] == "running" for b in s["bg_tasks"]))

    def test_small_state_untouched(self):
        s = self.state(3, 3)
        model.finalize_json(s)
        self.assertFalse(s["server"]["truncated"])
        self.assertNotIn("agents_omitted", s["sessions"][0])


class Masking(unittest.TestCase):
    def test_sec1_random_slash_value(self):
        # Mask the entire slash-separated value if any fragment looks random.
        v = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        self.assertNotIn(v, safe_text(f"key {v} end", 200))

    def test_sec1_digitless_mixed_case(self):
        v = "aBcDeFgHiJkLmNoPqRsTuVwXyZaBcD"
        self.assertNotIn(v, safe_text(f"key {v} end", 200))

    def test_sec1_paths_and_names_survive(self):
        for s in ("tests/test_collect/fixture_tree_helpers.py", "src/ComponentName/SomethingLongEnough.tsx", "feature/agent-watch-fix-pass-261030", "agent_watch_261030/static/index_backup_copy"):
            self.assertIn(s, safe_text(s, 200))

    def test_sec5_first_token_format_checked(self):
        self.assertEqual(command_first_token("python x.py"), "python")
        self.assertEqual(command_first_token("/usr/bin/git status"), "git")
        self.assertEqual(command_first_token("eyJ" + "a" * 120 + ".bbbbbbbbbb.cccccccccc x"), "(command)")
        self.assertEqual(command_first_token("$pw='hunter2value'; x"), "(command)")

    def test_sec7_long_options(self):
        for opt in ("--access-token", "--client-secret", "--refresh-token", "--auth-token", "--api_key", "--secret-key", "--private-key", "--pwd"):
            self.assertNotIn("Zx9qLm3pRt7vW", safe_text(f"tool {opt} Zx9qLm3pRt7vW next", 200), opt)

    def test_sec7_keeps_harmless_options(self):
        for s in ("curl --keep-alive 5 x", "tool --monkey 3", "tool --tokenizer gpt"):
            self.assertEqual(safe_text(s, 200), s)

    def test_sec7_more_names(self):
        self.assertNotIn("v4lue1234", safe_text("signature=v4lue1234 x", 200))
        self.assertNotIn("v4lue1234", safe_text("bearer=v4lue1234 x", 200))
        self.assertNotIn("v4lue1234", safe_text("비밀번호: v4lue1234 x", 200))
        self.assertNotIn("v4lue1234", safe_text("토큰 값은 v4lue1234 x", 200))

    def test_sec7_known_prefixes(self):
        sg = "SG." + "aB3dE5gH7jK9mN1pQ3sT5v" + "." + "wX7yZ9bC1dF3gH5jK7mN9pQ1sT3vW5xY7zA9bC1dE3f"
        self.assertNotIn("aB3dE5gH7jK9", safe_text(f"key {sg} end", 200))
        hook = "https://hooks.slack" + ".com/services/T00000000/B00000000/" + "XXXXXXXXXXXXXXXXXXXXXXXX"
        self.assertNotIn("T00000000", safe_text(hook, 200))

    def test_sec7_no_false_positive_on_words(self):
        self.assertEqual(safe_text("design: 3 obsession: x", 200), "design: 3 obsession: x")


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        t = Tree("fixh")
        t.add_registry(SID)
        t.add_main(SID, [ft.r_prompt(now_ms() - 500)])
        cls.app = srv.App(t.paths(), Settings(tick_s=0.5), port=0)
        cls.app.bind()
        cls.app.start()
        cls.port = cls.app.port
        for _ in range(100):
            if cls.app.scanner.first_tick_ms is not None:
                break
            time.sleep(0.05)

    @classmethod
    def tearDownClass(cls):
        cls.app.stop()

    def raw(self, data: bytes) -> bytes:
        s = socket.create_connection(("127.0.0.1", self.port), timeout=5)
        s.sendall(data)
        out = b""
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                out += chunk
        except TimeoutError:
            pass
        s.close()
        return out

    def test_sec6_post_body_not_executed(self):
        inner = f"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\n\r\n".encode()
        req = f"POST / HTTP/1.1\r\nHost: evil.com\r\nOrigin: http://evil.com\r\nContent-Length: {len(inner)}\r\n\r\n".encode() + inner
        out = self.raw(req)
        self.assertEqual(out.count(b"HTTP/1.1 "), 1)
        self.assertIn(b"405", out.split(b"\r\n", 1)[0])
        self.assertNotIn(b'"ok"', out)

    def test_sec6_denied_host_closes_connection(self):
        out = self.raw(b"GET / HTTP/1.1\r\nHost: evil.com\r\n\r\nGET /healthz HTTP/1.1\r\nHost: evil.com\r\n\r\n")
        self.assertEqual(out.count(b"HTTP/1.1 "), 1)

    def test_sec8_error_paths_carry_security_headers(self):
        cases = {
            b"GET / HTTP/9.9\r\n\r\n": b"505",
            b"PROPFIND / HTTP/1.1\r\nHost: x\r\n\r\n": b"501",
            b"GET /" + b"a" * 70_000 + b" HTTP/1.1\r\nHost: x\r\n\r\n": b"414",
        }
        for req, code in cases.items():
            out = self.raw(req)
            head = out.split(b"\r\n\r\n", 1)[0].lower()
            self.assertIn(code, out.split(b"\r\n", 1)[0])
            self.assertIn(b"content-security-policy", head)
            self.assertIn(b"x-content-type-options: nosniff", head)

    def test_perf4_first_tick_in_healthz(self):
        body = self.raw(f"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1:{self.port}\r\nConnection: close\r\n\r\n".encode())
        d = json.loads(body.split(b"\r\n\r\n", 1)[1])
        self.assertIsInstance(d["first_tick_ms"], float)




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
