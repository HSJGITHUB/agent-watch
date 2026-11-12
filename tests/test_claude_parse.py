import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import claude_parse as cp  # noqa: E402
import fixture_tree as ft  # noqa: E402
from masking import PRIVATE  # noqa: E402

T = 1_790_000_000_000


def state(owner=None):
    return cp.TranscriptState(owner, cp.SessionIndex())


def feed(s, *recs):
    for r in recs:
        s.feed(json.loads(json.dumps(r)))


class Steps(unittest.TestCase):
    def test_pending_tool(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "Bash", {"description": "Build", "timeout": 5000}))
        st = s.step()
        self.assertEqual((st["kind"], st["tool"], st["arg"], st["since_ms"], st["timeout_ms"]), ("tool", "Bash", "Build", T, 5000))

    def test_tool_result_resolves_to_model_wait(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "Read", {"file_path": "a/b.py"}), ft.r_tool_result(T + 5, "t1"))
        self.assertEqual(s.step()["kind"], "model_wait")
        self.assertEqual(s.last_tool["ok"], True)
        self.assertEqual(s.last_tool["arg"], "b.py")

    def test_tool_error_marks_last_tool(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "Read"), ft.r_tool_result(T + 5, "t1", is_error=True))
        self.assertIs(s.last_tool["ok"], False)

    def test_parallel_calls(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "Read"), ft.r_assistant_tool(T + 1, "m1", "t2", "Grep", {"pattern": "x"}))
        st = s.step()
        self.assertEqual((st["tool"], st["parallel"]), ("Grep", 1))
        feed(s, ft.r_tool_result(T + 2, "t2"))
        self.assertEqual(s.step()["tool"], "Read")

    def test_api_request_wait(self):
        s = state()
        feed(s, ft.r_api_request(T))
        self.assertEqual(s.step()["kind"], "model_wait")

    def test_thinking(self):
        s = state()
        feed(s, ft.r_assistant_thinking(T, "m1"))
        self.assertEqual(s.step()["kind"], "thinking")

    def test_writing(self):
        s = state()
        feed(s, ft.r_assistant_text(T, "m1", "Writing"))
        self.assertEqual(s.step()["kind"], "writing")
        self.assertEqual(s.last_text, "Writing")

    def test_retry(self):
        s = state()
        feed(s, ft.r_system(T, "api_error", retryAttempt=2, maxRetries=10))
        st = s.step()
        self.assertEqual((st["kind"], st["attempt"], st["max"]), ("retry", 2, 10))

    def test_end_turn(self):
        s = state()
        feed(s, ft.r_assistant_text(T, "m1", "Done", stop="end_turn"))
        self.assertTrue(s.turn_ended)

    def test_other_stop_reasons_are_turn_end(self):
        for stop in ("refusal", "stop_sequence", "max_tokens", "unknown_new"):
            with self.subTest(stop):
                s = state()
                feed(s, ft.r_assistant_text(T, "m1", "Done", stop=stop))
                self.assertTrue(s.turn_ended)

    def test_tool_ends_turn(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "StructuredOutput"), ft.r_tool_result(T + 1, "t1", ends_turn=True))
        self.assertTrue(s.turn_ended)
        self.assertEqual(s.last_tool["arg"], "(submit final result)")

    def test_stop_hook(self):
        s = state()
        feed(s, ft.r_system(T, "stop_hook_summary"))
        self.assertEqual(s.step()["kind"], "turn_end")

    def test_compact(self):
        s = state()
        feed(s, ft.r_system(T, "compact_boundary"))
        self.assertEqual(s.step()["kind"], "compact")

    def test_any_non_result_user_is_prompt(self):
        for kind in ("human", "coordinator", None):
            with self.subTest(kind):
                s = state()
                feed(s, ft.r_assistant_text(T, "m1", "Done", stop="end_turn"), ft.r_prompt(T + 1, kind))
                self.assertEqual(s.step()["kind"], "prompt")
                self.assertFalse(s.turn_ended)

    def test_new_message_clears_lost_pending(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "Read"), ft.r_assistant_tool(T + 1, "m2", "t2", "Grep"))
        self.assertEqual(list(s.pending), ["t2"])

    def test_unknown_records_ignored(self):
        s = state()
        feed(s, {"type": "brand-new-type", "timestamp": ft.iso(T)}, {"type": "mode", "mode": "x"}, {"type": "file-history-delta"})
        self.assertEqual(s.step()["kind"], "unknown")

    def test_non_dict_message_safe(self):
        s = state()
        s.feed({"type": "assistant", "message": "bad"})
        s.feed({"type": "user", "message": None})
        s.feed({"type": "system"})


class Usage(unittest.TestCase):
    def test_representative_record_is_max_output(self):
        s = state()
        u1 = {"input_tokens": 10, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 500, "iterations": [{}]}
        u2 = {"input_tokens": 10, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 24}
        feed(s, ft.r_assistant_text(T, "m1", "a", usage=u1), ft.r_assistant_text(T + 1, "m1", "b", usage=u2))
        self.assertEqual(s.last_ctx, 510)
        self.assertEqual(s.sum_out, 500)

    def test_iterations_win_ties(self):
        s = state()
        base = {"input_tokens": 1, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 5}
        feed(s, ft.r_assistant_text(T, "m1", "a", usage=dict(base)))
        feed(s, ft.r_assistant_text(T, "m1", "b", usage=dict(base, input_tokens=2, iterations=[1])))
        self.assertEqual(s.last_ctx, 7)

    def test_sum_across_messages(self):
        s = state()
        feed(s, ft.r_assistant_text(T, "m1", "a"), ft.r_assistant_text(T, "m2", "b"))
        self.assertEqual(s.sum_out, 40)
        self.assertEqual(s.last_ctx, 120)

    def test_tool_count(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "Read"), ft.r_assistant_tool(T, "m1", "t2", "Read"))
        self.assertEqual(s.tool_calls_seen, 2)


class Notifications(unittest.TestCase):
    def test_three_locations(self):
        text = ft.notification("b12345678", "failed", 'Background command "x" failed with exit code 3')
        for rec in (ft.r_notify_user(T, text), ft.r_notify_queue(T, text), ft.r_notify_attachment(T, text)):
            with self.subTest(rec["type"]):
                s = state()
                feed(s, rec)
                n = s.idx.notifs["b12345678"]
                self.assertEqual((n["status"], n["exit_code"]), ("failed", 3))

    def test_notification_event_has_status_only(self):
        s = state()
        feed(s, ft.r_notify_queue(T, ft.notification("b12345678", "failed", "Background command \"hidden\" failed with exit code 3")))
        e = list(s.events)[-1]
        self.assertEqual((e["kind"], e["arg"]), ("notification", "b12345678 failed (exit 3)"))

    def test_marker_in_tool_input_ignored(self):
        s = state()
        text = ft.notification("b99999999")
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "Bash", {"command": text, "description": "Write documentation"}))
        self.assertNotIn("b99999999", s.idx.notifs)

    def test_marker_in_assistant_text_ignored(self):
        s = state()
        feed(s, ft.r_assistant_text(T, "m1", ft.notification("b99999999")))
        self.assertNotIn("b99999999", s.idx.notifs)

    def test_marker_in_tool_result_ignored(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "Read"), ft.r_tool_result(T, "t1", ft.notification("b99999999")))
        self.assertNotIn("b99999999", s.idx.notifs)

    def test_human_prompt_with_marker_ignored(self):
        s = state()
        feed(s, ft.r_prompt(T, "human", ft.notification("b99999999")))
        self.assertNotIn("b99999999", s.idx.notifs)

    def test_monitor_event_not_finish(self):
        s = state()
        s.idx.bg["b1"] = {"task_id": "b1", "kind": "bash", "last_event_ms": None}
        text = ft.notification("b1", status=None, summary='Monitor event: "x"', event=True)
        feed(s, ft.r_notify_user(T, text))
        self.assertNotIn("b1", s.idx.notifs)
        self.assertEqual(s.idx.bg["b1"]["kind"], "monitor")
        self.assertEqual(s.idx.bg["b1"]["last_event_ms"], T)

    def test_exit_code(self):
        n = cp.parse_notifications(ft.notification("b1", "completed", 'Background command "x" completed (exit code 0)'))[0]
        self.assertEqual(n["exit_code"], 0)

    def test_orphan_phrases(self):
        for ph in (
            "Background shell command didn't finish before the previous session ended",
            "3 background shell command tasks from the previous session have no completion record",
            "No completion record was found for this task",
        ):
            with self.subTest(ph):
                self.assertTrue(cp.parse_notifications(ft.notification("b1", "completed", ph))[0]["orphan_notice"])

    def test_waiting_notice(self):
        n = cp.parse_notifications(ft.notification("a1", "completed", 'Agent "x" is waiting on its own background work'))[0]
        self.assertTrue(n["waiting_notice"])

    def test_usage_tags(self):
        n = cp.parse_notifications(ft.notification("a1", usage="<subagent_tokens>123</subagent_tokens><tool_uses>4</tool_uses><duration_ms>5</duration_ms>"))[0]
        self.assertEqual((n["tokens"], n["tool_uses"], n["duration_ms"]), (123, 4, 5))

    def test_workflow_usage(self):
        n = cp.parse_notifications(ft.notification("w1", usage="<total_tokens>9</total_tokens><agent_count>3</agent_count><agents_done>2</agents_done><agents_error>1</agents_error>"))[0]
        self.assertEqual((n["tokens"], n["agent_count"], n["agents_done"], n["agents_error"]), (9, 3, 2, 1))

    def test_result_body_cannot_fake_tags(self):
        text = ("<task-notification><task-id>a1</task-id><status>completed</status><summary>x</summary>"
                "<result><status>failed</status><subagent_tokens>999</subagent_tokens></result>"
                "<usage><subagent_tokens>1</subagent_tokens></usage></task-notification>")
        n = cp.parse_notifications(text)[0]
        self.assertEqual((n["status"], n["tokens"]), ("completed", 1))

    def test_last_notification_wins(self):
        s = state()
        feed(s, ft.r_notify_user(T, ft.notification("b1", "completed")), ft.r_notify_user(T + 10, ft.notification("b1", "failed")))
        self.assertEqual(s.idx.notifs["b1"]["status"], "failed")

    def test_older_notification_does_not_replace(self):
        s = state()
        feed(s, ft.r_notify_user(T + 10, ft.notification("b1", "failed")), ft.r_notify_user(T, ft.notification("b1", "completed")))
        self.assertEqual(s.idx.notifs["b1"]["status"], "failed")

    def test_multiple_blocks(self):
        text = ft.notification("b1") + "\n" + ft.notification("b2")
        self.assertEqual(len(cp.parse_notifications(text)), 2)


class Starts(unittest.TestCase):
    def test_bg_start_tool_use_result(self):
        s = state()
        feed(
            s,
            ft.r_assistant_tool(T, "m1", "t1", "Bash", {"description": "Start server", "run_in_background": True}),
            ft.r_tool_result(T + 1, "t1", "Command running in background with ID: bx1234567. Output is being written to: x", tur={"backgroundTaskId": "bx1234567"}),
        )
        rec = s.idx.bg["bx1234567"]
        self.assertTrue(rec["start_seen"])
        self.assertEqual(rec["description"], "Start server")
        self.assertFalse(rec["auto_backgrounded"])

    def test_bg_start_text_only_subagent(self):
        s = state("a0123456789abcdef")
        feed(
            s,
            ft.r_assistant_tool(T, "m1", "t1", "Bash", {"description": "Long task"}),
            ft.r_tool_result(T + 1, "t1", "Command running in background with ID: bx1234567. Output is being written to: x"),
        )
        self.assertEqual(s.idx.bg["bx1234567"]["owner"], "a0123456789abcdef")

    def test_bg_moved_timeout(self):
        s = state()
        feed(
            s,
            ft.r_assistant_tool(T, "m1", "t1", "Bash", {"description": "Test"}),
            ft.r_tool_result(T + 1, "t1", "Command did not complete within its 120s timeout and was moved to the background (ID: bx1234567). Output is being written to: y"),
        )
        self.assertTrue(s.idx.bg["bx1234567"]["auto_backgrounded"])

    def test_start_phrase_inside_bash_output_ignored(self):
        s = state()
        feed(
            s,
            ft.r_assistant_tool(T, "m1", "t1", "Bash"),
            ft.r_tool_result(T + 1, "t1", "log line\nCommand running in background with ID: bfake1234\n"),
        )
        self.assertNotIn("bfake1234", s.idx.bg)

    def test_start_regex_only_on_tool_result(self):
        s = state()
        feed(s, ft.r_prompt(T, "human", "Command running in background with ID: bfake1234"))
        self.assertNotIn("bfake1234", s.idx.bg)

    def test_taskstop_tool_use_result(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "TaskStop", {"task_id": "b1"}),
             ft.r_tool_result(T + 1, "t1", "x", tur={"task_id": "b1", "task_type": "local_bash", "message": "m"}))
        self.assertEqual(s.idx.stops["b1"], T + 1)

    def test_taskstop_json_text_subagent(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "TaskStop", {"task_id": "b1"}),
             ft.r_tool_result(T + 1, "t1", '{"message":"Successfully stopped task: b1 (cmd)","task_id":"b1"}'))
        self.assertEqual(s.idx.stops["b1"], T + 1)

    def test_taskstop_plain_text(self):
        s = state()
        feed(s, ft.r_tool_result(T + 1, "t1", "Successfully stopped task: b2 (cmd)"))
        self.assertIn("b2", s.idx.stops)

    def test_workflow_start_mapping(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "Workflow", {"script": "hidden"}),
             ft.r_tool_result(T + 1, "t1", "launched", tur={"status": "async_launched", "taskId": "wabc12345", "taskType": "local_workflow", "runId": "wf_1-a", "workflowName": "Research", "summary": "hidden"}))
        w = s.idx.workflows["wf_1-a"]
        self.assertEqual((w["task_id"], w["name"]), ("wabc12345", "Research"))
        self.assertEqual(s.idx.wf_by_task["wabc12345"], "wf_1-a")
        self.assertTrue(s.idx.relist)

    def test_async_agent_call(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "Agent", {"description": "x", "run_in_background": True}),
             ft.r_tool_result(T + 1, "t1", "launched", tur={"isAsync": True, "status": "async_launched", "agentId": "a1"}))
        call = s.idx.agent_calls["t1"]
        self.assertTrue(call["async"] and call["resolved"])

    def test_sync_agent_result(self):
        s = state()
        feed(s, ft.r_assistant_tool(T, "m1", "t1", "Agent", {"description": "x"}),
             ft.r_tool_result(T + 1, "t1", "done", tur={"status": "completed", "agentId": "a1", "totalTokens": 77, "totalToolUseCount": 3, "totalDurationMs": 9}))
        call = s.idx.agent_calls["t1"]
        self.assertEqual((call["sync_status"], call["sync_tokens"], call["sync_tools"]), ("completed", 77, 3))


class Titles(unittest.TestCase):
    def test_custom_and_ai(self):
        s = state()
        feed(s, {"type": "ai-title", "aiTitle": "Automatic title"}, {"type": "custom-title", "customTitle": "My title"})
        self.assertEqual((s.title_ai, s.title_custom), ("Automatic title", "My title"))

    def test_denied_title(self):
        s = state()
        feed(s, {"type": "ai-title", "aiTitle": "client-x notes"})
        self.assertEqual(s.title_ai, PRIVATE)

    def test_last_prompt_not_stored(self):
        s = state()
        feed(s, {"type": "last-prompt", "lastPrompt": "Raw user text"})
        self.assertFalse(any("Raw user text" in str(getattr(s, k, "")) for k in s.__slots__ if k != "idx"))


class Backfill(unittest.TestCase):
    def test_marker_filter_and_count(self):
        idx = cp.SessionIndex()
        tool = json.dumps(ft.r_assistant_tool(T, "m1", "toolu_1", "Read"), separators=(",", ":")).encode()
        n = cp.scan_backfill_line(tool, idx, None)
        self.assertEqual(n, 1)

    def test_blob_excluded_from_count(self):
        blob = json.dumps({"type": "api-request-blob", "body": '{"type":"tool_use","id":"toolu_x"}'}, separators=(",", ":")).encode()
        raw = b'{"type":"api-request-blob","body":{"content":[{"type":"tool_use","id":"toolu_1"}]}}'
        idx = cp.SessionIndex()
        self.assertEqual(cp.scan_backfill_line(raw, idx, None), 0)
        self.assertEqual(cp.scan_backfill_line(blob, idx, None), 0)

    def test_notification_found(self):
        idx = cp.SessionIndex()
        rec = json.dumps(ft.r_notify_queue(T, ft.notification("b1"))).encode()
        cp.scan_backfill_line(rec, idx, None)
        self.assertIn("b1", idx.notifs)

    def test_start_with_description(self):
        idx = cp.SessionIndex()
        a = ft.r_assistant_tool(T, "m1", "t1", "Bash", {"description": "Long-running server", "run_in_background": True})
        b = ft.r_tool_result(T + 1, "t1", "Command running in background with ID: bx1234567. x", tur={"backgroundTaskId": "bx1234567"})
        for r in (a, b):
            cp.scan_backfill_line(json.dumps(r, separators=(",", ":"), ensure_ascii=False).encode(), idx, None)
        self.assertIn("Long-running server", idx.bg["bx1234567"]["description"])

    def test_extract_title(self):
        data = (json.dumps({"type": "ai-title", "aiTitle": "Head title"}, ensure_ascii=False) + "\n").encode()
        self.assertEqual(cp.extract_title(data), (None, "Head title"))




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
