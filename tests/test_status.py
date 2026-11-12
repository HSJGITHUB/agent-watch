import os
import sys
import unittest
from types import SimpleNamespace as NS

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import config as c  # noqa: E402
import status as st  # noqa: E402

NOW = 1_790_000_000_000


def agent(quiet_s=0, step=None, finish=None, turn_ended=False, pending=0, backfill_done=True):
    return NS(
        finish=finish, turn_ended=turn_ended, own_bg_pending=pending,
        effective_activity_ms=NOW - int(quiet_s * 1000), step=step or {"kind": "model_wait", "since_ms": NOW - 1000},
        backfill_done=backfill_done,
    )


class AgentThresholds(unittest.TestCase):
    def test_n_boundary(self):
        self.assertEqual(st.agent_status(agent(c.N_WAIT_S), NOW, True).status, st.RUNNING)
        self.assertEqual(st.agent_status(agent(c.N_WAIT_S + 1), NOW, True).status, st.WAITING)

    def test_m_boundary(self):
        self.assertEqual(st.agent_status(agent(c.M_STALL_S), NOW, True).status, st.WAITING)
        self.assertEqual(st.agent_status(agent(c.M_STALL_S + 1), NOW, True).status, st.STALLED)

    def test_tool_timeout_extends(self):
        s = {"kind": "tool", "tool": "Bash", "since_ms": NOW, "timeout_ms": 900_000}
        # Clamp timeout to ten minutes: max(720, 600+120) = 720.
        self.assertEqual(st.agent_status(agent(721, s), NOW, True).status, st.STALLED)

    def test_tool_timeout_below_cap_keeps_m(self):
        s = {"kind": "tool", "tool": "Bash", "since_ms": NOW, "timeout_ms": 60_000}
        self.assertEqual(st.agent_status(agent(700, s), NOW, True).status, st.WAITING)

    def test_timeout_cap_constant(self):
        self.assertEqual(c.TOOL_TIMEOUT_CAP_MS, 600_000)

    def test_stalled_label(self):
        v = st.agent_status(agent(900), NOW, True)
        self.assertIn("Possibly stalled", v.label)
        self.assertIn("15min", v.label)

    def test_tool_label_uses_minutes(self):
        s = {"kind": "tool", "tool": "Bash", "since_ms": NOW - 180_000}
        self.assertEqual(st.agent_status(agent(180, s), NOW, True).label, "Running tool: Bash 3min")

    def test_subagent_wait_label(self):
        s = {"kind": "tool", "tool": "Agent", "since_ms": NOW - 180_000}
        self.assertEqual(st.agent_status(agent(180, s), NOW, True).label, "Waiting for subagents")


class AgentSpecials(unittest.TestCase):
    def test_finished(self):
        v = st.agent_status(agent(10_000, finish=st.Finish("completed", "meta")), NOW, False)
        self.assertEqual((v.status, v.outcome, v.finish_source), (st.FINISHED, "completed", "meta"))

    def test_finished_labels(self):
        self.assertEqual(st.finished_label("failed"), "Failed")
        self.assertEqual(st.finished_label("killed"), "Stopped")
        self.assertEqual(st.finished_label("stopped"), "Stopped")
        self.assertEqual(st.finished_label("other"), "Finished (other)")

    def test_parent_dead_orphaned(self):
        self.assertEqual(st.agent_status(agent(1), NOW, False).status, st.ORPHANED)

    def test_parent_unknown_quiet_orphaned(self):
        self.assertEqual(st.agent_status(agent(c.ORPHAN_QUIET_S + 1), NOW, None).status, st.ORPHANED)

    def test_parent_live_long_quiet_orphaned_not_stalled_forever(self):
        self.assertEqual(st.agent_status(agent(c.ORPHAN_QUIET_S + 1), NOW, True).status, st.ORPHANED)

    def test_quiet_orphan_blocked_by_own_bg(self):
        v = st.agent_status(agent(c.ORPHAN_QUIET_S + 1, pending=1), NOW, True)
        self.assertEqual(v.status, st.STALLED)

    def test_own_bg_wait(self):
        v = st.agent_status(agent(5000, turn_ended=True, pending=2), NOW, True)
        self.assertEqual((v.status, v.label), (st.WAITING, "Waiting for background jobs"))

    def test_human_wait_not_stalled(self):
        for tool in c.HUMAN_WAIT_TOOLS:
            with self.subTest(tool):
                s = {"kind": "tool", "tool": tool, "since_ms": NOW - 87_000_000}
                v = st.agent_status(agent(87_000, s), NOW, True)
                self.assertEqual((v.status, v.label), (st.WAITING, "Waiting for user input"))

    def test_turn_end_before_backfill_held(self):
        v = st.agent_status(agent(1000, turn_ended=True, backfill_done=False), NOW, True)
        self.assertEqual((v.status, v.label), (st.WAITING, "Checking completion"))


def direct(**kw):
    d = dict(
        notification=None, sync_status=None, sync_ms=None, meta_finished=False, meta_stopped=False,
        meta_mtime_ms=None, stop_ms=None, parent_resolved_ms=None, is_async=True, tail_end=False,
        tail_ms=None, own_bg_pending=0, backfill_done=True, last_au_ms=None,
    )
    d.update(kw)
    return st.resolve_direct_finish(**d)


class DirectFinish(unittest.TestCase):
    def test_notification_first(self):
        f = direct(notification={"status": "failed", "ts_ms": NOW}, meta_finished=True)
        self.assertEqual((f.outcome, f.source), ("failed", "notification"))

    def test_unknown_notification_status_other(self):
        self.assertEqual(direct(notification={"status": "weird", "ts_ms": NOW}).outcome, "other")

    def test_waiting_notice_not_finish(self):
        self.assertIsNone(direct(notification={"status": "completed", "ts_ms": NOW, "waiting_notice": True}))

    def test_sync_result(self):
        self.assertEqual(direct(sync_status="completed", sync_ms=NOW).source, "sync_result")

    def test_meta(self):
        self.assertEqual(direct(meta_finished=True).outcome, "completed")
        self.assertEqual(direct(meta_finished=True, meta_stopped=True).outcome, "stopped")

    def test_taskstop(self):
        self.assertEqual(direct(stop_ms=NOW).outcome, "stopped")

    def test_tail_inferred(self):
        f = direct(tail_end=True, tail_ms=NOW)
        self.assertEqual((f.outcome, f.confidence), ("completed", "inferred"))

    def test_tail_blocked_by_own_bg(self):
        self.assertIsNone(direct(tail_end=True, own_bg_pending=1))

    def test_tail_blocked_before_backfill(self):
        self.assertIsNone(direct(tail_end=True, backfill_done=False))

    def test_resumed_after_notification_clears_finish(self):
        self.assertIsNone(direct(notification={"status": "completed", "ts_ms": NOW}, last_au_ms=NOW + 69_000))

    def test_resumed_after_meta_clears_finish(self):
        self.assertIsNone(direct(meta_finished=True, meta_mtime_ms=NOW, last_au_ms=NOW + 6000))

    def test_meta_within_slack_valid(self):
        self.assertIsNotNone(direct(meta_finished=True, meta_mtime_ms=NOW, last_au_ms=NOW + 4000))

    def test_resumed_then_finished_again(self):
        f = direct(notification={"status": "completed", "ts_ms": NOW + 70_000}, last_au_ms=NOW + 69_000)
        self.assertEqual(f.source, "notification")

    def test_foreground_parent_resolved(self):
        f = direct(parent_resolved_ms=NOW, is_async=False)
        self.assertEqual((f.outcome, f.source), ("other", "parent"))

    def test_async_parent_resolved_is_not_finish(self):
        self.assertIsNone(direct(parent_resolved_ms=NOW, is_async=True))


class MainTable(unittest.TestCase):
    def test_busy(self):
        self.assertEqual(st.main_status("busy", True, agent(1), NOW).status, st.RUNNING)

    def test_idle(self):
        v = st.main_status("idle", True, agent(1), NOW)
        self.assertEqual((v.status, v.label), (st.IDLE, "Waiting for input"))

    def test_waiting(self):
        v = st.main_status("waiting", True, agent(1), NOW)
        self.assertEqual((v.status, v.label), (st.WAITING, "Waiting for permission or response (inferred)"))

    def test_shell(self):
        v = st.main_status("shell", True, agent(1), NOW)
        self.assertEqual((v.status, v.label), (st.RUNNING, "Shell running (inferred)"))

    def test_unknown(self):
        v = st.main_status("brandnew", True, agent(1), NOW)
        self.assertEqual((v.status, v.label), (st.WAITING, "Status: brandnew"))

    def test_dead(self):
        self.assertEqual(st.main_status("busy", False, agent(1), NOW).status, st.CLOSED)

    def test_no_registry(self):
        self.assertEqual(st.main_status(None, None, agent(1), NOW).status, st.RUNNING)

    def test_busy_turn_ended_without_pending_is_idle(self):
        v = st.main_status("busy", True, agent(5000, turn_ended=True), NOW)
        self.assertEqual((v.status, v.label), (st.IDLE, "Response complete"))

    def test_busy_turn_ended_with_workflow_waits(self):
        v = st.main_status("busy", True, agent(5000, turn_ended=True, pending=1), NOW)
        self.assertEqual((v.status, v.label), (st.WAITING, "Waiting for background jobs"))

    def test_busy_live_main_never_orphaned(self):
        s = {"kind": "tool", "tool": "Bash", "since_ms": NOW - 7200_000}
        self.assertEqual(st.main_status("busy", True, agent(7200, s), NOW).status, st.STALLED)

    def test_no_registry_turn_end_not_stalled(self):
        self.assertEqual(st.main_status(None, None, agent(2000, turn_ended=True), NOW).status, st.IDLE)

    def test_session_state(self):
        self.assertEqual(st.session_state("busy", True), "busy")
        self.assertEqual(st.session_state("busy", False), "closed")
        self.assertEqual(st.session_state(None, None), "unknown")
        self.assertEqual(st.session_state("brandnew", True), "unknown")


class BgTable(unittest.TestCase):
    def b(self, **kw):
        d = dict(notification=None, stop_ms=None, session_live=True, owner_finished=False, start_seen=True, backfill_done=True, output_mtime_ms=None, now_ms=NOW)
        d.update(kw)
        return st.bg_status(**d)

    def test_notification(self):
        v = self.b(notification={"status": "failed"})
        self.assertEqual((v.status, v.outcome), (st.FINISHED, "failed"))

    def test_orphan_notice(self):
        v = self.b(notification={"status": "completed", "orphan_notice": True})
        self.assertEqual((v.status, v.label), (st.FINISHED, "Unfinished in previous session"))

    def test_taskstop(self):
        self.assertEqual(self.b(stop_ms=NOW).outcome, "stopped")

    def test_session_dead(self):
        self.assertEqual(self.b(session_live=False).status, st.ORPHANED)

    def test_owner_finished(self):
        v = self.b(owner_finished=True)
        self.assertEqual((v.status, v.outcome, v.label), (st.FINISHED, "other", "Ended with agent (inferred)"))

    def test_output_active(self):
        v = self.b(output_mtime_ms=NOW - 10_000)
        self.assertEqual((v.status, v.label), (st.RUNNING, "Producing output"))

    def test_quiet_never_stalled(self):
        v = self.b(output_mtime_ms=NOW - 86_400_000)
        self.assertEqual((v.status, v.label), (st.WAITING, "Running quietly"))

    def test_unknown_before_backfill(self):
        v = self.b(start_seen=False, backfill_done=False)
        self.assertEqual((v.status, v.label), (st.UNKNOWN, "Checking"))

    def test_no_record_after_backfill(self):
        v = self.b(start_seen=False, backfill_done=True)
        self.assertEqual((v.status, v.label), (st.ORPHANED, "No record"))

    def test_monitor_event_without_status_is_not_finish(self):
        self.assertEqual(self.b(notification={"status": None}).status, st.WAITING)


class CodexTable(unittest.TestCase):
    def r(self, quiet=0, turn_open=True, running=None, wait=None, desktop=False, growth=None):
        return NS(
            turn_open=turn_open, last_record_ms=NOW - quiet * 1000, last_growth_ms=growth, running_cmd_since_ms=running,
            pending_wait=wait, outcome=None if turn_open else "completed", desktop=desktop,
        )

    def test_finished(self):
        self.assertEqual(st.codex_status(self.r(turn_open=False), NOW).status, st.FINISHED)

    def test_desktop_turn_label(self):
        self.assertEqual(st.codex_status(self.r(turn_open=False, desktop=True), NOW).label, "Turn complete")

    def test_running(self):
        self.assertEqual(st.codex_status(self.r(c.CODEX_N_S), NOW).status, st.RUNNING)

    def test_waiting_response(self):
        v = st.codex_status(self.r(c.CODEX_N_S + 1), NOW)
        self.assertEqual((v.status, v.label), (st.WAITING, "Waiting for response"))

    def test_waiting_command(self):
        v = st.codex_status(self.r(c.CODEX_N_S + 1, running=NOW - 180_000), NOW)
        self.assertEqual((v.status, v.label), (st.WAITING, "Running command 3min"))

    def test_waiting_function_call(self):
        v = st.codex_status(self.r(c.CODEX_N_S + 1, wait="wait"), NOW)
        self.assertEqual(v.label, "Waiting: wait")

    def test_stalled(self):
        self.assertEqual(st.codex_status(self.r(c.CODEX_M_S + 1), NOW).status, st.STALLED)

    def test_orphaned(self):
        self.assertEqual(st.codex_status(self.r(c.CODEX_ORPHAN_S + 1), NOW).status, st.ORPHANED)

    def test_growth_beats_old_timestamp(self):
        r = self.r(c.CODEX_M_S + 100, growth=NOW - 5000)
        self.assertEqual(st.codex_status(r, NOW).status, st.RUNNING)


class Workflow(unittest.TestCase):
    def w(self, **kw):
        d = dict(terminal_status=None, notification_status=None, agent_statuses=[], parent_live=True, last_activity_ms=NOW, now_ms=NOW)
        d.update(kw)
        return st.workflow_status(**d)

    def test_terminal_values(self):
        self.assertEqual(self.w(terminal_status="completed").outcome, "completed")
        self.assertEqual(self.w(terminal_status="failed").outcome, "failed")
        self.assertEqual(self.w(terminal_status="killed").outcome, "killed")

    def test_unknown_terminal_no_exception(self):
        v = self.w(terminal_status="weird-state")
        self.assertEqual((v.status, v.outcome), (st.FINISHED, "other"))

    def test_notification(self):
        self.assertEqual(self.w(notification_status="completed").status, st.FINISHED)

    def test_parent_dead(self):
        self.assertEqual(self.w(parent_live=False).status, st.ORPHANED)

    def test_agent_waiting_keeps_run_waiting_past_m(self):
        v = self.w(agent_statuses=[st.WAITING, st.FINISHED], last_activity_ms=NOW - 20 * 60_000)
        self.assertEqual(v.status, st.WAITING)

    def test_any_running(self):
        self.assertEqual(self.w(agent_statuses=[st.WAITING, st.RUNNING, st.STALLED]).status, st.RUNNING)

    def test_all_stalled(self):
        self.assertEqual(self.w(agent_statuses=[st.STALLED, st.STALLED]).status, st.STALLED)

    def test_no_agents_mtime_rule(self):
        self.assertEqual(self.w(last_activity_ms=NOW - 1000).status, st.RUNNING)
        self.assertEqual(self.w(last_activity_ms=NOW - 100_000).status, st.WAITING)
        self.assertEqual(self.w(last_activity_ms=NOW - 800_000).status, st.STALLED)

    def test_no_agents_parent_unknown_orphaned(self):
        self.assertEqual(self.w(parent_live=None, last_activity_ms=NOW - 4000 * 1000).status, st.ORPHANED)


class WorkflowAgentFinish(unittest.TestCase):
    def f(self, **kw):
        d = dict(terminal_state=None, run_outcome=None, journal_state=None, tail_end=False, tail_ms=None)
        d.update(kw)
        return st.resolve_workflow_finish(**d)

    def test_terminal_states(self):
        self.assertEqual(self.f(terminal_state="done").outcome, "completed")
        self.assertEqual(self.f(terminal_state="error").outcome, "failed")
        self.assertEqual(self.f(terminal_state="progress", run_outcome="killed").outcome, "killed")
        self.assertEqual(self.f(terminal_state="progress", run_outcome="completed").outcome, "other")
        self.assertEqual(self.f(terminal_state="strange").outcome, "other")

    def test_journal(self):
        self.assertEqual(self.f(journal_state="result").source, "journal")
        self.assertEqual(self.f(journal_state="failed").outcome, "failed")

    def test_tail(self):
        f = self.f(tail_end=True)
        self.assertEqual((f.outcome, f.confidence), ("completed", "inferred"))

    def test_none(self):
        self.assertIsNone(self.f())


if __name__ == "__main__":
    unittest.main()
