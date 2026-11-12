"""Pure status functions accepting now_ms; no file or clock access."""
from __future__ import annotations

from dataclasses import dataclass

from config import (
    BG_OUTPUT_ACTIVE_S,
    BG_PROCESS_SLACK_MS,
    CODEX_M_S,
    CODEX_N_S,
    CODEX_ORPHAN_S,
    FINISH_RESUME_SLACK_MS,
    HUMAN_WAIT_TOOLS,
    M_STALL_S,
    N_WAIT_S,
    ORPHAN_QUIET_S,
    TOOL_TIMEOUT_CAP_MS,
    TOOL_TIMEOUT_GRACE_S,
)
from masking import safe_text

RUNNING = "running"
WAITING = "waiting"
STALLED = "stalled"
FINISHED = "finished"
ORPHANED = "orphaned"
BG_WAIT_LABEL = "Waiting for background jobs"
IDLE = "idle"
CLOSED = "closed"
UNKNOWN = "unknown"

ACTIVE_STATES = (RUNNING, WAITING, STALLED)
TERMINAL_STATES = (FINISHED, ORPHANED, CLOSED)


@dataclass(slots=True)
class Verdict:
    status: str
    label: str
    outcome: str | None = None
    finish_source: str | None = None
    confidence: str = "high"


@dataclass(slots=True)
class Finish:
    outcome: str
    source: str
    ts_ms: int | None = None
    confidence: str = "high"


def fmt_minutes(ms: float) -> str:
    m = int(ms // 60_000)
    if m <= 0:
        return "under 1 minute"  # Changing labels every tick would prevent ETag 304 responses.
    if m < 60:
        return f"{m}min"
    return f"{m // 60}h {m % 60}min"


def finished_label(outcome: str | None) -> str:
    return {"completed": "Completed", "failed": "Failed", "killed": "Stopped", "stopped": "Stopped"}.get(outcome or "", "Finished (other)")


def step_label(step: dict, now_ms: int) -> str:
    kind = step.get("kind")
    since = step.get("since_ms")
    span = fmt_minutes(max(0, now_ms - since)) if since else ""
    if kind == "tool":
        tool = step.get("tool") or "Tool"
        if tool in ("Agent", "Task"):
            return "Waiting for subagents"
        return f"Running tool: {tool} {span}".strip()
    if kind == "model_wait":
        return f"Waiting for model response {span}".strip()
    if kind == "thinking":
        return f"Thinking {span}".strip()
    if kind == "writing":
        return f"Writing response {span}".strip()
    if kind == "retry":
        a, b = step.get("attempt"), step.get("max")
        return f"API retry {a}/{b}" if a is not None and b is not None else "API retry"
    if kind == "turn_end":
        return "Response complete"
    if kind == "prompt":
        return "Prompt received"
    if kind == "compact":
        return "Compacting context"
    return "Quiet"


def signal_valid(ts_ms: int | None, last_au_ms: int | None) -> bool:
    """Assistant/user records after a completion signal indicate resumption."""
    if ts_ms is None or last_au_ms is None:
        return True
    return ts_ms + FINISH_RESUME_SLACK_MS >= last_au_ms


def resolve_direct_finish(
    *,
    notification: dict | None,
    sync_status: str | None,
    sync_ms: int | None,
    meta_finished: bool,
    meta_stopped: bool,
    meta_mtime_ms: int | None,
    stop_ms: int | None,
    parent_resolved_ms: int | None,
    is_async: bool,
    tail_end: bool,
    tail_ms: int | None,
    own_bg_pending: int,
    backfill_done: bool,
    last_au_ms: int | None,
) -> Finish | None:
    """Direct-agent completion signals, in precedence order."""
    if notification is not None and not notification.get("waiting_notice"):
        status = notification.get("status")
        ts = notification.get("ts_ms")
        if status and signal_valid(ts, last_au_ms):
            return Finish(status if status in ("completed", "failed", "killed", "stopped") else "other", "notification", ts)
    if sync_status is not None and signal_valid(sync_ms, last_au_ms):
        return Finish("completed" if sync_status == "completed" else "other", "sync_result", sync_ms)
    if meta_finished and signal_valid(meta_mtime_ms, last_au_ms):
        return Finish("stopped" if meta_stopped else "completed", "meta", meta_mtime_ms)
    if stop_ms is not None and signal_valid(stop_ms, last_au_ms):
        return Finish("stopped", "taskstop", stop_ms)
    if parent_resolved_ms is not None and not is_async and signal_valid(parent_resolved_ms, last_au_ms):
        # A synchronous child without its own completion signal ends when the parent call finishes.
        return Finish("other", "parent", parent_resolved_ms)
    if tail_end and own_bg_pending == 0 and backfill_done:
        return Finish("completed", "tail", tail_ms, "inferred")
    return None


def resolve_workflow_finish(
    *,
    terminal_state: str | None,
    run_outcome: str | None,
    journal_state: str | None,
    tail_end: bool,
    tail_ms: int | None,
    own_bg_pending: int = 0,
    backfill_done: bool = True,
) -> Finish | None:
    if terminal_state is not None:
        if terminal_state == "done":
            return Finish("completed", "terminal")
        if terminal_state == "error":
            return Finish("failed", "terminal")
        if terminal_state == "progress":
            return Finish("killed" if run_outcome == "killed" else "other", "terminal")
        return Finish("other", "terminal")
    if run_outcome is not None:
        return Finish("killed" if run_outcome == "killed" else "other", "terminal")
    if journal_state == "result":
        return Finish("completed", "journal")
    if journal_state == "failed":
        return Finish("failed", "journal")
    # Tail inference follows direct-agent rules: unfinished background work or incomplete backfill prevents completion.
    if tail_end and own_bg_pending == 0 and backfill_done:
        return Finish("completed", "tail", tail_ms, "inferred")
    return None


def agent_status(a, now_ms: int, parent_live: bool | None) -> Verdict:
    """a provides finish, turn_ended, own_bg_pending, effective_activity_ms, step, and backfill_done."""
    if a.finish is not None:
        return Verdict(FINISHED, finished_label(a.finish.outcome), a.finish.outcome, a.finish.source, a.finish.confidence)
    if parent_live is False:
        return Verdict(ORPHANED, "No completion record")
    if a.turn_ended and a.own_bg_pending > 0:
        return Verdict(WAITING, BG_WAIT_LABEL)
    step = a.step or {}
    if step.get("kind") == "tool" and step.get("tool") in HUMAN_WAIT_TOOLS:
        return Verdict(WAITING, "Waiting for user input")
    if a.turn_ended and not getattr(a, "backfill_done", True):
        return Verdict(WAITING, "Checking completion")
    quiet_s = (now_ms - (a.effective_activity_ms or 0)) / 1000
    limit_s = M_STALL_S
    if step.get("kind") == "tool" and step.get("timeout_ms"):
        limit_s = max(limit_s, min(step["timeout_ms"], TOOL_TIMEOUT_CAP_MS) / 1000 + TOOL_TIMEOUT_GRACE_S)
    if quiet_s > ORPHAN_QUIET_S and a.own_bg_pending == 0:
        return Verdict(ORPHANED, "No completion record")
    if quiet_s <= N_WAIT_S:
        return Verdict(RUNNING, "Working")
    if quiet_s <= limit_s:
        return Verdict(WAITING, step_label(step, now_ms))
    return Verdict(STALLED, f"Possibly stalled ({int(quiet_s // 60)}min without response)")


def main_status(reg_status: str | None, live: bool | None, a, now_ms: int) -> Verdict:
    """Session status classification."""
    if live is False:
        return Verdict(CLOSED, "Closed")
    if reg_status is None:
        if getattr(a, "turn_ended", False) and a.own_bg_pending == 0:
            return Verdict(IDLE, "Response complete")
        return agent_status(a, now_ms, None)
    if reg_status == "busy":
        # The registry may still say busy while the main thread waits for asynchronous jobs after ending its turn.
        if getattr(a, "turn_ended", False) and a.own_bg_pending == 0:
            return Verdict(IDLE, "Response complete")
        v = agent_status(a, now_ms, True)
        if v.status == ORPHANED:
            quiet_s = (now_ms - (a.effective_activity_ms or 0)) / 1000
            return Verdict(STALLED, f"Possibly stalled ({int(quiet_s // 60)}min without response)")
        return v
    if reg_status == "idle":
        return Verdict(IDLE, "Waiting for input")
    if reg_status == "waiting":
        return Verdict(WAITING, "Waiting for permission or response (inferred)")
    if reg_status == "shell":
        return Verdict(RUNNING, "Shell running (inferred)")
    return Verdict(WAITING, f"Status: {safe_text(str(reg_status), 32)}")


def session_state(reg_status: str | None, live: bool | None) -> str:
    if live is False:
        return "closed"
    if reg_status in ("busy", "idle", "waiting", "shell"):
        return reg_status
    return "unknown"


def workflow_status(
    *,
    terminal_status: str | None,
    notification_status: str | None,
    agent_statuses: list[str],
    parent_live: bool | None,
    last_activity_ms: int | None,
    now_ms: int,
) -> Verdict:
    """Derive workflow status from its agents."""
    if terminal_status is not None:
        outcome = terminal_status if terminal_status in ("completed", "failed", "killed") else "other"
        return Verdict(FINISHED, finished_label(outcome), outcome, "terminal")
    if notification_status is not None:
        outcome = notification_status if notification_status in ("completed", "failed", "killed", "stopped") else "other"
        return Verdict(FINISHED, finished_label(outcome), outcome, "notification")
    if parent_live is False:
        return Verdict(ORPHANED, "No completion record")
    live_agents = [s for s in agent_statuses if s in ACTIVE_STATES]
    if live_agents:
        if RUNNING in live_agents:
            return Verdict(RUNNING, "Working")
        if WAITING in live_agents:
            return Verdict(WAITING, "Waiting for agents")
        return Verdict(STALLED, "Possibly stalled")
    quiet_s = (now_ms - (last_activity_ms or 0)) / 1000
    if parent_live is None and quiet_s > ORPHAN_QUIET_S:
        return Verdict(ORPHANED, "No completion record")
    if quiet_s <= N_WAIT_S:
        return Verdict(RUNNING, "Working")
    if quiet_s <= M_STALL_S:
        return Verdict(WAITING, "Waiting for next phase")
    return Verdict(STALLED, f"Possibly stalled ({int(quiet_s // 60)}min without response)")


def codex_status(r, now_ms: int) -> Verdict:
    """3.7. r: turn_open, last_growth_ms, last_record_ms, running_cmd_since_ms, pending_wait, outcome, desktop."""
    if not r.turn_open:
        outcome = r.outcome or "completed"
        label = "Turn complete" if r.desktop else finished_label(outcome)
        return Verdict(FINISHED, label, outcome)
    quiet_s = (now_ms - max(r.last_growth_ms or 0, r.last_record_ms or 0)) / 1000
    if quiet_s > CODEX_ORPHAN_S:
        return Verdict(ORPHANED, "No completion record")
    if quiet_s > CODEX_M_S:
        return Verdict(STALLED, f"Possibly stalled ({int(quiet_s // 60)}min without response)")
    if r.running_cmd_since_ms:
        label = f"Running command {fmt_minutes(max(0, now_ms - r.running_cmd_since_ms))}"
    elif r.pending_wait:
        label = f"Waiting: {r.pending_wait}"
    else:
        label = "Waiting for response"
    if quiet_s <= CODEX_N_S:
        return Verdict(RUNNING, label if r.running_cmd_since_ms else "Working")
    return Verdict(WAITING, label)


def bg_gone(
    *,
    started_ms: int | None = None,
    process_started_ms: int | None = None,
    expires_ms: int | None = None,
    output_mtime_ms: int | None = None,
    output_missing: bool = False,
    now_ms: int = 0,
) -> str | None:
    """Evidence of completion without a terminal record, or None. Owner waiting uses the same rules."""
    if expires_ms and now_ms >= expires_ms:
        return "expired"
    if output_mtime_ms and (now_ms - output_mtime_ms) / 1000 <= BG_OUTPUT_ACTIVE_S:
        return None  # Current output indicates activity.
    if process_started_ms and started_ms and started_ms < process_started_ms - BG_PROCESS_SLACK_MS:
        return "prior"  # Jobs started before the session process belong to an earlier process.
    if output_missing:
        return "missing"
    return None


def bg_status(
    *,
    notification: dict | None,
    stop_ms: int | None,
    session_live: bool | None,
    owner_finished: bool,
    start_seen: bool,
    backfill_done: bool,
    output_mtime_ms: int | None,
    now_ms: int,
    started_ms: int | None = None,
    process_started_ms: int | None = None,
    expires_ms: int | None = None,
    output_missing: bool = False,
    monitor: bool = False,
) -> Verdict:
    """3.8 + critic MUST-15."""
    if notification is not None:
        if notification.get("orphan_notice"):
            return Verdict(FINISHED, "Unfinished in previous session", "other", "notification")
        status = notification.get("status")
        if status:
            outcome = status if status in ("completed", "failed", "killed", "stopped") else "other"
            return Verdict(FINISHED, finished_label(outcome), outcome, "notification")
    if stop_ms is not None:
        return Verdict(FINISHED, "Stopped", "stopped", "taskstop")
    if session_live is False:
        if monitor:  # Monitor runs inside the session process and ends with it even without expiry.
            return Verdict(FINISHED, "Ended with session (inferred)", "other", "session", "inferred")
        return Verdict(ORPHANED, "No completion record")
    if not start_seen:
        if not backfill_done:
            return Verdict(UNKNOWN, "Checking")
        return Verdict(ORPHANED, "No record")
    if owner_finished:
        return Verdict(FINISHED, "Ended with agent (inferred)", "other", "owner")
    gone = bg_gone(
        started_ms=started_ms, process_started_ms=process_started_ms, expires_ms=expires_ms,
        output_mtime_ms=output_mtime_ms, output_missing=output_missing, now_ms=now_ms,
    )
    if gone == "expired":
        return Verdict(FINISHED, "Expired", "other", "expiry")
    if gone == "prior":
        return Verdict(FINISHED, "Earlier process job (inferred ended)", "other", "process", "inferred")
    if gone == "missing":
        return Verdict(ORPHANED, "Output file missing (inferred ended)")
    if output_mtime_ms and (now_ms - output_mtime_ms) / 1000 <= BG_OUTPUT_ACTIVE_S:
        return Verdict(RUNNING, "Producing output")
    return Verdict(WAITING, "Running quietly")
