"""Claude transcript records: events, state machines, and notifications. Raw text stays in local variables; all strings stored in state pass through masking."""
from __future__ import annotations

import json
import re
from collections import OrderedDict, deque
from datetime import datetime

from config import (
    AGENT_CALLS_MAX,
    EVENTS_PER_AGENT,
    HINTS_MAX,
    MSG_USAGE_KEEP,
    NOTIFS_MAX,
    PENDING_TOOLS_MAX,
    STOPS_MAX,
    TOOL_IDS_MAX,
    WORKFLOWS_MAX,
    WORKFLOWS_OPEN_MAX,
)
from masking import PRIVATE, field, is_denied, safe_text, summarize_tool_input
from model import EventLog

TOOL_USE_PATTERN = b'"type":"tool_use","id":"toolu_'
TOOL_ID_RE = re.compile(rb'"type":"tool_use","id":"(toolu_[A-Za-z0-9_-]+)"')
MARKERS = (
    b"backgroundTaskId",
    b"Command running in background with ID",
    b"moved to the background",
    b"task-notification",
    b"Successfully stopped task",
    b"local_workflow",
    b"async_launched",
    b'"run_in_background":true',  # Also recover launch descriptions.
    b"Monitor started",
    b'"name":"Monitor"',  # Recover Monitor descriptions.
    b'"custom-title"',  # Detect private titles outside the head and tail windows.
    b'"ai-title"',
)

NOTIF_OPEN = "<task-notification>"
_NOTIF_BLOCK = re.compile(r"<task-notification>(.*?)</task-notification>", re.S)
_TAGS = {
    t: re.compile(rf"<{t}>(.*?)</{t}>", re.S)
    for t in (
        "task-id", "tool-use-id", "status", "summary", "event",
        "subagent_tokens", "total_tokens", "tool_uses", "duration_ms",
        "agent_count", "agents_done", "agents_error",
    )
}
_EXIT_RE = re.compile(r"exit code (\d+)")
_BG_START_RE = re.compile(r"^\s*Command running in background with ID: ([A-Za-z0-9_-]+)")
_BG_MOVED_RE = re.compile(r"^\s*Command did not complete[^\n]*?moved to the background \(ID: ([A-Za-z0-9_-]+)\)")
_STOP_RE = re.compile(r'^\s*(?:\{\s*"message"\s*:\s*")?Successfully stopped task: ([A-Za-z0-9_-]+)')
# Supported forms: expires in 20m, timeout 600000ms, and persistent until TaskStop.
_MON_START_RE = re.compile(r"^\s*Monitor started \(task ([A-Za-z0-9_-]+)(?:, (?:expires in|timeout) (\d+)(ms|s|m|h)\b)?")
_UNIT_MS = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000}
BG_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")  # Validate values before using them in paths.
_ORPHAN_PHRASES = (
    "didn't finish before the previous session ended",
    "have no completion record",
    "No completion record was found",
)
_WAITING_PHRASE = "is waiting on its own background work"
OUTCOMES = ("completed", "failed", "killed", "stopped")


def parse_ts(v: object) -> int | None:
    """ISO 8601 'Z' → epoch ms."""
    if not isinstance(v, str) or len(v) < 19:
        return None
    try:
        return int(datetime.fromisoformat(v).timestamp() * 1000)
    except ValueError:
        return None


def normalize_outcome(status: object) -> str:
    return status if status in OUTCOMES else "other"


def _int_tag(body: str, name: str) -> int | None:
    m = _TAGS[name].search(body)
    if not m:
        return None
    try:
        return int(m.group(1).strip())
    except ValueError:
        return None


def parse_notifications(text: object) -> list[dict]:
    """Parse task-notification blocks; retain signals, not raw result or summary text."""
    if not isinstance(text, str) or NOTIF_OPEN not in text:
        return []
    out = []
    for m in _NOTIF_BLOCK.finditer(text):
        body = m.group(1)
        head = body.split("<result>", 1)[0]
        tail = body.rsplit("</result>", 1)[-1] if "</result>" in body else body
        # Text inside event is monitored output, not notification structure.
        plain = _TAGS["event"].sub("", head)
        tid_m = _TAGS["task-id"].search(plain)
        if not tid_m:
            continue
        status_m = _TAGS["status"].search(plain)
        status = status_m.group(1).strip().lower() if status_m else None
        summary_m = _TAGS["summary"].search(plain)
        summary = summary_m.group(1) if summary_m else ""
        exit_m = _EXIT_RE.search(summary)
        tool_use = _TAGS["tool-use-id"].search(head)
        tokens = _int_tag(tail, "subagent_tokens")
        if tokens is None:
            tokens = _int_tag(tail, "total_tokens")
        out.append(
            {
                "task_id": tid_m.group(1).strip(),
                "tool_use_id": tool_use.group(1).strip() if tool_use else None,
                "status": status,
                "exit_code": int(exit_m.group(1)) if exit_m else None,
                "orphan_notice": any(p in summary for p in _ORPHAN_PHRASES),
                "waiting_notice": _WAITING_PHRASE in summary,
                # A status marks completion, even when the final Monitor notification includes an event.
                "is_event": not status and (plain != head or summary.startswith("Monitor event")),
                "monitor": plain != head or summary.startswith("Monitor "),
                "tokens": tokens,
                "tool_uses": _int_tag(tail, "tool_uses"),
                "duration_ms": _int_tag(tail, "duration_ms"),
                "agent_count": _int_tag(tail, "agent_count"),
                "agents_done": _int_tag(tail, "agents_done"),
                "agents_error": _int_tag(tail, "agents_error"),
            }
        )
    return out


def _block_text(block: dict) -> str:
    c = block.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "\n".join(x.get("text", "") for x in c if isinstance(x, dict) and isinstance(x.get("text"), str))
    return ""


def _user_text(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(x.get("text", "") for x in content if isinstance(x, dict) and isinstance(x.get("text"), str))
    return ""


def _trim(d: OrderedDict, cap: int) -> None:
    while len(d) > cap:
        d.popitem(last=False)


def _new_bg(task_id: str, kind: str = "bash", owner=None, started_ms=None, start_seen: bool = False, auto: bool = False) -> dict:
    return {
        "task_id": task_id, "kind": kind, "owner": owner, "description": None,
        "started_ms": started_ms, "start_seen": start_seen, "auto_backgrounded": auto,
        "output_bytes": None, "output_mtime_ms": None, "last_event_ms": None,
    }


class ToolIds:
    """Count unique tool_use IDs. Once capped, stop growing the set and report approximate counts."""

    __slots__ = ("seen", "extra")

    def __init__(self):
        self.seen: set[bytes] = set()
        self.extra = 0

    def add(self, tool_id: bytes) -> None:
        if tool_id in self.seen:
            return
        if len(self.seen) < TOOL_IDS_MAX:
            self.seen.add(tool_id)
        else:
            self.extra += 1

    def update(self, ids) -> None:
        for tool_id in ids:
            self.add(tool_id)

    def __len__(self) -> int:
        return len(self.seen) + self.extra

    @property
    def exact(self) -> bool:
        return self.extra == 0


class SessionIndex:
    """Session index shared idempotently by main transcripts, agents, and backfill. Background rows are bounded by build_bg_views; other indexes use FIFO limits. forget_* also removes owned entries."""

    __slots__ = (
        "bg", "notifs", "stops", "agent_calls", "workflows", "wf_by_task", "hints", "relist", "title_custom", "title_ai", "title_pos",
        "stat_seq",
    )

    def __init__(self):
        self.bg: dict[str, dict] = {}
        self.notifs: OrderedDict[str, dict] = OrderedDict()
        self.stops: OrderedDict[str, int] = OrderedDict()
        self.agent_calls: OrderedDict[str, dict] = OrderedDict()
        self.workflows: OrderedDict[str, dict] = OrderedDict()
        self.wf_by_task: dict[str, str] = {}
        self.hints: OrderedDict[str, dict] = OrderedDict()
        self.relist = False
        # Masked head/backfill titles and offsets. Tail titles in TranscriptState are always newer.
        self.title_custom: str | None = None
        self.title_ai: str | None = None
        self.title_pos: dict[str, int] = {"custom": -1, "ai": -1}
        self.stat_seq = 0  # Round-robin position for stat_open_tasks.

    def set_title(self, kind: str, text: str | None, pos: int) -> None:
        """Accept only titles at later file offsets, regardless of reader."""
        if text is None or pos < self.title_pos[kind]:
            return
        self.title_pos[kind] = pos
        if kind == "custom":
            self.title_custom = text
        else:
            self.title_ai = text

    def call(self, tool_use_id: str, ts_ms: int | None) -> dict:
        c = self.agent_calls.get(tool_use_id)
        if c is None:
            c = self.agent_calls[tool_use_id] = _new_call(tool_use_id, ts_ms)
            _trim(self.agent_calls, AGENT_CALLS_MAX)
        return c

    def workflow(self, run_id: str, owner: str | None, ts_ms: int | None) -> dict:
        wf = self.workflows.get(run_id)
        if wf is None:
            wf = self.workflows[run_id] = {"run_id": run_id, "task_id": None, "name": None, "owner": owner, "ts_ms": ts_ms, "terminal": False}
            self._trim_workflows()
        return wf

    def _trim_workflows(self) -> None:
        """Evict finished runs first; open runs need launch names for privacy decisions."""
        over = len(self.workflows) - WORKFLOWS_MAX
        if over <= 0:
            return
        done = [k for k, w in self.workflows.items() if w.get("terminal")][:over]
        # Beyond WORKFLOWS_OPEN_MAX, evict oldest entries. Runs without names remain private.
        spill = len(self.workflows) - len(done) - WORKFLOWS_OPEN_MAX
        if spill > 0:
            done += [k for k, w in self.workflows.items() if not w.get("terminal")][:spill]
        for k in done:
            self.wf_by_task.pop(self.workflows.pop(k).get("task_id"), None)

    def forget_workflow(self, run_id: str) -> None:
        wf = self.workflows.pop(run_id, None)
        task_id = (wf or {}).get("task_id")
        if task_id:
            self.wf_by_task.pop(task_id, None)
            self.notifs.pop(task_id, None)
            self.stops.pop(task_id, None)

    def forget_bg(self, task_id: str) -> None:
        self.bg.pop(task_id, None)
        self.notifs.pop(task_id, None)
        self.stops.pop(task_id, None)

    def forget_agent(self, agent_id: str, tool_use_id: object) -> None:
        self.notifs.pop(agent_id, None)
        self.stops.pop(agent_id, None)
        if isinstance(tool_use_id, str):
            self.agent_calls.pop(tool_use_id, None)

    def add_notification(self, n: dict, ts_ms: int | None) -> None:
        tid = n["task_id"]
        prev = self.notifs.get(tid)
        ts = ts_ms or 0
        if n["is_event"]:
            # Monitor events update activity without marking completion.
            if tid.startswith("b"):
                rec = self.bg.get(tid)
                if rec is not None:
                    rec["kind"] = "monitor"
                    rec["last_event_ms"] = max(rec.get("last_event_ms") or 0, ts)
            return
        if prev is None or ts >= prev["ts_ms"]:
            self.notifs[tid] = dict(n, ts_ms=ts)
            _trim(self.notifs, NOTIFS_MAX)
        if n["status"] or n["orphan_notice"]:
            self.settle_bg(tid, final=dict(n, ts_ms=ts))
            if n["monitor"] and tid in self.bg:
                self.bg[tid]["kind"] = "monitor"  # Preserve the kind even in closed sessions whose launch record cannot be read.
        if n["status"]:
            wf = self.workflows.get(self.wf_by_task.get(tid))
            if wf is not None:
                wf["terminal"] = True
                wf["final"] = dict(n, ts_ms=ts)  # Keep run state when notification indexes evict entries.

    def settle_bg(self, tid: str, final: dict | None = None, stop_ms: int | None = None) -> None:
        """Copy completion into background records so FIFO eviction cannot revive completed jobs. Tail completion can precede backfilled launch records; reserve a slot for bg_start to inherit."""
        rec = self.bg.get(tid)
        if rec is None:
            if not tid.startswith("b") or not BG_ID_RE.fullmatch(tid):
                return
            rec = self.bg[tid] = _new_bg(tid)
        if final is not None and (rec.get("final") is None or final["ts_ms"] >= rec["final"]["ts_ms"]):
            rec["final"] = final
        if stop_ms is not None:
            rec["stop_ms"] = max(rec.get("stop_ms") or 0, stop_ms)

    def bg_start(self, task_id, owner, ts_ms, auto, kind, hint, expires_ms=None) -> None:
        rec = self.bg.get(task_id)
        if rec is None:
            rec = self.bg[task_id] = _new_bg(task_id, kind, owner, ts_ms, True, auto)
            # IDs not starting with b have no reserved slot; copy any indexed completion here.
            nt = self.notifs.get(task_id)
            if nt is not None and (nt.get("status") or nt.get("orphan_notice")):
                rec["final"] = nt
            if task_id in self.stops:
                rec["stop_ms"] = self.stops[task_id]
        else:
            rec["start_seen"] = True
            rec["owner"] = owner
            rec["auto_backgrounded"] = rec["auto_backgrounded"] or auto
            if rec.get("started_ms") is None or (ts_ms and ts_ms < rec["started_ms"]):
                rec["started_ms"] = ts_ms
        if kind == "monitor":
            rec["kind"] = "monitor"
        if expires_ms:
            rec["expires_ms"] = expires_ms
        if hint:
            if hint.get("kind") == "monitor":
                rec["kind"] = "monitor"
            if hint.get("description") and not rec.get("description"):
                rec["description"] = hint["description"]

    def remember_hint(self, tool_use_id: str, kind: str, description: str | None) -> None:
        self.hints[tool_use_id] = {"kind": kind, "description": description}
        _trim(self.hints, HINTS_MAX)


def index_user_tool_result(rec: dict, block: dict, idx: SessionIndex, owner: str | None, ts_ms: int | None, text: str | None = None) -> None:
    """Extract background launches, TaskStop, and agent/workflow launches from user tool_result blocks."""
    tid = block.get("tool_use_id")
    tur = rec.get("toolUseResult")
    tur = tur if isinstance(tur, dict) else None
    hint = idx.hints.pop(tid, None) if isinstance(tid, str) else None
    bg_id = None
    auto = False
    monitor = False
    expires_ms = None
    if tur is not None and isinstance(tur.get("backgroundTaskId"), str):
        bg_id = tur["backgroundTaskId"]
        auto = bool(tur.get("timedOutAfterMs") or tur.get("backgroundedByUser"))
    if text is None:
        text = _block_text(block)
    if bg_id is None and text:
        m = _BG_START_RE.match(text)
        if m:
            bg_id = m.group(1)
        else:
            m = _BG_MOVED_RE.match(text)
            if m:
                bg_id = m.group(1)
                auto = True
            else:
                m = _MON_START_RE.match(text)
                if m:
                    bg_id = m.group(1)
                    monitor = True
                    expires_ms = _monitor_expiry(m, tur, ts_ms)
    if bg_id and BG_ID_RE.fullmatch(bg_id):
        kind = "monitor" if monitor else ((hint or {}).get("kind") or "bash")
        idx.bg_start(bg_id, owner, ts_ms, auto, kind, hint, expires_ms)
    stop_id = None
    if tur is not None and isinstance(tur.get("task_id"), str) and "task_type" in tur:
        stop_id = tur["task_id"]
    elif text:
        m = _STOP_RE.match(text)
        if m:
            stop_id = m.group(1)
    if stop_id:
        prev = idx.stops.get(stop_id)
        if prev is None or (ts_ms or 0) > prev:
            idx.stops[stop_id] = ts_ms or 0
            _trim(idx.stops, STOPS_MAX)
            idx.settle_bg(stop_id, stop_ms=ts_ms or 0)
    if tur is not None:
        if tur.get("taskType") == "local_workflow" or (isinstance(tur.get("runId"), str) and tur["runId"].startswith("wf_")):
            run_id = tur.get("runId")
            if isinstance(run_id, str):
                wf = idx.workflow(run_id, owner, ts_ms)
                if isinstance(tur.get("taskId"), str):
                    wf["task_id"] = tur["taskId"]
                    idx.wf_by_task[tur["taskId"]] = run_id
                    nt = idx.notifs.get(tur["taskId"])
                    if nt is not None and nt.get("status"):
                        wf["terminal"] = True
                        wf["final"] = nt
                name = tur.get("workflowName")
                if isinstance(name, str) and name:
                    wf["name"] = field(name, 60, first_line=True)
        agent_id = tur.get("agentId")
        if isinstance(agent_id, str) and isinstance(tid, str):
            call = idx.call(tid, ts_ms)
            call["agent_id"] = agent_id
            call["resolved"] = True
            call["resolved_ms"] = ts_ms
            if tur.get("isAsync") or tur.get("status") == "async_launched":
                call["async"] = True
            elif tur.get("status") is not None:
                call["sync_status"] = tur.get("status")
                call["sync_tokens"] = tur.get("totalTokens")
                call["sync_tools"] = tur.get("totalToolUseCount")
                call["sync_duration_ms"] = tur.get("totalDurationMs")
    if isinstance(tid, str):
        call = idx.agent_calls.get(tid)
        if call is not None and not call["resolved"]:
            call["resolved"] = True
            call["resolved_ms"] = ts_ms


def _monitor_expiry(m: re.Match, tur: dict | None, ts_ms: int | None) -> int | None:
    """Monitor expiry time; persistent monitors do not expire."""
    if ts_ms is None or (tur is not None and tur.get("persistent") is True):
        return None
    if m.group(2) is not None:
        return ts_ms + int(m.group(2)) * _UNIT_MS[m.group(3)]
    ms = tur.get("timeoutMs") if tur is not None else None
    return ts_ms + ms if isinstance(ms, int) and not isinstance(ms, bool) and ms > 0 else None


def _new_call(tool_use_id: str, ts_ms: int | None) -> dict:
    return {
        "tool_use_id": tool_use_id, "agent_id": None, "async": False, "resolved": False,
        "resolved_ms": None, "sync_status": None, "sync_tokens": None, "sync_tools": None,
        "sync_duration_ms": None, "ts_ms": ts_ms,
    }


def index_notification_record(rec: dict, idx: SessionIndex, ts_ms: int | None) -> list[dict]:
    """Validate and parse the three notification locations, excluding tool inputs and assistant text."""
    t = rec.get("type")
    text = None
    if t == "user":
        origin = rec.get("origin")
        if isinstance(origin, dict) and origin.get("kind") == "task-notification":
            text = _user_text((rec.get("message") or {}).get("content"))
    elif t == "queue-operation":
        c = rec.get("content")
        if isinstance(c, str) and c.lstrip().startswith(NOTIF_OPEN):
            text = c
    elif t == "attachment":
        a = rec.get("attachment")
        if isinstance(a, dict) and a.get("type") == "queued_command":
            p = a.get("prompt")
            if isinstance(p, str) and p.lstrip().startswith(NOTIF_OPEN):
                text = p
                ts_ms = parse_ts(a.get("timestamp")) or ts_ms
    if text is None:
        return []
    found = parse_notifications(text)
    for n in found:
        idx.add_notification(n, ts_ms)
    return found


def _notification_arg(found: list[dict]) -> str | None:
    """For detail views, retain only status and exit code."""
    if not found:
        return None
    n = found[-1]
    label = normalize_outcome(n["status"]) if n["status"] else "event"
    if n["exit_code"] is not None:
        label += f" (exit {n['exit_code']})"
    return f"{safe_text(n['task_id'], 12)} {label}"


def index_record(rec: dict, idx: SessionIndex, owner: str | None, pos: int = 0) -> None:
    """Backfill only: apply records with markers to the session index. pos ends the read range containing this line."""
    t = rec.get("type")
    ts_ms = parse_ts(rec.get("timestamp"))
    if t == "user":
        if index_notification_record(rec, idx, ts_ms):
            return
        content = (rec.get("message") or {}).get("content")
        if isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    index_user_tool_result(rec, b, idx, owner, ts_ms)
    elif t in ("queue-operation", "attachment"):
        index_notification_record(rec, idx, ts_ms)
    elif t in ("custom-title", "ai-title"):
        if owner is None:
            v = rec.get("customTitle" if t == "custom-title" else "aiTitle")
            if isinstance(v, str) and v.strip():
                idx.set_title("custom" if t == "custom-title" else "ai", field(v, 80, first_line=True), pos)
    elif t == "assistant":
        content = (rec.get("message") or {}).get("content")
        if isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_use":
                    _hint_from_tool_use(b, idx)


def _hint_from_tool_use(block: dict, idx: SessionIndex) -> None:
    name = block.get("name")
    if name in ("Bash", "PowerShell", "Monitor"):
        tid = block.get("id")
        if isinstance(tid, str):
            idx.remember_hint(tid, "monitor" if name == "Monitor" else "bash", _bg_description(name, block.get("input")))


def _bg_description(name: str, inp: object) -> str | None:
    arg = summarize_tool_input(name, inp)
    return arg[5:] if arg and arg.startswith("[bg] ") else arg


class TranscriptState:
    """Incremental state machine for one file."""

    __slots__ = (
        "owner", "idx", "pending", "cur_mid", "usage", "last_ctx", "sum_out", "tool_ids",
        "first_ts", "last_ts", "last_au_ms", "last_text", "last_tool", "events", "title_custom", "title_ai",
        "model", "effort", "has_assistant", "last_step", "cwd", "notif_seen",
    )

    def __init__(self, owner: str | None, idx: SessionIndex):
        self.owner = owner  # None = main thread.
        self.idx = idx
        self.pending: OrderedDict[str, dict] = OrderedDict()
        self.cur_mid: str | None = None
        self.usage: OrderedDict[str, dict] = OrderedDict()
        self.last_ctx: int | None = None
        self.sum_out = 0
        # Resume or compaction may repeat IDs. Share the backfill set to count unique IDs.
        self.tool_ids = ToolIds()
        self.first_ts: int | None = None
        self.last_ts: int | None = None
        self.last_au_ms: int | None = None  # Last assistant/user timestamp, used to detect resumption.
        self.last_text: str | None = None
        self.last_tool: dict | None = None
        self.events = EventLog(EVENTS_PER_AGENT)
        self.title_custom: str | None = None
        self.title_ai: str | None = None
        self.model: str | None = None
        self.effort: str | None = None
        self.has_assistant = False
        self.last_step: dict = {"kind": "unknown", "since_ms": None}
        self.cwd: str | None = None
        self.notif_seen: deque = deque(maxlen=8)  # Notifications may repeat in queue, attachment, and user records.

    # ---- Public queries ----
    @property
    def tool_calls_seen(self) -> int:
        return len(self.tool_ids)

    def step(self) -> dict:
        if self.pending:
            vals = list(self.pending.values())
            last = vals[-1]
            return {
                "kind": "tool", "tool": last["name"], "arg": last["arg"], "since_ms": last["ts_ms"],
                "parallel": len(vals) - 1, "timeout_ms": last["timeout_ms"],
            }
        s = {"tool": None, "arg": None, "parallel": 0, "timeout_ms": None}
        s.update(self.last_step)
        return s

    @property
    def turn_ended(self) -> bool:
        return not self.pending and self.last_step.get("kind") == "turn_end"

    # ---- Record ingestion ----
    def feed(self, rec: dict) -> None:
        t = rec.get("type")
        ts = parse_ts(rec.get("timestamp"))
        if ts is not None:
            if self.first_ts is None or ts < self.first_ts:
                self.first_ts = ts
            if self.last_ts is None or ts > self.last_ts:
                self.last_ts = ts
        cwd = rec.get("cwd")
        if isinstance(cwd, str) and cwd:
            self.cwd = cwd
        if t == "assistant":
            self._assistant(rec, ts)
        elif t == "user":
            self._user(rec, ts)
        elif t == "system":
            self._system(rec, ts)
        elif t == "api-request":
            if not self.pending:
                self._set_step("model_wait", ts)
                self.events.append(_ev(ts, "model_wait"))
        elif t == "ai-title":
            v = rec.get("aiTitle")
            if isinstance(v, str) and v.strip():
                self.title_ai = field(v, 80, first_line=True)
        elif t == "custom-title":
            v = rec.get("customTitle")
            if isinstance(v, str) and v.strip():
                self.title_custom = field(v, 80, first_line=True)
        elif t in ("queue-operation", "attachment"):
            found = index_notification_record(rec, self.idx, ts)
            if found:
                self._notification_event(ts, found)

    def _notification_event(self, ts: int | None, found: list[dict]) -> None:
        key = tuple((n["task_id"], n["status"]) for n in found if not n["is_event"])
        if key and key in self.notif_seen:
            return
        if key:
            self.notif_seen.append(key)
        self.events.append(_ev(ts, "notification", arg=_notification_arg(found)))

    def _set_step(self, kind: str, ts: int | None, **extra) -> None:
        d = {"kind": kind, "since_ms": ts}
        d.update(extra)
        self.last_step = d

    def _assistant(self, rec: dict, ts: int | None) -> None:
        self.has_assistant = True
        if ts is not None:
            self.last_au_ms = max(self.last_au_ms or 0, ts)
        msg = rec.get("message")
        if not isinstance(msg, dict):
            return
        mid = msg.get("id")
        if isinstance(mid, str) and mid != self.cur_mid:
            # Clear unmatched tool_use entries when a new message starts.
            self.pending.clear()
            self.cur_mid = mid
        model = msg.get("model")
        if isinstance(model, str) and model and model != "<synthetic>":
            self.model = model
        effort = rec.get("effort")
        if isinstance(effort, str):
            self.effort = effort
        self._usage(mid, msg.get("usage"))
        last_kind = None
        content = msg.get("content")
        if isinstance(content, list):
            for b in content:
                if not isinstance(b, dict):
                    continue
                bt = b.get("type")
                if bt == "tool_use":
                    self._tool_use(b, ts)
                    last_kind = "tool"
                elif bt == "text":
                    text = b.get("text")
                    if isinstance(text, str) and text.strip():
                        self.last_text = PRIVATE if is_denied(text) else safe_text(text, 120)
                        self.events.append(_ev(ts, "text", text=PRIVATE if is_denied(text) else safe_text(text, 200)))
                        last_kind = "text"
                elif bt == "thinking":
                    last_kind = "thinking"
        stop = msg.get("stop_reason")
        if stop in (None, ""):
            if not self.pending:
                if last_kind == "thinking":
                    self._set_step("thinking", ts)
                elif last_kind == "text":
                    self._set_step("writing", ts)
        elif stop != "tool_use":
            # Every stop reason except tool_use ends the turn, including end_turn, refusal, stop_sequence, and max_tokens.
            self.pending.clear()
            self._set_step("turn_end", ts, stop_reason=_short_enum(stop))
            self.events.append(_ev(ts, "turn_end"))

    def _usage(self, mid: object, u: object) -> None:
        if not isinstance(mid, str) or not isinstance(u, dict):
            return
        try:
            out = int(u.get("output_tokens") or 0)
            ctx = (
                int(u.get("input_tokens") or 0)
                + int(u.get("cache_creation_input_tokens") or 0)
                + int(u.get("cache_read_input_tokens") or 0)
                + out
            )
        except (TypeError, ValueError):
            return
        has_iter = bool(u.get("iterations"))
        prev = self.usage.get(mid)
        if prev is None:
            self.usage[mid] = {"out": out, "ctx": ctx, "iter": has_iter}
            self.sum_out += out
            while len(self.usage) > MSG_USAGE_KEEP:
                self.usage.popitem(last=False)
        elif out > prev["out"] or (out == prev["out"] and has_iter and not prev["iter"]):
            self.sum_out += out - prev["out"]
            prev.update(out=out, ctx=ctx, iter=has_iter)
        self.last_ctx = self.usage[mid]["ctx"]

    def _tool_use(self, b: dict, ts: int | None) -> None:
        tid = b.get("id")
        name = b.get("name")
        if not isinstance(tid, str) or not isinstance(name, str):
            return
        inp = b.get("input")
        arg = summarize_tool_input(name, inp)
        timeout = None
        if isinstance(inp, dict) and isinstance(inp.get("timeout"), (int, float)) and not isinstance(inp.get("timeout"), bool):
            timeout = int(inp["timeout"])
        safe_name = safe_text(name, 60)
        self.pending[tid] = {"name": safe_name, "arg": arg, "ts_ms": ts, "timeout_ms": timeout}
        while len(self.pending) > PENDING_TOOLS_MAX:
            self.pending.popitem(last=False)
        self.tool_ids.add(tid.encode("utf-8", "replace"))
        self.last_tool = {"name": safe_name, "arg": arg, "ok": None, "ts_ms": ts, "id": tid}
        self.events.append(_ev(ts, "tool_call", tool=safe_name, arg=arg))
        if name in ("Bash", "PowerShell", "Monitor"):
            self.idx.remember_hint(tid, "monitor" if name == "Monitor" else "bash", _bg_description(name, inp))
        elif name in ("Agent", "Task", "Workflow"):
            self.idx.relist = True
            if name != "Workflow":
                call = self.idx.call(tid, ts)
                if isinstance(inp, dict) and inp.get("run_in_background"):
                    call["async"] = True

    def _user(self, rec: dict, ts: int | None) -> None:
        if ts is not None:
            self.last_au_ms = max(self.last_au_ms or 0, ts)
        msg = rec.get("message")
        content = msg.get("content") if isinstance(msg, dict) else None
        results = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"] if isinstance(content, list) else []
        if not results:
            # A user record without tool_result is a prompt regardless of origin.kind.
            found = index_notification_record(rec, self.idx, ts)
            self.pending.clear()
            self._set_step("prompt", ts)
            if found:
                self._notification_event(ts, found)
            else:
                self.events.append(_ev(ts, "prompt"))
            return
        for b in results:
            tid = b.get("tool_use_id")
            ok = not bool(b.get("is_error"))
            p = self.pending.pop(tid, None) if isinstance(tid, str) else None
            if self.last_tool is not None and self.last_tool.get("id") == tid:
                self.last_tool["ok"] = ok
            self.events.append(_ev(ts, "tool_result", tool=p["name"] if p else None, ok=ok))
            index_user_tool_result(rec, b, self.idx, self.owner, ts)
        if rec.get("toolEndsTurn"):
            self.pending.clear()
            self._set_step("turn_end", ts, stop_reason="tool_ends_turn")
            self.events.append(_ev(ts, "turn_end"))
        elif not self.pending:
            self._set_step("model_wait", ts)

    def _system(self, rec: dict, ts: int | None) -> None:
        sub = rec.get("subtype")
        if sub == "api_error":
            attempt = rec.get("retryAttempt")
            maxr = rec.get("maxRetries")
            self._set_step("retry", ts, attempt=attempt if isinstance(attempt, int) else None, max=maxr if isinstance(maxr, int) else None)
            self.events.append(_ev(ts, "retry"))
        elif sub == "stop_hook_summary":
            if not self.pending:
                self._set_step("turn_end", ts, stop_reason=self.last_step.get("stop_reason"))
        elif sub == "compact_boundary":
            self._set_step("compact", ts)
            self.events.append(_ev(ts, "compact"))


def _short_enum(v: object) -> str:
    return safe_text(v, 32) if isinstance(v, str) else "other"


def _ev(ts, kind, tool=None, arg=None, ok=None, text=None) -> dict:
    return {"ts_ms": ts, "kind": kind, "tool": tool, "arg": arg, "ok": ok, "text": text}


def is_blob_line(line: bytes) -> bool:
    return b"api-request-blob" in line[:120]


def loads_line(line: bytes) -> dict | None:
    try:
        rec = json.loads(line.decode("utf-8", "replace"))
    except ValueError:
        return None
    return rec if isinstance(rec, dict) else None


def scan_backfill_line(line: bytes, idx: SessionIndex, owner: str | None, ids: set | ToolIds | None = None, pos: int = 0) -> int:
    """Process one backfill line and return new tool calls. With ids, count only unseen IDs. Skip JSON parsing for lines without markers."""
    if is_blob_line(line):
        return 0
    n = 0
    if TOOL_USE_PATTERN in line:
        found = TOOL_ID_RE.findall(line)
        if ids is None:
            n = len(found)
        else:
            before = len(ids)
            ids.update(found)
            n = len(ids) - before
    for m in MARKERS:
        if m in line:
            rec = loads_line(line)
            if rec is not None:
                index_record(rec, idx, owner, pos)
            break
    return n


def extract_title_pos(data: bytes) -> dict[str, tuple[str | None, int]]:
    """Find the latest title of each kind and its offset in the file head."""
    found: dict[str, tuple[str | None, int]] = {}
    pos = 0
    for line in data.split(b"\n"):
        start = pos
        pos += len(line) + 1
        if b"-title" not in line[:64]:
            continue
        rec = loads_line(line)
        if not rec:
            continue
        if rec.get("type") == "custom-title" and isinstance(rec.get("customTitle"), str):
            found["custom"] = (field(rec["customTitle"], 80, first_line=True), start)
        elif rec.get("type") == "ai-title" and isinstance(rec.get("aiTitle"), str):
            found["ai"] = (field(rec["aiTitle"], 80, first_line=True), start)
    return found


def extract_title(data: bytes) -> tuple[str | None, str | None]:
    found = extract_title_pos(data)
    return found.get("custom", (None, 0))[0], found.get("ai", (None, 0))[0]
