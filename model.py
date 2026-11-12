"""Assemble view dictionaries, propagate privacy, and serialize JSON. Collectors own internal records; this module handles display contracts."""
from __future__ import annotations

import hashlib
import json
import re
from collections import deque

from config import (
    STATE_AGENTS_SHRUNK,
    STATE_BG_SHRUNK,
    STATE_CODEX_SHRUNK,
    STATE_JSON_MAX,
    STATE_SHRINK_STEPS,
)
from masking import PRIVATE, is_denied


class EventLog(deque):
    """Detail-event ring buffer. Use seq to reuse snapshots when nothing changes."""

    def __init__(self, maxlen: int):
        super().__init__(maxlen=maxlen)
        self.seq = 0

    def append(self, item) -> None:
        self.seq += 1
        super().append(item)


def event_snapshot(holder, events: EventLog, force: bool) -> tuple:
    """Immutable copy using privacy at publication time; holder has ev_key and ev_snap attributes."""
    key = (events.seq, force)
    if holder.ev_key != key:
        holder.ev_key = key
        holder.ev_snap = tuple(redact_events(events, force))
    return holder.ev_snap


def private_if(v):
    return PRIVATE if v else v


def redact_step(step: dict | None) -> None:
    if step and step.get("arg"):
        step["arg"] = PRIVATE


def redact_agent_view(v: dict, force: bool = False) -> None:
    """A match in description, label, or phase hides the entire agent."""
    hit = force or is_denied(v.get("description")) or is_denied(v.get("phase"))
    if not hit:
        return
    v["private"] = True
    v["description"] = private_if(v.get("description"))
    v["phase"] = private_if(v.get("phase"))
    v["last_text"] = private_if(v.get("last_text"))
    redact_step(v.get("step"))
    lt = v.get("last_tool")
    if lt and lt.get("arg"):
        lt["arg"] = PRIVATE


def redact_workflow_view(w: dict, force: bool = False) -> None:
    hit = force or is_denied(w.get("name"))
    if hit:
        w["name"] = private_if(w.get("name"))
        w["private"] = True
    for p in w.get("phases") or []:
        if hit or is_denied(p.get("title")):
            p["title"] = private_if(p.get("title"))
    for a in w.get("agents") or []:
        redact_agent_view(a, force=hit)


def redact_bg_view(b: dict, force: bool = False) -> None:
    if force or is_denied(b.get("description")):
        b["description"] = private_if(b.get("description"))
    if force or is_denied(b.get("owner_label")):
        b["owner_label"] = private_if(b.get("owner_label"))


def redact_session_view(s: dict, bg_views: list[dict], private_owners: frozenset | set = frozenset()) -> None:
    """A session title or path match hides all session text. Compute private_owners from all ownership records before filtering and caps, never from truncated views."""
    hit = bool(s.get("title_hidden")) or is_denied(s.get("title")) or is_denied(s.get("cwd_display"))
    if is_denied(s.get("project_name")) or is_denied(s.get("cwd_display")):
        hit = True
        s["project_name"] = PRIVATE
    if hit:
        s["title_hidden"] = True
        s["title"] = PRIVATE
        s["project_name"] = PRIVATE
        s["cwd_display"] = private_if(s.get("cwd_display"))
    redact_agent_view(s["main"], force=hit)
    for a in s.get("agents") or []:
        redact_agent_view(a, force=hit or a.get("agent_id") in private_owners)
    for w in s.get("workflows") or []:
        redact_workflow_view(w, force=hit)
        for a in w.get("agents") or []:
            if a.get("agent_id") in private_owners:
                redact_agent_view(a, force=True)
    # Private agents or workflows also hide descriptions of their background jobs.
    for b in bg_views:
        force = hit or bool(b.get("private")) or b.get("owner_agent_id") in private_owners
        b["private"] = force
        redact_bg_view(b, force=force)


def redact_codex_view(r: dict) -> None:
    """A task-folder or cwd match hides the entire run."""
    hit = is_denied(r.get("packet")) or is_denied(r.get("cwd_display"))
    lc = r.get("last_command")
    if hit:
        r["private"] = True
        r["packet"] = private_if(r.get("packet"))
        r["cwd_display"] = private_if(r.get("cwd_display"))
        r["last_message"] = private_if(r.get("last_message"))
        if lc and lc.get("text"):
            lc["text"] = PRIVATE
    elif lc and is_denied(lc.get("text")):
        lc["text"] = PRIVATE


def redact_events(events, force: bool) -> list[dict]:
    out = []
    for e in events:
        e = dict(e)
        e.pop("id", None)
        if force:
            if e.get("arg"):
                e["arg"] = PRIVATE
            if e.get("text"):
                e["text"] = PRIVATE
        else:
            if is_denied(e.get("arg")):
                e["arg"] = PRIVATE
            if is_denied(e.get("text")):
                e["text"] = PRIVATE
        out.append(e)
    return out


# Exclude values that change every tick from the content hash.
_VOLATILE_RE = re.compile(rb'"(?:now_ms|elapsed_ms|state_version|rss_mb)":\s*-?[0-9.]+')


def dumps(obj: dict) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "replace")


def content_hash(body: bytes) -> str:
    return hashlib.blake2b(_VOLATILE_RE.sub(b"", body), digest_size=16).hexdigest()


def _count_omitted(state: dict, key: str, n: int, holder: dict | None = None, field_: str | None = None) -> None:
    """Record omissions globally and locally; the UI uses these counts for additional-item labels."""
    if n <= 0:
        return
    server = state.setdefault("server", {})
    server["truncated"] = True
    omitted = server.setdefault("omitted", {})
    omitted[key] = omitted.get(key, 0) + n
    if holder is not None and field_:
        holder[field_] = holder.get(field_, 0) + n


def _keep(state: dict, holder: dict, key: str, rows: list, label: str, field_: str) -> bool:
    n = len(holder.get(key, [])) - len(rows)
    if n <= 0:
        return False
    holder[key] = rows
    _count_omitted(state, label, n, holder, field_)
    return True


def note_caps(state: dict, hot_deferred: int = 0, codex_cut: int = 0) -> None:
    """Add display-cap omissions to global totals; the UI reads server.omitted."""
    for s in state.get("sessions", []):
        _count_omitted(state, "agents", s.get("agents_omitted", 0))
        for w in s.get("workflows", []):
            _count_omitted(state, "workflow_agents", w.get("agents_omitted", 0))
    _count_omitted(state, "codex", codex_cut, state, "codex_omitted")
    _count_omitted(state, "hot_files", hot_deferred)


def shrink_for_size(state: dict) -> bool:
    """Remove finished items first above STATE_JSON_MAX; return True if reduced."""
    changed = False
    for s in state.get("sessions", []):
        changed |= _keep(state, s, "agents", [a for a in s.get("agents", []) if a.get("status") != "finished"], "agents", "agents_omitted")
        changed |= _keep(state, s, "workflows", [w for w in s.get("workflows", []) if w.get("status") != "finished"], "workflows", "workflows_omitted")
    changed |= _keep(state, state, "bg_tasks", [b for b in state.get("bg_tasks", []) if b.get("status") != "finished"], "bg", "bg_omitted")
    changed |= _keep(state, state, "codex_runs", [r for r in state.get("codex_runs", []) if r.get("status") != "finished"], "codex", "codex_omitted")
    return changed


def shrink_active(
    state: dict, agents: int = STATE_AGENTS_SHRUNK, bg: int = STATE_BG_SHRUNK, codex: int = STATE_CODEX_SHRUNK
) -> bool:
    """If still oversized, truncate active items, retaining their existing priority order."""
    changed = False
    for s in state.get("sessions", []):
        changed |= _keep(state, s, "agents", s.get("agents", [])[:agents], "agents", "agents_omitted")
        for w in s.get("workflows", []):
            changed |= _keep(state, w, "agents", w.get("agents", [])[:agents], "workflow_agents", "agents_omitted")
    rows = state.get("bg_tasks", [])
    if len(rows) > bg:
        ordered = sorted(rows, key=lambda b: b.get("status") not in ("running", "waiting"))
        changed |= _keep(state, state, "bg_tasks", ordered[:bg], "bg", "bg_omitted")
    changed |= _keep(state, state, "codex_runs", state.get("codex_runs", [])[:codex], "codex", "codex_omitted")
    return changed


def drop_sessions(state: dict, limit: int) -> None:
    """Last resort: remove entire sessions from the end of the priority list. Keep full counts."""
    sessions = state.get("sessions", [])
    used = len(dumps(dict(state, sessions=[], projects=[])))
    project_of = {sid: p for p in state.get("projects", []) for sid in p.get("session_ids", [])}
    counted: set[int] = set()
    kept = []
    for s in sessions:
        # Measure project rows at first use; later ID removal can only shrink them.
        p = project_of.get(s.get("id"))
        n = len(dumps(s)) + 1 + (len(dumps(p)) + 1 if p is not None and id(p) not in counted else 0)
        if used + n <= limit:
            kept.append(s)
            used += n
            counted.add(id(p))
    _count_omitted(state, "sessions", len(sessions) - len(kept), state, "sessions_omitted")
    state["sessions"] = kept
    ids = {s.get("id") for s in kept}
    projects = []
    for p in state.get("projects", []):
        p["session_ids"] = [i for i in p.get("session_ids", []) if i in ids]
        if p["session_ids"]:
            projects.append(p)
    state["projects"] = projects


def finalize_json(state: dict) -> bytes:
    """Fit the body within the cap, reserving space for state_version substitution. The minimum state always fits."""
    limit = STATE_JSON_MAX - 64
    body = dumps(state)
    if len(body) <= limit:
        return body
    state["server"]["truncated"] = True
    if shrink_for_size(state):
        body = dumps(state)
    for step in STATE_SHRINK_STEPS:
        if len(body) <= limit:
            return body
        if shrink_active(state, *step):
            body = dumps(state)
    if len(body) > limit:
        drop_sessions(state, limit)
        body = dumps(state)
    return body


def reachable_only(state: dict, index: dict, codex_index: dict) -> tuple[dict, dict]:
    """Items omitted for size must also be inaccessible through detail APIs."""
    keep = set()
    for s in state.get("sessions", []):
        keep.add((s.get("id"), "main"))
        keep.update((s.get("id"), a.get("agent_id")) for a in s.get("agents", []))
        for w in s.get("workflows", []):
            keep.update((s.get("id"), a.get("agent_id")) for a in w.get("agents", []))
    threads = {r.get("thread_id") for r in state.get("codex_runs", [])}
    return {k: v for k, v in index.items() if k in keep}, {k: v for k, v in codex_index.items() if k in threads}
