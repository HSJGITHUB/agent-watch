"""Background task inventory and marker backfill. Inspect only output filenames, sizes, and mtimes; never read their contents."""
from __future__ import annotations

import heapq
import os
from collections import deque

from claude_parse import SessionIndex, scan_backfill_line
from config import BACKFILL_MAX_FILE, BACKFILL_TICK_CAP, BG_PER_SESSION_MAX, BG_STAT_PER_TICK, FINISHED_KEEP_S, ORPHAN_QUIET_S, STALE_KEEP_S
from masking import field
from status import FINISHED, ORPHANED, RUNNING, WAITING, bg_gone, bg_status
from tailreader import RangeScanner

OUTPUT_SUFFIX = ".output"


def scan_tasks_dir(tasks_dir, idx: SessionIndex, now_ms: int) -> int:
    """Scan task folders to a fixed depth and inventory b* jobs."""
    n = 0
    seen: set[str] = set()
    try:
        it = os.scandir(tasks_dir)
    except OSError:
        return 0
    with it:
        for e in it:
            name = e.name
            if not name.startswith("b") or not name.endswith(OUTPUT_SUFFIX):
                continue
            tid = name[: -len(OUTPUT_SUFFIX)]
            seen.add(tid)
            try:
                st = e.stat()
            except OSError:
                continue
            mt = st.st_mtime_ns // 1_000_000
            rec = idx.bg.get(tid)
            if rec is None:
                # Exclude outputs older than 24 hours without a launch record.
                if (now_ms - mt) / 1000 > STALE_KEEP_S or len(idx.bg) >= BG_PER_SESSION_MAX:
                    continue
                rec = {
                    "task_id": tid, "kind": "bash", "owner": None, "description": None,
                    "started_ms": None, "start_seen": False, "auto_backgrounded": False,
                    "output_bytes": None, "output_mtime_ms": None, "last_event_ms": None,
                }
                idx.bg[tid] = rec
            rec["output_bytes"] = st.st_size
            rec["output_mtime_ms"] = mt
            rec["output_missing"] = False
            rec["scans"] = rec.get("scans", 0) + 1
            n += 1
    # Foreground Bash outputs can briefly exist without launch records; drop rows when their files disappear.
    # Keep completed placeholders for launch records discovered later.
    for tid in [t for t, r in idx.bg.items() if not r.get("start_seen") and t not in seen and not _closed(r)]:
        idx.bg.pop(tid, None)
    return n


def _closed(rec: dict) -> bool:
    """Check completion from notifications or TaskStop. Ingest copies it into records, independent of FIFO indexes."""
    return rec.get("final") is not None or rec.get("stop_ms") is not None


def _persistent_idle(rec: dict, now_ms: int) -> bool:
    """Check whether a persistent Monitor has been quiet beyond ORPHAN_QUIET_S; such jobs do not prevent owner completion."""
    if rec.get("kind") != "monitor" or rec.get("expires_ms"):
        return False
    last = max(rec.get("last_event_ms") or 0, rec.get("output_mtime_ms") or 0, rec.get("started_ms") or 0)
    return (now_ms - last) / 1000 > ORPHAN_QUIET_S


def stat_open_tasks(tasks_dir, idx: SessionIndex) -> None:
    """Refresh only output size and mtime for open jobs. Inspect BG_STAT_PER_TICK least-recently-seen entries per tick: ceil(N/64) ticks, at most eight with the 500-job cap."""
    if tasks_dir is None:
        return
    todo = [(tid, rec) for tid, rec in idx.bg.items() if rec.get("start_seen") and not _closed(rec)]
    if len(todo) > BG_STAT_PER_TICK:
        todo = heapq.nsmallest(BG_STAT_PER_TICK, todo, key=lambda p: p[1].get("stat_seq", 0))
    idx.stat_seq += 1
    for tid, rec in todo:
        rec["stat_seq"] = idx.stat_seq
        try:
            st = os.stat(os.path.join(tasks_dir, tid + OUTPUT_SUFFIX))
        except FileNotFoundError:
            rec["output_missing"] = True
            continue
        except OSError:
            continue
        rec["output_missing"] = False
        rec["output_bytes"] = st.st_size
        rec["output_mtime_ms"] = st.st_mtime_ns // 1_000_000


def _gone(rec: dict, process_started_ms: int | None, now_ms: int) -> str | None:
    return bg_gone(
        started_ms=rec.get("started_ms"), process_started_ms=process_started_ms, expires_ms=rec.get("expires_ms"),
        output_mtime_ms=rec.get("output_mtime_ms"), output_missing=bool(rec.get("output_missing")), now_ms=now_ms,
    )


def bg_open_by_owner(idx: SessionIndex, process_started_ms: int | None = None, now_ms: int = 0) -> dict:
    """Count open jobs by owner, excluding owner completion rules to avoid cycles."""
    out: dict = {}
    for rec in idx.bg.values():
        if not rec.get("start_seen") or _closed(rec):
            continue
        if _gone(rec, process_started_ms, now_ms) or _persistent_idle(rec, now_ms):
            continue
        owner = rec.get("owner")
        out[owner] = out.get(owner, 0) + 1
    return out


def build_bg_views(session, owner_info, now_ms: int, process_started_ms: int | None = None) -> tuple[list[dict], int]:
    """Build display rows and active counts from SessionRec and owner_info(agent_id): finished, label, private."""
    idx: SessionIndex = session.idx
    rows: list[dict] = []
    running = 0
    drop: list[str] = []
    open_ids: set[str] = set()
    for tid, rec in idx.bg.items():
        # Rows without launch records need content and two consecutive discoveries.
        if not rec.get("start_seen") and (rec.get("scans", 0) < 2 or not rec.get("output_bytes")):
            continue
        nt = rec.get("final")
        stop_ms = rec.get("stop_ms")
        owner = rec.get("owner")
        owner_finished, owner_label, owner_private = owner_info(owner)
        v = bg_status(
            notification=nt,
            stop_ms=stop_ms,
            session_live=session.live,
            owner_finished=owner_finished,
            start_seen=bool(rec.get("start_seen")),
            backfill_done=session.backfill_done(),
            output_mtime_ms=rec.get("output_mtime_ms"),
            now_ms=now_ms,
            started_ms=rec.get("started_ms"),
            process_started_ms=process_started_ms,
            expires_ms=rec.get("expires_ms"),
            output_missing=bool(rec.get("output_missing")),
            monitor=rec.get("kind") == "monitor",
        )
        finished_ms = None
        if v.status == FINISHED:
            expired = rec.get("expires_ms") if v.finish_source == "expiry" else None
            ended = session.main.mtime_ms if v.finish_source == "session" else None
            finished_ms = (nt or {}).get("ts_ms") or stop_ms or expired or ended or rec.get("output_mtime_ms")
        ref_ms = finished_ms or rec.get("output_mtime_ms") or rec.get("started_ms") or 0
        age_s = (now_ms - ref_ms) / 1000
        if v.status == FINISHED and age_s > FINISHED_KEEP_S:
            drop.append(tid)
            continue
        if v.status == ORPHANED and age_s > STALE_KEEP_S:
            drop.append(tid)
            continue
        if v.status in (RUNNING, WAITING):
            running += 1
            open_ids.add(tid)
        started = rec.get("started_ms")
        elapsed = None
        if started:
            elapsed = (finished_ms or now_ms) - started
        rows.append(
            {
                "task_id": field(tid, 32),
                "kind": rec.get("kind") or "bash",
                "session_id": session.sid,
                "session_short": session.sid[:8],
                "owner_agent_id": owner,
                "owner_label": owner_label,
                "description": rec.get("description"),
                "status": v.status,
                "status_label": v.label,
                "outcome": v.outcome,
                "exit_code": (nt or {}).get("exit_code"),
                "started_ms": started,
                "finished_ms": finished_ms,
                "output_bytes": rec.get("output_bytes"),
                "output_mtime_ms": rec.get("output_mtime_ms"),
                "elapsed_ms": elapsed,
                "start_seen": bool(rec.get("start_seen")),
                "auto_backgrounded": bool(rec.get("auto_backgrounded")),
                "private": owner_private,
            }
        )
    for tid in drop:
        rec = idx.bg.get(tid)
        # Drop entries with launch records; the 24-hour rule prevents inventory re-entry.
        if rec is not None and len(idx.bg) > BG_PER_SESSION_MAX:
            idx.forget_bg(tid)
    over = len(idx.bg) - BG_PER_SESSION_MAX
    if over > 0:
        # All entries are within the display window. Evict oldest completed entries, then oldest open entries if necessary.
        # Evict placeholders last, or a later launch record could revive a completed job.
        for tid in sorted(idx.bg, key=lambda t: (t in open_ids, not idx.bg[t].get("start_seen"), idx.bg[t].get("started_ms") or 0))[:over]:
            idx.forget_bg(tid)
    rows.sort(key=lambda r: (r["status"] not in (RUNNING, WAITING), -(r["started_ms"] or 0)))
    return rows, running


class _Item:
    __slots__ = ("scanner", "idx", "owner", "tools", "on_done", "size", "ids")

    def __init__(self, scanner, idx, owner, on_done, size, ids=None):
        self.scanner = scanner
        self.idx = idx
        self.owner = owner
        self.tools = 0
        self.on_done = on_done
        self.size = size
        self.ids = ids


class BackfillQueue:
    """Slow, single-pass recovery of launch records outside the tail window."""

    def __init__(self, on_error=None):
        self.items: deque[_Item] = deque()
        self.total = 0
        self.done = 0
        self.on_error = on_error

    def add(self, path, end: int, idx: SessionIndex, owner, on_done, front: bool = False, ids: set | None = None) -> None:
        """Call on_done(tools); None means skipped and an inexact tool count."""
        if end <= 0:
            on_done(0)
            return
        if end > BACKFILL_MAX_FILE:
            on_done(None)
            return
        item = _Item(RangeScanner(path, end), idx, owner, on_done, end, ids)
        self.total += end
        if front:
            self.items.appendleft(item)
        else:
            self.items.append(item)

    def pending(self) -> bool:
        return bool(self.items)

    def cancel(self, match) -> None:
        """Remove entries without owners and call on_done(None) to update remaining counts."""
        kept: deque[_Item] = deque()
        for item in self.items:
            if match(item):
                self.done += item.size - item.scanner.offset
                item.on_done(None)
            else:
                kept.append(item)
        self.items = kept

    def pct(self) -> int:
        if self.total <= 0:
            return 100
        return min(100, int(self.done * 100 / self.total))

    def run(self, cap: int = BACKFILL_TICK_CAP) -> int:
        spent = 0
        while self.items and spent < cap:
            item = self.items[0]
            before = item.scanner.offset
            try:
                lines = item.scanner.step(min(cap - spent, BACKFILL_TICK_CAP))
            except OSError as e:
                if self.on_error:
                    self.on_error(e)
                self.items.popleft()
                self.done += item.size - before
                item.on_done(None)
                continue
            got = item.scanner.offset - before
            spent += got
            self.done += got
            for ln in lines:
                item.tools += scan_backfill_line(ln, item.idx, item.owner, item.ids, item.scanner.offset)
            if item.scanner.done:
                self.items.popleft()
                item.on_done(item.tools)
            elif got == 0:
                self.items.popleft()
                self.done += item.size - item.scanner.offset
                item.on_done(None)
        return spent
