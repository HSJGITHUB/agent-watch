"""Collect registries, sessions, subagents, and workflows and assemble views."""
from __future__ import annotations

import hashlib
import heapq
import json
import os
import re
import time
from collections import OrderedDict
from types import SimpleNamespace

import collect_bg
import model
import status as st
from claude_parse import SessionIndex, TranscriptState, extract_title_pos, is_blob_line, loads_line
from config import (
    AGENTS_PER_SESSION_MAX,
    BF_SEEN_MAX,
    FINISHED_KEEP_S,
    GONE_MAX,
    HOT_MAX,
    HOT_RR_SLOTS,
    INIT_TAIL,
    MAP_CACHE_S,
    ORPHAN_QUIET_S,
    PATH_CACHE_MAX,
    PER_FILE_TICK_CAP,
    REGISTRY_MAX_BYTES,
    RELIST_HOLD_MS,
    RUNS_SKIP_MAX,
    SESSIONS_MAX,
    STALE_KEEP_S,
    TERMINAL_MAX_BYTES,
    TITLE_HEAD_BYTES,
    Paths,
    Settings,
)
from masking import PRIVATE, field, path_display
from tailreader import Budget, IncrementalReader, read_all, read_head
from winproc import LivenessCache

REG_NAME_RE = re.compile(r"^\d+\.json$")
SID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
AGENT_FILE_RE = re.compile(r"^agent-(a[0-9a-f]{8,40})\.jsonl$")
RUN_DIR_RE = re.compile(r"^wf_[0-9A-Za-z_-]+$")
SLUG_RE = re.compile(r"[^A-Za-z0-9]")
SAFE_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
AGENT_ID_RE = re.compile(r"a[0-9a-f]{8,40}")  # Validate source IDs before using them in paths or displays.
REG_FIELDS = (
    "pid", "sessionId", "cwd", "startedAt", "procStart", "version", "kind",
    "entrypoint", "name", "status", "statusUpdatedAt", "updatedAt",
)
_UNSET = object()
MISS_RETRY_S = 30.0
FINAL_SOURCES = ("notification", "meta", "sync_result", "terminal", "journal", "taskstop", "parent")


class Stats:
    __slots__ = ("bad_lines", "skipped_lines", "parse_errors")

    def __init__(self):
        self.bad_lines = 0
        self.skipped_lines = 0
        self.parse_errors = 0


class NullLog:
    def error(self, *a, **k):
        pass

    def info(self, *a, **k):
        pass


class Tracked:
    """One file: incremental reader and parser state."""

    __slots__ = (
        "path", "reader", "state", "idx", "owner", "mtime_ms", "size", "birth_ms", "first_done", "bf", "gen",
        "polled_tick", "ev_key", "ev_snap",
    )

    def __init__(self, path, idx: SessionIndex, owner: str | None, tail: int = INIT_TAIL):
        self.path = path
        self.idx = idx
        self.owner = owner
        self.reader = IncrementalReader(path, tail=tail)
        self.state = TranscriptState(owner, idx)
        self.mtime_ms: int | None = None
        self.size: int | None = None
        self.birth_ms: int | None = None
        self.first_done = False
        self.bf = "none"  # none | queued | done | skipped
        self.gen = 0  # File generation read by this parser state.
        self.polled_tick = 0  # Last tick granted a read slot.
        self.ev_key = None
        self.ev_snap: tuple = ()

    @property
    def backfill_done(self) -> bool:
        return self.bf in ("done", "skipped") or (self.first_done and self.reader.first_start == 0)

    def fresh_state(self, idx: SessionIndex | None = None) -> None:
        """Rebuild parser state and discard cached event snapshots."""
        self.idx = idx or self.idx
        self.state = TranscriptState(self.owner, self.idx)
        self.ev_key = None
        self.ev_snap = ()


class AgentRec:
    __slots__ = (
        "agent_id", "kind", "run_id", "tracked", "jsonl_path", "meta_path", "meta_key", "meta",
        "meta_mtime_ms", "label", "phase", "journal_state", "mtime_ms", "size", "birth_ms", "finish",
        "bf_requested", "expired", "closed",
    )

    def __init__(self, agent_id, kind, jsonl_path, run_id=None):
        self.agent_id = agent_id
        self.kind = kind
        self.run_id = run_id
        self.tracked: Tracked | None = None
        self.jsonl_path = jsonl_path
        self.meta_path = str(jsonl_path)[: -len(".jsonl")] + ".meta.json"
        self.meta_key = None
        self.meta: dict = {}
        self.meta_mtime_ms: int | None = None
        self.label: str | None = None
        self.phase: str | None = None
        self.journal_state: str | None = None
        self.mtime_ms: int | None = None
        self.size: int | None = None
        self.birth_ms: int | None = None
        self.finish = None
        self.bf_requested = False
        self.expired = False  # Outside the display window at the last view build.
        self.closed = False  # Inferred closed without a completion record.


class RunRec:
    __slots__ = (
        "run_id", "dir", "terminal_path", "terminal", "terminal_key", "journal", "agents", "started_order",
        "journal_birth_ms", "journal_mtime_ms", "script_name", "script_checked", "expired", "journal_gen",
        "final_sizes", "activity_ms",
    )

    def __init__(self, run_id, run_dir, terminal_path, activity_ms: int = 0):
        self.run_id = run_id
        self.dir = run_dir
        self.terminal_path = terminal_path
        self.terminal: dict | None = None
        self.terminal_key = None
        self.journal = IncrementalReader(os.path.join(run_dir, "journal.jsonl"), tail=1 << 62)
        self.agents: dict[str, AgentRec] = {}
        self.started_order: list[str] = []
        self.journal_birth_ms: int | None = None
        self.journal_mtime_ms: int | None = None
        self.script_name: str | None = None
        self.script_checked = False
        self.expired = False
        self.journal_gen = 0
        self.final_sizes: dict[str, int] | None = None  # Agent file size at completion; limit for detail rereads.
        self.activity_ms = activity_ms  # Measure the display window from activity after completion when present.


class SessionRec:
    __slots__ = (
        "sid", "path", "dir", "slug_dir", "reg", "seen_in_registry", "live", "live_source", "live_pending",
        "live_count", "main", "idx", "agents", "runs", "runs_skip", "title_head_done",
        "relist_until_ms", "tasks_dir", "tasks_checked", "cwd", "bf_pending", "bf_seen", "gone",
    )

    def __init__(self, sid, path):
        self.sid = sid
        self.path = path
        self.dir = str(path)[: -len(".jsonl")]
        self.slug_dir = os.path.basename(os.path.dirname(str(path)))
        self.reg: dict | None = None
        self.seen_in_registry = False
        self.live = _UNSET
        self.live_source = "registry"
        self.live_pending = _UNSET
        self.live_count = 0
        self.idx = SessionIndex()
        self.main = Tracked(path, self.idx, None)
        self.agents: dict[str, AgentRec] = {}
        self.runs: dict[str, RunRec] = {}
        # Expired run to last activity mtime and launch record. Later activity restores it; stat checks recover even evicted entries.
        self.runs_skip: OrderedDict[str, tuple | None] = OrderedDict()
        self.title_head_done = False
        self.relist_until_ms = 0
        self.tasks_dir: str | None = None
        self.tasks_checked = 0.0
        self.cwd: str | None = None
        self.bf_pending = 0  # Pending backfill for files outside the display set.
        self.bf_seen: OrderedDict[str, None] = OrderedDict()
        # Retired agents: ID to last mtime, owner label, and privacy. Unchanged files stay retired; owned background rows use this decision.
        self.gone: OrderedDict[str, tuple] = OrderedDict()

    def backfill_done(self) -> bool:
        if not self.main.backfill_done or self.bf_pending > 0:
            return False
        for a in self.agents.values():
            if a.tracked is not None and not a.tracked.backfill_done:
                return False
        for run in self.runs.values():
            for a in run.agents.values():
                if a.tracked is not None and not a.tracked.backfill_done:
                    return False
        return True


class _AI:
    """Input to status.agent_status."""

    __slots__ = ("finish", "turn_ended", "own_bg_pending", "effective_activity_ms", "step", "backfill_done")

    def __init__(self, finish, turn_ended, own_bg_pending, effective_activity_ms, step, backfill_done):
        self.finish = finish
        self.turn_ended = turn_ended
        self.own_bg_pending = own_bg_pending
        self.effective_activity_ms = effective_activity_ms
        self.step = step
        self.backfill_done = backfill_done


def _remember(d: OrderedDict, key, value, cap: int) -> None:
    d[key] = value
    d.move_to_end(key)
    while len(d) > cap:
        d.popitem(last=False)


def _agent_private(a: AgentRec) -> bool:
    """Use records, not views: hidden agents must still hide their background jobs."""
    return any(model.is_denied(v) for v in (a.label, a.phase, a.meta.get("description"), a.meta.get("workflowPhase")))


def _ms(ns: int) -> int:
    return ns // 1_000_000


def _birth_ms(s: os.stat_result) -> int | None:
    v = getattr(s, "st_birthtime", None)
    return int(v * 1000) if v else None


def _norm_cwd(cwd: str) -> str:
    return cwd.replace("\\", "/").rstrip("/").lower()


def _project_key(cwd: str) -> str:
    """Export a hash instead of raw cwd, which has not passed through masking."""
    return hashlib.blake2b(_norm_cwd(cwd).encode("utf-8", "replace"), digest_size=8).hexdigest()


def _project_name(cwd: str | None) -> str:
    if not cwd:
        return "(unknown)"
    low = cwd.replace("\\", "/")
    if "/scratchpad" in low.lower():
        return "(scratchpad)"
    return low.rstrip("/").rsplit("/", 1)[-1] or low


class ClaudeCollector:
    def __init__(self, paths: Paths, settings: Settings, stats: Stats | None = None, log=None):
        self.paths = paths
        self.settings = settings
        self.stats = stats or Stats()
        self.log = log or NullLog()
        self.sessions: dict[str, SessionRec] = {}
        self.reg_cache: dict[str, tuple] = {}
        self.liveness = LivenessCache()
        self.project_map: dict[str, str] = {}
        self.temp_map: dict[str, str] = {}
        self.maps_ms = 0.0
        self.path_cache: OrderedDict[str, str] = OrderedDict()
        self.backfill = collect_bg.BackfillQueue(on_error=lambda e: self.log.error("backfill", e))
        self.truncated = False
        self.first_scan_done = False
        self.hot_count = 0  # healthz reads this value without iterating scan-thread dictionaries.
        self.hot_deferred = 0  # Files not granted a read slot this tick.
        self.hot_lag = 0  # Longest wait in ticks among those files.
        self.tick_no = 0
        self.path_miss: dict[str, float] = {}

    # ---- Path mapping ----
    def _refresh_maps(self) -> None:
        now = time.monotonic()
        if now - self.maps_ms < MAP_CACHE_S and self.project_map:
            return
        self.maps_ms = now
        self.project_map = _dir_map(self.paths.projects_dir)
        self.temp_map = _dir_map(self.paths.temp_claude)

    def _resolve_path(self, sid: str, cwd: str | None) -> str | None:
        hit = self.path_cache.get(sid)
        if hit and os.path.exists(hit):
            self.path_cache.move_to_end(sid)
            return hit
        if cwd:
            d = self.project_map.get(SLUG_RE.sub("-", cwd).lower())
            if d:
                p = os.path.join(str(self.paths.projects_dir), d, sid + ".jsonl")
                if os.path.exists(p):
                    _remember(self.path_cache, sid, p, PATH_CACHE_MAX)
                    return p
        best = None
        best_m = -1
        for d in self.project_map.values():
            p = os.path.join(str(self.paths.projects_dir), d, sid + ".jsonl")
            try:
                m = os.stat(p).st_mtime_ns
            except OSError:
                continue
            if m > best_m:
                best, best_m = p, m
        if best:
            _remember(self.path_cache, sid, best, PATH_CACHE_MAX)
        return best

    # ---- Registry ----
    def scan_registry(self) -> dict[str, dict]:
        """Map sessionId to registry dictionaries containing only allowed fields."""
        rd = str(self.paths.registry_dir)
        try:
            names = os.listdir(rd)
        except OSError:
            return {}
        out: dict[str, dict] = {}
        seen: set[str] = set()
        for n in names:
            if not REG_NAME_RE.match(n):
                continue  # Do not even stat key files.
            seen.add(n)
            p = os.path.join(rd, n)
            try:
                s = os.stat(p)
            except OSError:
                continue
            key = (s.st_mtime_ns, s.st_size)
            cached = self.reg_cache.get(n)
            if cached and cached[0] == key:
                d = cached[1]
            else:
                try:
                    raw = json.loads(read_all(p, REGISTRY_MAX_BYTES).decode("utf-8", "replace"))
                    if not isinstance(raw, dict):
                        raise ValueError
                except (OSError, ValueError):
                    # Retain previous values during partial writes; do not cache the new key.
                    d = cached[1] if cached else None
                    if d is None:
                        continue
                else:
                    d = {k: raw.get(k) for k in REG_FIELDS}
                    self.reg_cache[n] = (key, d)
            sid = d.get("sessionId")
            if not isinstance(sid, str) or not SID_RE.match(sid):
                continue  # Used to construct paths.
            prev = out.get(sid)
            if prev is None or (d.get("updatedAt") or 0) >= (prev.get("updatedAt") or 0):
                out[sid] = d
        for n in list(self.reg_cache):
            if n not in seen:
                self.reg_cache.pop(n, None)
        return out

    def _set_live(self, s: SessionRec, value, source: str) -> None:
        """Apply live transitions after two consecutive observations."""
        s.live_source = source
        if s.live is _UNSET:
            s.live = value
            return
        if value == s.live:
            s.live_pending = _UNSET
            s.live_count = 0
            return
        if s.live_pending == value:
            s.live_count += 1
        else:
            s.live_pending = value
            s.live_count = 1
        if s.live_count >= 2:
            s.live = value
            s.live_pending = _UNSET
            s.live_count = 0

    def _apply_registry(self, reg: dict[str, dict], now_ms: int) -> None:
        cutoff = now_ms - int(self.settings.window_h * 3600_000)
        mono = time.monotonic()
        for sid, d in reg.items():
            alive = self.liveness.check(d.get("pid"), d.get("procStart"), d.get("startedAt"))
            s = self.sessions.get(sid)
            if s is None:
                # Avoid rescanning every folder each tick for sessions without transcripts.
                if mono - self.path_miss.get(sid, -1e9) < MISS_RETRY_S:
                    continue
                p = self._resolve_path(sid, d.get("cwd") if isinstance(d.get("cwd"), str) else None)
                if p is None:
                    self.path_miss[sid] = mono
                    continue
                self.path_miss.pop(sid, None)
                if alive is False and _older_than(p, cutoff):
                    self.path_miss[sid] = mono  # Stale registry entry from a dead process.
                    continue
                s = self._ensure_session(sid, p)
            s.reg = d
            s.seen_in_registry = True
            if isinstance(d.get("cwd"), str):
                s.cwd = d["cwd"]
            self._set_live(s, alive, "registry")
        for sid, s in self.sessions.items():
            if sid in reg:
                continue
            s.reg = None
            if s.seen_in_registry:
                # Disappeared from the registry while observed: normal closure.
                self._set_live(s, False, "registry")
                continue
            quiet = (now_ms - (s.main.mtime_ms or 0)) / 1000
            self._set_live(s, None if quiet <= ORPHAN_QUIET_S else False, "mtime")

    def _ensure_session(self, sid: str, path: str) -> SessionRec:
        s = self.sessions.get(sid)
        if s is None:
            s = SessionRec(sid, path)
            self.sessions[sid] = s
        return s

    # ---- Tick ----
    def tick(self, now_ms: int, budget: Budget) -> None:
        self.tick_no += 1
        self._refresh_maps()
        self._apply_registry(self.scan_registry(), now_ms)
        hot = self._hot_files()
        self.hot_count = len(hot)
        self.hot_deferred = max(0, len(hot) - HOT_MAX)
        self.truncated = self.hot_deferred > 0
        self.hot_lag = 0
        if self.truncated:
            hot = self._pick_hot(hot)
        for owner, t in hot:
            self._poll(owner, t, budget)
        for s in list(self.sessions.values()):
            if s.live is False:
                continue
            if s.idx.relist:
                s.idx.relist = False
                s.relist_until_ms = now_ms + RELIST_HOLD_MS
            if now_ms <= s.relist_until_ms:
                self._list_children(s, now_ms)
            for run in list(s.runs.values()):
                if run.terminal is None:
                    self._poll_run(s, run, now_ms, budget)
            if s.main.first_done:
                self._request_backfill(s, s.main, front=True)
            for a in s.agents.values():
                if a.tracked is not None and a.tracked.first_done:
                    self._request_backfill(s, a.tracked)
            for run in s.runs.values():
                for a in run.agents.values():
                    if a.tracked is not None and a.tracked.first_done:
                        self._request_backfill(s, a.tracked)
            if s.tasks_dir:
                collect_bg.stat_open_tasks(s.tasks_dir, s.idx)
        self.stats.skipped_lines = self._sum_skipped()

    def _sum_skipped(self) -> int:
        total = 0
        for s in self.sessions.values():
            total += s.main.reader.skipped_lines
            for a in s.agents.values():
                if a.tracked is not None:
                    total += a.tracked.reader.skipped_lines
        return total

    def _hot_files(self) -> list[tuple[SessionRec, Tracked]]:
        out: list[tuple[SessionRec, Tracked]] = []
        for s in self.sessions.values():
            if s.live is False:
                continue
            out.append((s, s.main))
            for a in s.agents.values():
                if a.tracked is not None and not _is_final(a):
                    out.append((s, a.tracked))
            for run in s.runs.values():
                if run.terminal is None:
                    for a in run.agents.values():
                        if a.tracked is not None and not _is_final(a):
                            out.append((s, a.tracked))
        return out

    def _pick_hot(self, hot: list[tuple[SessionRec, Tracked]]) -> list[tuple[SessionRec, Tracked]]:
        """Bound latency above HOT_MAX: read the 150 most recent files plus 50 least recently read files. Each of N files gets a turn within ceil((N-150)/50) ticks; waiting files use the read budget first."""
        hot.sort(key=lambda p: p[1].mtime_ms or 0, reverse=True)
        recent = HOT_MAX - HOT_RR_SLOTS
        due = heapq.nsmallest(HOT_RR_SLOTS, hot[recent:], key=lambda p: p[1].polled_tick)
        self.hot_lag = self.tick_no - due[0][1].polled_tick
        return due + hot[:recent]

    def _poll(self, owner: SessionRec, t: Tracked, budget: Budget) -> bool:
        try:
            s = os.stat(t.path)
        except OSError:
            return False
        t.mtime_ms = _ms(s.st_mtime_ns)
        t.size = s.st_size
        if t.birth_ms is None:
            t.birth_ms = _birth_ms(s)
        if not t.reader.changed(s) and t.first_done:
            t.polled_tick = self.tick_no
            return False
        cap = budget.allow(PER_FILE_TICK_CAP)
        if cap <= 0:
            return False
        t.polled_tick = self.tick_no
        try:
            lines = t.reader.poll(s, cap)
        except OSError as e:
            if not isinstance(e, (FileNotFoundError, PermissionError)):
                self.log.error("tail_read", e)
            return False
        budget.spend(t.reader.last_read)
        if t.reader.generation != t.gen:
            self._file_replaced(owner, t)
            t.birth_ms = _birth_ms(s)
        self._feed(t, lines)
        if not t.first_done and t.reader.caught_up():
            if not t.state.has_assistant and t.reader.can_expand():
                t.reader.expand()
                t.fresh_state()
            else:
                t.first_done = True
        return True

    def _file_replaced(self, s: SessionRec, t: Tracked) -> None:
        """Replacement at the same path: discard the old parser, totals, and backfill state."""
        t.gen = t.reader.generation
        old = s.idx
        main = t is s.main
        # Cancel first because the callback touches t.bf.
        self.backfill.cancel((lambda item: item.idx is old) if main else (lambda item: item.scanner.path == t.path))
        t.first_done = False
        t.bf = "none"
        if main:
            # The main file builds the session index, so rebuild its children too.
            s.idx = SessionIndex()
            s.idx.relist = True
            t.fresh_state(s.idx)
            s.agents.clear()
            s.runs.clear()
            s.runs_skip.clear()
            s.bf_seen.clear()
            s.gone.clear()
            s.bf_pending = 0
            s.title_head_done = False
            return
        t.fresh_state()
        s.bf_seen.pop(str(t.path), None)
        idx = s.idx
        for tid in [k for k, r in idx.bg.items() if r.get("owner") == t.owner]:
            idx.forget_bg(tid)
        for rid in [k for k, w in idx.workflows.items() if w.get("owner") == t.owner]:
            idx.forget_workflow(rid)

    def _feed(self, t: Tracked, lines: list[bytes]) -> None:
        state = t.state
        for ln in lines:
            if is_blob_line(ln):
                continue
            rec = loads_line(ln)
            if rec is None:
                self.stats.bad_lines += 1
                continue
            try:
                state.feed(rec)
            except Exception as e:  # One bad record must not stop the whole scan.
                self.stats.parse_errors += 1
                self.log.error("feed", e)

    def _request_backfill(self, s: SessionRec, t: Tracked, front: bool = False) -> None:
        # Backfill recent unregistered sessions too, so titles outside the window still affect privacy.
        if t.bf != "none" or s.live is False or s.live is _UNSET:
            return
        end = t.reader.first_start
        if end <= 0:
            t.bf = "done"
            return
        t.bf = "queued"

        def done(tools, t=t):
            t.bf = "skipped" if tools is None else "done"

        self.backfill.add(t.path, end, s.idx, t.owner, done, front=front, ids=t.state.tool_ids)

    def _backfill_whole(self, s: SessionRec, path: str, size: int, owner: str) -> None:
        """For undisplayed files, recover launch records without reading the tail."""
        if path in s.bf_seen:
            return
        _remember(s.bf_seen, path, None, BF_SEEN_MAX)
        s.bf_pending += 1

        def done(tools, s=s):
            s.bf_pending -= 1

        self.backfill.add(path, size, s.idx, owner, done)

    # ---- Discovery (30 seconds) ----
    def discover(self, now_ms: int, budget: Budget) -> None:
        self._refresh_maps()
        mono = time.monotonic()
        # MISS_RETRY_S also bounds entry lifetime.
        self.path_miss = {k: v for k, v in self.path_miss.items() if mono - v < MISS_RETRY_S}
        cutoff = now_ms - int(self.settings.window_h * 3600_000)
        found = self._scan_projects(cutoff)
        for sid, (path, _m) in found.items():
            cur = self.sessions.get(sid)
            if cur is None:
                self._ensure_session(sid, path)
            elif cur.reg is None and str(cur.path) != path:
                # For duplicate local and network session IDs, use the latest mtime.
                try:
                    if os.stat(path).st_mtime_ns > os.stat(cur.path).st_mtime_ns:
                        self._drop_session(cur)
                        self.sessions[sid] = SessionRec(sid, path)
                except OSError:
                    pass
        self._apply_registry(self.scan_registry(), now_ms)
        keep = sorted(
            self.sessions.values(),
            key=lambda s: (s.live is True, s.main.mtime_ms or found.get(s.sid, (None, 0))[1]),
            reverse=True,
        )
        for s in keep[SESSIONS_MAX:]:
            self._drop_session(s)
        for s in list(self.sessions.values()):
            try:
                self._poll(s, s.main, budget)
                if s.main.first_done and not s.title_head_done:
                    self._title_from_head(s)
                if self._evict(s, now_ms, cutoff):
                    continue
                self._find_tasks_dir(s)
                self._list_children(s, now_ms)
                self._warm(s, now_ms, budget)
                if s.tasks_dir and s.live is True:
                    collect_bg.scan_tasks_dir(s.tasks_dir, s.idx, now_ms)
            except Exception as e:
                self.stats.parse_errors += 1
                self.log.error("discover_session", e)
        self.first_scan_done = True

    def _drop_session(self, s: SessionRec) -> None:
        self.sessions.pop(s.sid, None)
        self.backfill.cancel(lambda item: item.idx is s.idx)

    def _evict(self, s: SessionRec, now_ms: int, cutoff: int) -> bool:
        if s.live is True or s.live is None or s.live is _UNSET:
            return False
        if (s.main.mtime_ms or 0) < cutoff:
            self._drop_session(s)
            self.path_miss[s.sid] = time.monotonic()
            return True
        return False

    def _forget_agent(self, s: SessionRec, rec: AgentRec) -> None:
        """Retire expired trackers and indexes. Tombstones prevent recreation and preserve background privacy."""
        s.agents.pop(rec.agent_id, None)
        label = rec.label or rec.meta.get("description") or rec.agent_id[:8]
        _remember(s.gone, rec.agent_id, (rec.mtime_ms or 0, label, _agent_private(rec)), GONE_MAX)
        s.idx.forget_agent(rec.agent_id, rec.meta.get("toolUseId"))

    def _forget_run(self, s: SessionRec, run: RunRec) -> None:
        private = self._run_private(s, run)
        for aid, a in run.agents.items():
            _remember(s.gone, aid, (0, a.label or a.meta.get("description") or aid[:8], aid in private), GONE_MAX)
        for p in (run.terminal or {}).get("progress", ()):
            aid = p.get("agent_id")
            if aid:
                _remember(s.gone, aid, (0, p.get("label") or aid[:8], aid in private), GONE_MAX)
        s.runs.pop(run.run_id, None)
        _remember(s.runs_skip, run.run_id, (_run_activity(run.dir, run.terminal_path), s.idx.workflows.get(run.run_id)), RUNS_SKIP_MAX)
        s.idx.forget_workflow(run.run_id)

    def _revive_run(self, s: SessionRec, rid: str, run_dir: str, term_path: str) -> bool:
        """Restore retired runs on later activity, including launch records to preserve names."""
        entry = s.runs_skip[rid]
        if _run_activity(run_dir, term_path) <= (entry[0] if entry else 0):
            return False
        del s.runs_skip[rid]
        launch = entry[1] if entry else None
        if launch is not None:
            launch["terminal"] = False
            launch.pop("final", None)
            s.idx.workflows[rid] = launch
            if launch.get("task_id"):
                s.idx.wf_by_task[launch["task_id"]] = rid
        return True

    def _scan_projects(self, cutoff_ms: int) -> dict[str, tuple[str, int]]:
        root = str(self.paths.projects_dir)
        out: dict[str, tuple[str, int]] = {}
        for d in self.project_map.values():
            pd = os.path.join(root, d)
            try:
                it = os.scandir(pd)
            except OSError:
                continue
            with it:
                for e in it:
                    n = e.name
                    if not n.endswith(".jsonl"):
                        continue
                    sid = n[:-6]
                    if not SID_RE.match(sid):
                        continue
                    try:
                        m = _ms(e.stat().st_mtime_ns)
                    except OSError:
                        continue
                    if m < cutoff_ms:
                        continue
                    cur = out.get(sid)
                    if cur is None or m > cur[1]:
                        out[sid] = (os.path.join(pd, n), m)
        return out

    def _title_from_head(self, s: SessionRec) -> None:
        s.title_head_done = True
        st_ = s.main.state
        if (st_.title_custom and st_.title_ai) or s.main.reader.first_start == 0:
            return
        try:
            found = extract_title_pos(read_head(s.main.path, TITLE_HEAD_BYTES))
        except OSError:
            return
        for kind, (text, pos) in found.items():
            s.idx.set_title(kind, text, pos)

    def _find_tasks_dir(self, s: SessionRec) -> None:
        if s.tasks_dir is not None:
            return
        now = time.monotonic()
        if now - s.tasks_checked < MAP_CACHE_S:
            return
        s.tasks_checked = now
        d = self.temp_map.get(s.slug_dir.lower())
        if not d:
            return
        p = os.path.join(str(self.paths.temp_claude), d, s.sid, "tasks")
        if os.path.isdir(p):
            s.tasks_dir = p

    def _list_children(self, s: SessionRec, now_ms: int) -> None:
        cutoff = now_ms - int(self.settings.window_h * 3600_000)
        sub = os.path.join(s.dir, "subagents")
        try:
            it = os.scandir(sub)
        except OSError:
            return
        with it:
            for e in it:
                n = e.name
                m = AGENT_FILE_RE.match(n)
                if not m:
                    continue
                try:
                    es = e.stat()
                except OSError:
                    continue
                mt = _ms(es.st_mtime_ns)
                aid = m.group(1)
                rec = s.agents.get(aid)
                if rec is None:
                    if mt < cutoff:
                        continue
                    gone = s.gone.get(aid)
                    if gone is not None and mt <= gone[0]:
                        continue  # Already retired with no later records.
                    s.gone.pop(aid, None)
                    rec = AgentRec(aid, "direct", os.path.join(sub, n))
                    s.agents[aid] = rec
                rec.mtime_ms = mt
                rec.size = es.st_size
                if rec.tracked is not None:
                    rec.tracked.mtime_ms = max(rec.tracked.mtime_ms or 0, mt)
        self._list_runs(s, now_ms, cutoff)

    def _list_runs(self, s: SessionRec, now_ms: int, cutoff: int) -> None:
        root = os.path.join(s.dir, "subagents", "workflows")
        try:
            it = os.scandir(root)
        except OSError:
            return
        with it:
            names = [e.name for e in it if RUN_DIR_RE.match(e.name)]
        for rid in names:
            run = s.runs.get(rid)
            rd = os.path.join(root, rid)
            term = os.path.join(s.dir, "workflows", rid + ".json")
            skipped = rid in s.runs_skip
            if skipped or (run is not None and run.terminal is not None):
                if s.live is True:
                    self._backfill_run_files(s, rd, cutoff)
                if not skipped or not self._revive_run(s, rid, rd, term):
                    continue
            elif run is not None:
                continue
            activity = 0
            try:
                ts = os.stat(term)
            except OSError:
                ts = None
            if ts is not None:
                activity = max(_ms(ts.st_mtime_ns), _newest_agent_mtime(rd))
                if (now_ms - activity) / 1000 > FINISHED_KEEP_S:
                    _remember(s.runs_skip, rid, (activity, None), RUNS_SKIP_MAX)
                    continue
            else:
                try:
                    js = os.stat(os.path.join(rd, "journal.jsonl"))
                    newest = _ms(js.st_mtime_ns)
                except OSError:
                    newest = 0
                newest = max(newest, _newest_agent_mtime(rd))
                if newest < cutoff:
                    continue
            s.runs[rid] = RunRec(rid, rd, term, activity)

    def _backfill_run_files(self, s: SessionRec, run_dir: str, cutoff: int) -> None:
        try:
            it = os.scandir(run_dir)
        except OSError:
            return
        with it:
            for e in it:
                m = AGENT_FILE_RE.match(e.name)
                if not m or e.path in s.bf_seen:
                    continue
                try:
                    es = e.stat()
                except OSError:
                    continue
                if _ms(es.st_mtime_ns) >= cutoff:
                    self._backfill_whole(s, e.path, es.st_size, m.group(1))

    def _warm(self, s: SessionRec, now_ms: int, budget: Budget) -> None:
        for rec in list(s.agents.values()):
            self._warm_agent(s, rec, now_ms, budget)
        for run in list(s.runs.values()):
            if run.script_name is None:
                run.script_checked = False  # Retry every discovery in case the script file appeared late.
            self._poll_run(s, run, now_ms, budget)
            if run.terminal is not None:
                age = (now_ms - max(_terminal_end_ms(run.terminal) or now_ms, run.activity_ms)) / 1000
                if age > FINISHED_KEEP_S:
                    self._forget_run(s, run)
            elif run.expired:
                self._forget_run(s, run)  # Display window expired without a terminal record.

    def _warm_agent(self, s: SessionRec, rec: AgentRec, now_ms: int, budget: Budget) -> None:
        self._load_meta(rec)
        if rec.meta.get("finished") is True and (now_ms - (rec.mtime_ms or 0)) / 1000 > FINISHED_KEEP_S:
            # Outside the display set: skip tails, but backfill launches for live sessions.
            if s.live is True:
                self._backfill_whole(s, rec.jsonl_path, rec.size or 0, rec.agent_id)
            self._forget_agent(s, rec)
            return
        if rec.expired:
            self._forget_agent(s, rec)
            return
        if rec.tracked is None:
            rec.tracked = Tracked(rec.jsonl_path, s.idx, rec.agent_id)
        self._poll(s, rec.tracked, budget)

    def _load_meta(self, rec: AgentRec) -> None:
        try:
            ms = os.stat(rec.meta_path)
        except OSError:
            return
        key = (ms.st_mtime_ns, ms.st_size)
        if key == rec.meta_key:
            return
        try:
            d = json.loads(read_all(rec.meta_path, REGISTRY_MAX_BYTES).decode("utf-8", "replace"))
        except (OSError, ValueError):
            return
        if not isinstance(d, dict):
            return
        rec.meta_key = key
        rec.meta_mtime_ms = _ms(ms.st_mtime_ns)
        rec.meta = {
            "agentType": d.get("agentType"),
            "description": field(d.get("description"), 80, first_line=True),
            "toolUseId": _safe_id(d.get("toolUseId")),
            "spawnDepth": d.get("spawnDepth"),
            "model": d.get("model"),
            "requestShape": d.get("requestShape"),
            "finished": d.get("finished"),
            "stoppedByUser": d.get("stoppedByUser"),
            "parentAgentId": _agent_id(d.get("parentAgentId")),
            "workflowPhase": field(d.get("workflowPhase"), 60, first_line=True),
        }

    # ---- Workflows ----
    def _poll_run(self, s: SessionRec, run: RunRec, now_ms: int, budget: Budget) -> None:
        self._load_terminal(run)
        if run.terminal is not None:
            launch = s.idx.workflows.get(run.run_id)
            if launch is not None:
                launch["terminal"] = True
            if run.final_sizes is None:
                run.final_sizes = _final_sizes(run.dir)
            run.agents.clear()  # Finished runs use terminal data only.
            if s.live is True:
                self._backfill_run_files(s, run.dir, now_ms - int(self.settings.window_h * 3600_000))
            return
        journal_path = run.journal.path
        try:
            js = os.stat(journal_path)
            run.journal_mtime_ms = _ms(js.st_mtime_ns)
            if run.journal_birth_ms is None:
                run.journal_birth_ms = _birth_ms(js)
            if run.journal.changed(js):
                cap = budget.allow(PER_FILE_TICK_CAP)
                if cap > 0:
                    lines = run.journal.poll(js, cap)
                    budget.spend(run.journal.last_read)
                    if run.journal.generation != run.journal_gen:
                        run.journal_gen = run.journal.generation
                        run.agents.clear()
                        run.started_order.clear()
                    self._feed_journal(run, lines)
        except OSError:
            pass
        try:
            it = os.scandir(run.dir)
        except OSError:
            return
        with it:
            for e in it:
                m = AGENT_FILE_RE.match(e.name)
                if not m:
                    continue
                aid = m.group(1)
                try:
                    es = e.stat()
                except OSError:
                    continue
                rec = run.agents.get(aid)
                if rec is None:
                    rec = AgentRec(aid, "workflow", os.path.join(run.dir, e.name), run.run_id)
                    run.agents[aid] = rec
                rec.mtime_ms = _ms(es.st_mtime_ns)
                rec.size = es.st_size
                if rec.tracked is not None:
                    rec.tracked.mtime_ms = max(rec.tracked.mtime_ms or 0, rec.mtime_ms)
        for rec in run.agents.values():
            if rec.tracked is None:
                self._load_meta(rec)
                rec.tracked = Tracked(rec.jsonl_path, s.idx, rec.agent_id)

    def _feed_journal(self, run: RunRec, lines: list[bytes]) -> None:
        for ln in lines:
            rec = loads_line(ln)
            if rec is None:
                self.stats.bad_lines += 1
                continue
            t = rec.get("type")
            aid = rec.get("agentId")
            if not isinstance(aid, str) or not AGENT_ID_RE.fullmatch(aid):
                continue
            a = run.agents.get(aid)
            if a is None:
                path = os.path.join(run.dir, f"agent-{aid}.jsonl")
                a = AgentRec(aid, "workflow", path, run.run_id)
                run.agents[aid] = a
            if t == "started":
                a.label = field(rec.get("label"), 60, first_line=True)
                a.phase = field(rec.get("phase"), 60, first_line=True)
                if aid not in run.started_order:
                    run.started_order.append(aid)
            elif t in ("result", "failed"):
                a.journal_state = t

    def _load_terminal(self, run: RunRec) -> None:
        try:
            ts = os.stat(run.terminal_path)
        except OSError:
            return
        key = (ts.st_mtime_ns, ts.st_size)
        if key == run.terminal_key:
            return
        try:
            d = json.loads(read_all(run.terminal_path, TERMINAL_MAX_BYTES).decode("utf-8", "replace"))
        except (OSError, ValueError):
            return
        if not isinstance(d, dict):
            return
        run.terminal_key = key
        run.terminal = _pick_terminal(d, _ms(ts.st_mtime_ns))
        run.final_sizes = None

    # ---- View assembly ----
    def build(self, now_ms: int) -> dict:
        sessions: list[dict] = []
        bg_rows: list[dict] = []
        index: dict[tuple[str, str], dict] = {}
        for s in self.sessions.values():
            try:
                view, rows, private_owners, sources = self._session_view(s, now_ms)
                model.redact_session_view(view, rows, private_owners)
                entries = _detail_entries(s, view, sources)
            except Exception as e:  # Do not publish sessions whose privacy decision failed.
                self.stats.parse_errors += 1
                self.log.error("session_view", e)
                continue
            index.update(entries)
            bg_rows.extend(rows)
            sessions.append(view)
        sessions.sort(key=_session_sort_key)
        projects = _projects(sessions)
        return {"sessions": sessions, "bg_tasks": bg_rows, "projects": projects, "index": index}

    def _session_view(self, s: SessionRec, now_ms: int) -> tuple[dict, list[dict], set, dict]:
        """Build session views, background rows, private owners, and detail sources. Decide privacy before display filtering and caps."""
        live = None if s.live is _UNSET else s.live
        private_owners = self._private_owners(s)
        sources: dict[str, tuple] = {}
        idx = s.idx
        # _poll updates Tracked only; synchronize AgentRec values used by status each tick.
        for a in s.agents.values():
            t = a.tracked
            if t is not None and t.mtime_ms:
                a.mtime_ms = max(a.mtime_ms or 0, t.mtime_ms)
                if t.size is not None:
                    a.size = t.size
        proc_started = _proc_started(s)
        open_bg = collect_bg.bg_open_by_owner(idx, proc_started, now_ms)
        children_by_tool: dict[str, AgentRec] = {}
        async_children: dict[str | None, list[AgentRec]] = {}
        for a in s.agents.values():
            tid = a.meta.get("toolUseId")
            if isinstance(tid, str):
                children_by_tool[tid] = a
            call = idx.agent_calls.get(tid) if isinstance(tid, str) else None
            is_async = bool(call and call.get("async")) or a.meta.get("requestShape") == "background"
            if is_async:
                async_children.setdefault(a.meta.get("parentAgentId"), []).append(a)

        wf_open: dict[str | None, int] = {}
        for rid, w in idx.workflows.items():
            run = s.runs.get(rid)
            term = run is not None and run.terminal is not None
            task = w.get("task_id")
            nt = idx.notifs.get(task) if task else None
            if not term and not w.get("terminal") and not (nt and nt.get("status")) and rid not in s.runs_skip:
                wf_open[w.get("owner")] = wf_open.get(w.get("owner"), 0) + 1

        memo_finish: dict[str, object] = {}
        memo_pending: dict[str, int] = {}

        def pending_of(a: AgentRec) -> int:
            if a.agent_id in memo_pending:
                return memo_pending[a.agent_id]
            memo_pending[a.agent_id] = 0  # Guard against cycles.
            n = open_bg.get(a.agent_id, 0) + wf_open.get(a.agent_id, 0)
            for c in async_children.get(a.agent_id, ()):
                # Long-quiet orphan children must not block parent completion forever.
                if finish_of(c) is None and (now_ms - (c.mtime_ms or 0)) / 1000 <= ORPHAN_QUIET_S:
                    n += 1
            memo_pending[a.agent_id] = n
            return n

        def finish_of(a: AgentRec):
            if a.agent_id in memo_finish:
                return memo_finish[a.agent_id]
            memo_finish[a.agent_id] = None
            t = a.tracked
            state = t.state if t else None
            tid = a.meta.get("toolUseId")
            call = idx.agent_calls.get(tid) if isinstance(tid, str) else None
            is_async = bool(call and call.get("async")) or a.meta.get("requestShape") == "background"
            f = st.resolve_direct_finish(
                notification=idx.notifs.get(a.agent_id),
                sync_status=call.get("sync_status") if call else None,
                sync_ms=call.get("resolved_ms") if call else None,
                meta_finished=a.meta.get("finished") is True,
                meta_stopped=a.meta.get("stoppedByUser") is True,
                meta_mtime_ms=a.meta_mtime_ms,
                stop_ms=idx.stops.get(a.agent_id),
                parent_resolved_ms=(call.get("resolved_ms") or now_ms) if call and call.get("resolved") else None,
                is_async=is_async,
                tail_end=bool(state and state.turn_ended),
                tail_ms=state.last_ts if state else None,
                own_bg_pending=pending_of(a),
                backfill_done=t.backfill_done if t else True,
                last_au_ms=state.last_au_ms if state else None,
            )
            memo_finish[a.agent_id] = f
            a.finish = f
            return f

        memo_eff: dict[str, int] = {}

        def eff_of(a: AgentRec) -> int:
            if a.agent_id in memo_eff:
                return memo_eff[a.agent_id]
            memo_eff[a.agent_id] = a.mtime_ms or 0
            best = a.mtime_ms or 0
            if a.tracked is not None:
                for tid in a.tracked.state.pending:
                    c = children_by_tool.get(tid)
                    if c is not None:
                        best = max(best, eff_of(c))
            memo_eff[a.agent_id] = best
            return best

        agent_views: list[dict] = []
        counts = {"running": 0, "waiting": 0, "stalled": 0, "bg_running": 0}
        for a in s.agents.values():
            finish_of(a)
        for a in s.agents.values():
            if a.tracked is None:
                continue
            ai = _AI(
                a.finish, a.tracked.state.turn_ended, pending_of(a), eff_of(a), a.tracked.state.step(),
                a.tracked.backfill_done,
            )
            v = st.agent_status(ai, now_ms, live)
            a.closed = v.status == st.ORPHANED
            view = self._agent_view(s, a, v, ai, now_ms)
            a.expired = not _shown(view, now_ms)
            if a.expired:
                continue
            agent_views.append(view)
            _bump(counts, view["status"])
            sources[a.agent_id] = (a.jsonl_path, a.tracked, None)

        wf_views = []
        for run in s.runs.values():
            wv = self._workflow_view(s, run, live, now_ms, sources, counts, pending_of)
            run.expired = wv is None
            if wv is not None:
                wf_views.append(wv)

        # Main thread.
        main_eff = s.main.mtime_ms or 0
        for tid in s.main.state.pending:
            c = children_by_tool.get(tid)
            if c is not None:
                main_eff = max(main_eff, eff_of(c))
        reg_status = (s.reg or {}).get("status")
        main_pending = open_bg.get(None, 0)
        main_pending += sum(1 for v_ in agent_views if v_["status"] in st.ACTIVE_STATES and v_["background"] and not v_["parent_agent_id"])
        main_pending += sum(1 for w in wf_views if w["status"] in st.ACTIVE_STATES and idx.workflows.get(w["run_id"], {}).get("owner") is None)
        main_ai = _AI(None, s.main.state.turn_ended, main_pending, main_eff, s.main.state.step(), True)
        mv = st.main_status(reg_status, live, main_ai, now_ms)
        main_view = self._main_view(s, mv, main_eff, now_ms)
        main_view["own_bg_pending"] = main_pending
        sources["main"] = (s.main.path, s.main, None)

        def owner_info(owner):
            if owner is None:
                return False, "Main", False
            a = s.agents.get(owner)
            if a is not None:
                return a.finish is not None or a.closed, a.label or a.meta.get("description") or owner[:8], owner in private_owners
            for run in s.runs.values():
                if owner in run.agents:
                    r = run.agents[owner]
                    return r.finish is not None or r.closed, r.label or owner[:8], owner in private_owners
                if run.terminal is not None:
                    for p in run.terminal["progress"]:
                        if p.get("agent_id") == owner:
                            return True, p.get("label") or owner[:8], owner in private_owners
            gone = s.gone.get(owner)
            if gone is not None:
                return True, gone[1], gone[2]
            # Without owner records, the description cannot be classified; hide it conservatively, including expired run agents.
            return True, owner[:8], True

        rows, bg_running = collect_bg.build_bg_views(s, owner_info, now_ms, proc_started)
        counts["bg_running"] = bg_running

        agent_views.sort(key=_agent_sort_key)
        agents_cut = max(0, len(agent_views) - AGENTS_PER_SESSION_MAX)
        agent_views = agent_views[:AGENTS_PER_SESSION_MAX]

        state = s.main.state
        title, source, hidden = self._title(s)
        last_activity = max(
            [main_eff]
            + [v["effective_activity_ms"] or 0 for v in agent_views if v["status"] in st.ACTIVE_STATES]
            + [w["last_activity_ms"] or 0 for w in wf_views if w["status"] in st.ACTIVE_STATES]
        )
        cwd = s.cwd or state.cwd
        started = (s.reg or {}).get("startedAt") if isinstance((s.reg or {}).get("startedAt"), int) else s.main.birth_ms
        view = {
            "id": s.sid,
            "short": s.sid[:8],
            "project_key": _project_key(cwd or s.slug_dir),
            "project_name": field(_project_name(cwd), 80),
            "cwd_display": path_display(cwd) if cwd else None,
            "title": title,
            "title_source": source,
            "title_hidden": hidden,
            "live": live,
            "live_source": s.live_source,
            "state": st.session_state(reg_status, live),
            "kind": _short((s.reg or {}).get("kind")),
            "version": _short((s.reg or {}).get("version")),
            "pid": (s.reg or {}).get("pid") if isinstance((s.reg or {}).get("pid"), int) else None,
            "model": _short(state.model),
            "effort": _short(state.effort),
            "started_ms": started,
            "last_activity_ms": last_activity,
            "main": main_view,
            "agents": agent_views,
            "workflows": wf_views,
            "counts": counts,
            "backfill_done": s.backfill_done(),
        }
        if agents_cut:
            view["agents_omitted"] = agents_cut
        return view, rows, private_owners, sources

    def _private_owners(self, s: SessionRec) -> set:
        """Collect private agent IDs from all ownership records, independent of view filters and caps."""
        out = {aid for aid, a in s.agents.items() if _agent_private(a)}
        for run in s.runs.values():
            out |= self._run_private(s, run)
        return out

    def _run_private(self, s: SessionRec, run: RunRec) -> set:
        hit = model.is_denied(self._run_label(s, run))
        out = {aid for aid, a in run.agents.items() if hit or _agent_private(a)}
        for p in (run.terminal or {}).get("progress", ()):
            aid = p.get("agent_id")
            if aid and (hit or model.is_denied(p.get("label")) or model.is_denied(p.get("phase_title"))):
                out.add(aid)
        return out

    def _run_label(self, s: SessionRec, run: RunRec) -> str:
        """Display name; unnamed runs remain private until their name is known."""
        launch = s.idx.workflows.get(run.run_id) or {}
        name = (run.terminal or {}).get("workflowName") or launch.get("name") or self._script_name(s, run)
        return field(name, 60, first_line=True) or PRIVATE

    def _title(self, s: SessionRec) -> tuple[str | None, str, bool]:
        """Choose the latest title of each kind. Either private title hides the entire session."""
        state = s.main.state
        custom = state.title_custom or s.idx.title_custom
        ai = state.title_ai or s.idx.title_ai
        if PRIVATE in (custom, ai):
            return PRIVATE, "custom" if custom == PRIVATE else "ai", True
        if custom:
            return custom, "custom", False
        if ai:
            return ai, "ai", False
        name = (s.reg or {}).get("name")
        if isinstance(name, str) and name:
            return field(name, 80), "registry", False
        return None, "none", False

    def _agent_view(self, s: SessionRec, a: AgentRec, v: st.Verdict, ai: _AI, now_ms: int) -> dict:
        t = a.tracked
        state = t.state
        idx = s.idx
        meta = a.meta
        nt = idx.notifs.get(a.agent_id) or {}
        tid = meta.get("toolUseId")
        call = idx.agent_calls.get(tid) if isinstance(tid, str) else None
        exact_tokens, exact_src = None, None
        if nt.get("tokens") is not None:
            exact_tokens, exact_src = nt["tokens"], "notification"
        elif call and isinstance(call.get("sync_tokens"), int):
            exact_tokens, exact_src = call["sync_tokens"], "sync_result"
        tools_exact = nt.get("tool_uses")
        if tools_exact is None and call and isinstance(call.get("sync_tools"), int):
            tools_exact = call["sync_tools"]
        started = a.birth_ms or t.birth_ms or state.first_ts
        finished_ms = None
        if v.status == st.FINISHED:
            finished_ms = (a.finish.ts_ms if a.finish else None) or state.last_ts or a.mtime_ms
        duration = nt.get("duration_ms")
        if duration is None and call and isinstance(call.get("sync_duration_ms"), int):
            duration = call["sync_duration_ms"]
        if v.status == st.FINISHED:
            # Tail-window duration can understate long runs; use it only as a last resort.
            if duration is not None:
                elapsed = duration
            elif finished_ms and started:
                elapsed = max(0, finished_ms - started)
            else:
                elapsed = _span(state.first_ts, state.last_ts)
        else:
            elapsed = now_ms - started if started else None
        background = None
        if meta.get("requestShape") is not None:
            background = meta.get("requestShape") == "background"
        return {
            "agent_id": a.agent_id,
            "kind": a.kind,
            "description": a.label or meta.get("description"),
            "agent_type": _short(meta.get("agentType")),
            "model": _short(state.model),
            "model_alias": _short(meta.get("model")),
            "background": background,
            "spawn_depth": meta.get("spawnDepth") if isinstance(meta.get("spawnDepth"), int) else None,
            "parent_agent_id": meta.get("parentAgentId") if isinstance(meta.get("parentAgentId"), str) else None,
            "parent_tool_use_id": tid if isinstance(tid, str) and tid.startswith("toolu_") else None,
            "workflow_run_id": a.run_id,
            "phase": a.phase or meta.get("workflowPhase"),
            "status": v.status,
            "status_label": v.label,
            "outcome": v.outcome,
            "finish_source": v.finish_source,
            "started_ms": started,
            "last_write_ms": a.mtime_ms,
            "effective_activity_ms": ai.effective_activity_ms,
            "finished_ms": finished_ms,
            "elapsed_ms": elapsed,
            "tokens": _tokens(state, exact_tokens, exact_src),
            "tool_calls": _tool_calls(t, tools_exact),
            "step": state.step(),
            "last_tool": _last_tool(state),
            "last_text": state.last_text,
            "own_bg_pending": ai.own_bg_pending,
            "confidence": v.confidence,
            "private": False,
        }

    def _main_view(self, s: SessionRec, v: st.Verdict, eff: int, now_ms: int) -> dict:
        t = s.main
        state = t.state
        started = (s.reg or {}).get("startedAt") if isinstance((s.reg or {}).get("startedAt"), int) else t.birth_ms
        return {
            "agent_id": "main",
            "kind": "main",
            "description": "Main thread",
            "agent_type": None,
            "model": _short(state.model),
            "model_alias": None,
            "background": None,
            "spawn_depth": 0,
            "parent_agent_id": None,
            "parent_tool_use_id": None,
            "workflow_run_id": None,
            "phase": None,
            "status": v.status,
            "status_label": v.label,
            "outcome": None,
            "finish_source": None,
            "started_ms": started,
            "last_write_ms": t.mtime_ms,
            "effective_activity_ms": eff,
            "finished_ms": None,
            "elapsed_ms": now_ms - started if started else None,
            "tokens": _tokens(state, None, None),
            "tool_calls": _tool_calls(t, None),
            "step": state.step(),
            "last_tool": _last_tool(state),
            "last_text": state.last_text,
            "own_bg_pending": 0,
            "confidence": "high",
            "private": False,
        }

    def _workflow_view(self, s: SessionRec, run: RunRec, live, now_ms: int, sources: dict, counts: dict, pending_of) -> dict | None:
        idx = s.idx
        launch = idx.workflows.get(run.run_id) or {}
        term = run.terminal
        task_id = (term or {}).get("taskId") or launch.get("task_id")
        nt = (idx.notifs.get(task_id) if task_id else None) or launch.get("final")
        agent_views: list[dict] = []
        statuses: list[str] = []
        if term is not None:
            for p in term["progress"]:
                agent_views.append(_terminal_agent_view(p, run.run_id, term))
                aid = p.get("agent_id")
                if aid:
                    # Reread retired agents only up to their completion size, excluding newer records.
                    sources[aid] = (os.path.join(run.dir, f"agent-{aid}.jsonl"), None, (run.final_sizes or {}).get(aid, 0))
        else:
            for a in run.agents.values():
                t = a.tracked
                if t is None:
                    continue
                self._load_meta_if_needed(a)
                state = t.state
                pending = pending_of(a)
                # Closed sessions do not backfill, so waiting cannot complete it.
                seen_all = t.backfill_done or live is False
                a.finish = st.resolve_workflow_finish(
                    terminal_state=None,
                    run_outcome=None,
                    journal_state=a.journal_state,
                    tail_end=state.turn_ended,
                    tail_ms=state.last_ts,
                    own_bg_pending=pending,
                    backfill_done=seen_all,
                )
                ai = _AI(a.finish, state.turn_ended, pending, a.mtime_ms or run.journal_mtime_ms or 0, state.step(), seen_all)
                v = st.agent_status(ai, now_ms, live)
                a.closed = v.status == st.ORPHANED
                view = self._agent_view(s, a, v, ai, now_ms)
                view["kind"] = "workflow"
                agent_views.append(view)
                statuses.append(v.status)
                sources[a.agent_id] = (a.jsonl_path, t, None)
        last_activity = max(
            [run.journal_mtime_ms or 0] + [a.mtime_ms or 0 for a in run.agents.values()]
        )
        v = st.workflow_status(
            terminal_status=(term or {}).get("status"),
            notification_status=(nt or {}).get("status"),
            agent_statuses=statuses,
            parent_live=live,
            last_activity_ms=last_activity,
            now_ms=now_ms,
        )
        finished_ms = None
        if term is not None:
            finished_ms = _terminal_end_ms(term)
            last_activity = max(last_activity, finished_ms or 0, run.activity_ms)
        elif v.status == st.FINISHED:
            finished_ms = (nt or {}).get("ts_ms") or last_activity
        ref = last_activity if term is not None else (finished_ms or last_activity)
        age = (now_ms - ref) / 1000
        if v.status == st.FINISHED and age > FINISHED_KEEP_S:
            return None
        if v.status in (st.ORPHANED, st.STALLED) and age > STALE_KEEP_S:
            return None
        for status in statuses:
            _bump(counts, status)
        started = (term or {}).get("startTime") or run.journal_birth_ms
        duration = (term or {}).get("durationMs")
        if v.status == st.FINISHED:
            elapsed = duration if duration is not None else (nt or {}).get("duration_ms")
        else:
            elapsed = now_ms - started if started else None
        token_sum = sum((a["tokens"].get("value") or 0) for a in agent_views)
        tool_sum = sum((a["tool_calls"].get("value") or 0) for a in agent_views)
        tok_exact = (term or {}).get("totalTokens")
        tool_exact = (term or {}).get("totalToolCalls")
        if tok_exact is None and nt:
            tok_exact = nt.get("tokens")
        phases = _phases(run, agent_views)  # Compute before sorting to preserve launch order.
        agent_views.sort(key=_agent_sort_key)
        cut = max(0, len(agent_views) - AGENTS_PER_SESSION_MAX)
        view = {
            "run_id": run.run_id,
            "task_id": _short(task_id),
            "name": self._run_label(s, run),
            "status": v.status,
            "status_label": v.label,
            "outcome": v.outcome,
            "started_ms": started,
            "finished_ms": finished_ms,
            "last_activity_ms": last_activity,
            "elapsed_ms": elapsed,
            "phases": phases,
            "agents_started": len(run.started_order) if term is None else len(agent_views),
            "agents_total": (term or {}).get("agentCount") if term else None,
            "total_is_exact": term is not None,
            "tokens": {"value": tok_exact if tok_exact is not None else token_sum, "exact": tok_exact is not None},
            "tool_calls": {"value": tool_exact if tool_exact is not None else tool_sum, "exact": tool_exact is not None},
            "agents": agent_views[:AGENTS_PER_SESSION_MAX],
            "private": False,
        }
        if cut:
            view["agents_omitted"] = cut
        return view

    def _load_meta_if_needed(self, a: AgentRec) -> None:
        if a.meta_key is None:
            self._load_meta(a)

    def _script_name(self, s: SessionRec, run: RunRec) -> str | None:
        if run.script_checked:
            return run.script_name
        run.script_checked = True
        d = os.path.join(s.dir, "workflows", "scripts")
        suffix = f"-{run.run_id}.js"
        try:
            with os.scandir(d) as it:
                for e in it:
                    if e.name.endswith(suffix):
                        run.script_name = e.name[: -len(suffix)]
                        break
        except OSError:
            pass
        return run.script_name


def _detail_entries(s: SessionRec, view: dict, sources: dict) -> dict:
    """Build immutable detail entries only from final redacted views. Undisplayed items cannot be accessed through details."""
    out: dict[tuple[str, str], dict] = {}

    def add(v: dict) -> None:
        aid = v.get("agent_id")
        src = sources.get(aid)
        if src is None:
            return
        path, t, end = src
        events = None if t is None else model.event_snapshot(t, t.state.events, bool(v.get("private")))
        out[(s.sid, aid)] = {"view": v, "path": path, "events": events, "end": end}

    add(view["main"])
    for a in view["agents"]:
        add(a)
    for w in view["workflows"]:
        for a in w["agents"]:
            add(a)
    return out


def _safe_id(v: object) -> str | None:
    return v if isinstance(v, str) and SAFE_ID_RE.fullmatch(v) else None


def _agent_id(v: object) -> str | None:
    return v if isinstance(v, str) and AGENT_ID_RE.fullmatch(v) else None


def _proc_started(s: SessionRec) -> int | None:
    v = (s.reg or {}).get("startedAt")
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _older_than(path, cutoff_ms: int) -> bool:
    try:
        return _ms(os.stat(path).st_mtime_ns) < cutoff_ms
    except OSError:
        return True


def _dir_map(root) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with os.scandir(root) as it:
            for e in it:
                try:
                    if e.is_dir():
                        out[e.name.lower()] = e.name
                except OSError:
                    continue
    except OSError:
        pass
    return out


def _final_sizes(run_dir: str) -> dict[str, int]:
    """Stat each agent file for its current size; Windows directory entries can lag."""
    out: dict[str, int] = {}
    try:
        names = os.listdir(run_dir)
    except OSError:
        return out
    for n in names:
        m = AGENT_FILE_RE.match(n)
        if m:
            try:
                out[m.group(1)] = os.stat(os.path.join(run_dir, n)).st_size
            except OSError:
                continue
    return out


def _run_activity(run_dir: str, term_path: str) -> int:
    """Latest activity mtime across the journal, agent files, and terminal record."""
    best = _newest_agent_mtime(run_dir)
    try:
        best = max(best, _ms(os.stat(term_path).st_mtime_ns))
    except OSError:
        pass
    return best


def _newest_agent_mtime(run_dir: str) -> int:
    best = 0
    try:
        with os.scandir(run_dir) as it:
            for e in it:
                if e.name.endswith(".jsonl"):
                    try:
                        best = max(best, _ms(e.stat().st_mtime_ns))
                    except OSError:
                        continue
    except OSError:
        pass
    return best


def _is_final(a: AgentRec) -> bool:
    return a.finish is not None and a.finish.source in FINAL_SOURCES


def _pick_terminal(d: dict, mtime_ms: int) -> dict:
    """Keep only allowed terminal JSON keys; discard script, result, summary, logs, error, promptPreview, and other fields."""
    phases = []
    progress = []
    wp = d.get("workflowProgress")
    if isinstance(wp, list):
        for p in wp:
            if not isinstance(p, dict):
                continue
            if p.get("type") == "workflow_phase":
                phases.append({"index": p.get("index"), "title": field(p.get("title"), 60, first_line=True)})
            elif p.get("type") == "workflow_agent":
                progress.append(
                    {
                        "agent_id": p.get("agentId") if isinstance(p.get("agentId"), str) and AGENT_ID_RE.fullmatch(p["agentId"]) else None,
                        "label": field(p.get("label"), 60, first_line=True),
                        "phase_index": p.get("phaseIndex"),
                        "phase_title": field(p.get("phaseTitle"), 60, first_line=True),
                        "agent_type": _short(p.get("agentType")),
                        "model": _short(p.get("model")),
                        "state": _short(p.get("state")),
                        "started_ms": p.get("startedAt") if isinstance(p.get("startedAt"), int) else None,
                        "last_tool": _short(p.get("lastToolName")),
                        "tokens": p.get("tokens") if isinstance(p.get("tokens"), int) else None,
                        "tool_calls": p.get("toolCalls") if isinstance(p.get("toolCalls"), int) else None,
                        "duration_ms": p.get("durationMs") if isinstance(p.get("durationMs"), int) else None,
                    }
                )
    if not phases and isinstance(d.get("phases"), list):
        for i, p in enumerate(d["phases"]):
            if isinstance(p, dict):
                phases.append({"index": i + 1, "title": field(p.get("title"), 60, first_line=True)})
    return {
        "taskId": d.get("taskId") if isinstance(d.get("taskId"), str) else None,
        "workflowName": d.get("workflowName") if isinstance(d.get("workflowName"), str) else None,
        "status": d.get("status") if isinstance(d.get("status"), str) else "other",
        "startTime": d.get("startTime") if isinstance(d.get("startTime"), int) else None,
        "timestamp": d.get("timestamp") if isinstance(d.get("timestamp"), str) else None,
        "durationMs": d.get("durationMs") if isinstance(d.get("durationMs"), int) else None,
        "agentCount": d.get("agentCount") if isinstance(d.get("agentCount"), int) else None,
        "totalTokens": d.get("totalTokens") if isinstance(d.get("totalTokens"), int) else None,
        "totalToolCalls": d.get("totalToolCalls") if isinstance(d.get("totalToolCalls"), int) else None,
        "phases": phases,
        "progress": progress,
        "mtime_ms": mtime_ms,
    }


def _terminal_end_ms(term: dict) -> int | None:
    from claude_parse import parse_ts

    return parse_ts(term.get("timestamp")) or term.get("mtime_ms")


def _terminal_agent_view(p: dict, run_id: str, term: dict) -> dict:
    f = st.resolve_workflow_finish(
        terminal_state=p.get("state") or "other",
        run_outcome=term.get("status"),
        journal_state=None,
        tail_end=False,
        tail_ms=None,
    )
    label = st.finished_label(f.outcome)
    last_tool = {"name": p["last_tool"], "arg": None, "ok": None, "ts_ms": None} if p.get("last_tool") else None
    return {
        "agent_id": p.get("agent_id"),
        "kind": "workflow",
        "description": p.get("label"),
        "agent_type": p.get("agent_type"),
        "model": p.get("model"),
        "model_alias": None,
        "background": None,
        "spawn_depth": 1,
        "parent_agent_id": None,
        "parent_tool_use_id": None,
        "workflow_run_id": run_id,
        "phase": p.get("phase_title"),
        "status": st.FINISHED,
        "status_label": label,
        "outcome": f.outcome,
        "finish_source": "terminal",
        "started_ms": p.get("started_ms"),
        "last_write_ms": None,
        "effective_activity_ms": None,
        "finished_ms": (p["started_ms"] + p["duration_ms"]) if p.get("started_ms") and p.get("duration_ms") else None,
        "elapsed_ms": p.get("duration_ms"),
        "tokens": {"value": p.get("tokens"), "exact": p.get("tokens") is not None, "ctx": None, "sum_out_observed": None, "source": "terminal"},
        "tool_calls": {"value": p.get("tool_calls"), "exact": p.get("tool_calls") is not None},
        "step": {"kind": "turn_end", "tool": None, "arg": None, "since_ms": None, "parallel": 0, "timeout_ms": None},
        "last_tool": last_tool,
        "last_text": None,
        "own_bg_pending": 0,
        "confidence": "high",
        "private": False,
    }


def _phases(run: RunRec, agent_views: list[dict]) -> list[dict]:
    order: list[str] = []
    table: dict[str, dict] = {}
    if run.terminal:
        for p in run.terminal["phases"]:
            t = p.get("title") or ""
            if t not in table:
                order.append(t)
                table[t] = _phase_row(len(order), t)
    for a in agent_views:
        t = a.get("phase") or ""
        if t not in table:
            order.append(t)
            table[t] = _phase_row(len(order), t)
        row = table[t]
        row["agents_total"] += 1
        if a["status"] == st.FINISHED:
            if a.get("outcome") == "completed":
                row["agents_done"] += 1
            else:
                row["agents_error"] += 1
        else:
            row["agents_running"] += 1
    return [table[t] for t in order]


def _phase_row(i: int, title: str) -> dict:
    return {"index": i, "title": title or None, "agents_total": 0, "agents_done": 0, "agents_error": 0, "agents_running": 0}


def _tokens(state: TranscriptState, exact: int | None, source: str | None) -> dict:
    ctx = state.last_ctx
    v = {"value": ctx, "exact": False, "ctx": ctx, "sum_out_observed": state.sum_out, "source": "tail"}
    if isinstance(exact, int):
        v.update(value=exact, exact=True, source=source)
    return v


def _tool_calls(t: Tracked, exact: int | None) -> dict:
    if isinstance(exact, int):
        return {"value": exact, "exact": True}
    ids = t.state.tool_ids
    return {"value": len(ids), "exact": ids.exact and (t.bf == "done" or (t.first_done and t.reader.first_start == 0))}


def _last_tool(state: TranscriptState) -> dict | None:
    lt = state.last_tool
    if not lt:
        return None
    return {"name": lt["name"], "arg": lt["arg"], "ok": lt["ok"], "ts_ms": lt["ts_ms"]}


def _span(a: int | None, b: int | None) -> int | None:
    return b - a if a is not None and b is not None else None


def _short(v: object) -> str | None:
    return field(v, 32) if isinstance(v, str) else None


def _bump(counts: dict, status: str) -> None:
    if status in ("running", "waiting", "stalled"):
        counts[status] += 1


def _shown(view: dict, now_ms: int) -> bool:
    status = view["status"]
    if status in st.ACTIVE_STATES:
        return True
    ref = view.get("finished_ms") or view.get("last_write_ms") or 0
    age = (now_ms - ref) / 1000
    if status == st.FINISHED:
        return age <= FINISHED_KEEP_S
    if status == st.ORPHANED:
        return age <= STALE_KEEP_S
    return False


# Running and waiting alternate after 60 quiet seconds. Equal ranks prevent row jumps.
_ORDER = {"stalled": 0, "running": 1, "waiting": 1, "orphaned": 2, "finished": 3}


def _agent_sort_key(v: dict):
    return (_ORDER.get(v["status"], 5), v.get("started_ms") or 0)


def _session_sort_key(s: dict):
    c = s["counts"]
    active = c["running"] + c["waiting"] + c["stalled"] + c["bg_running"] > 0 or s["state"] == "busy"
    calm = c["stalled"] == 0 and s["main"]["status"] != "stalled"
    return (calm, not active, s["live"] is not True, -(s["last_activity_ms"] or 0))


def _projects(sessions: list[dict]) -> list[dict]:
    out: dict[str, dict] = {}
    for s in sessions:
        p = out.setdefault(
            s["project_key"],
            {"key": s["project_key"], "name": s.get("project_name"), "cwd_display": s.get("cwd_display"), "session_ids": []},
        )
        p["session_ids"].append(s["id"])
    rows = list(out.values())
    for p in rows:
        if model.is_denied(p.get("name")):
            p["name"] = PRIVATE
        if model.is_denied(p.get("cwd_display")):
            p["cwd_display"] = PRIVATE
    return rows


def read_detail(path: str, idx_owner: str | None, end: int | None = None) -> TranscriptState | None:
    """Dedicated detail reread with a separate reader, not the tick cache. Stop at end when supplied."""
    state = TranscriptState(idx_owner, SessionIndex())
    reader = IncrementalReader(path)
    try:
        s = os.stat(path)
        if end is not None:
            s = SimpleNamespace(st_size=min(s.st_size, end), st_ino=s.st_ino, st_mtime_ns=s.st_mtime_ns)
        lines = reader.poll(s)
    except OSError:
        return None
    for ln in lines:
        if is_blob_line(ln):
            continue
        rec = loads_line(ln)
        if rec is not None:
            try:
                state.feed(rec)
            except Exception:
                continue
    return state

