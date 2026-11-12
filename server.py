"""Agent Watch entry point: HTTP, scanner thread, single instance, and stop file. Source trees are read-only; writes are confined to the state directory."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import select
import socket
import socketserver
import sys
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

PACKAGE_DIR = Path(__file__).resolve().parent
if str(PACKAGE_DIR) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIR))

import model  # noqa: E402
import winproc  # noqa: E402
from collect_claude import ClaudeCollector, Stats, read_detail  # noqa: E402
from collect_codex import CodexCollector  # noqa: E402
from config import (  # noqa: E402
    AGENT_SCHEMA,
    BACKOFF_MAX_S,
    BACKFILL_TICK_CAP,
    DETAIL_CACHE_S,
    DETAIL_MIN_INTERVAL_S,
    DISCOVERY_INTERVAL_S,
    FAST_TICK_MS,
    FAST_TICK_RUN,
    IDLE_TICK_S,
    LOG_MAX_BYTES,
    LOG_REPEAT_S,
    MAX_HANDLERS,
    OBSERVER_TIMEOUT_S,
    REQUEST_DEADLINE_S,
    SLOW_TICK_MS,
    SLOW_TICK_RUN,
    STATE_SCHEMA,
    TICK_READ_CAP,
    VERSION,
    Paths,
    Settings,
)
from masking import PRIVATE, is_denied, path_display  # noqa: E402
from tailreader import Budget  # noqa: E402

DEFAULT_PORT = 8810

EXIT_USAGE = 2
EXIT_ALREADY_RUNNING = 3
EXIT_BIND_FAILED = 4

SID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
AID_RE = re.compile(r"^(main|a[0-9a-f]{8,40})$")
THREAD_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
STOP_FILE = "agent_watch.stop"
LOG_FILE = "agent_watch.log"
RUN_FILE = "run.json"
TICK_HUNG_MS = 30_000
REFUSE_WAIT_S = 0.1  # Maximum time one refused connection can occupy the accept thread.
LOG_SIGNATURES_MAX = 256
BUSY_BODY = b'{"error":"busy"}'
BUSY_RESPONSE = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Content-Type: application/json; charset=utf-8\r\n"
    b"Content-Length: " + str(len(BUSY_BODY)).encode("ascii") + b"\r\n"
    b"Connection: close\r\n"
    b"Retry-After: 1\r\n"
    b"X-Content-Type-Options: nosniff\r\n"
    b"Referrer-Policy: no-referrer\r\n"
    b"X-Frame-Options: DENY\r\n"
    b"Cache-Control: no-store\r\n"
    b"Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n"
    b"\r\n" + BUSY_BODY
)


class Log:
    """Log each error signature at most once per ten minutes; never retain transcript text."""

    def __init__(self, state_dir: Path):
        self.path = state_dir / LOG_FILE
        self.seen: dict[tuple, list] = {}
        self.lock = threading.Lock()

    def _write(self, line: str) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size > LOG_MAX_BYTES:
                os.replace(self.path, str(self.path) + ".old")
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass

    def info(self, what: str, detail: str = "") -> None:
        with self.lock:
            self._write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} INFO {what} {detail}".rstrip())

    def error(self, where: str, exc: BaseException) -> None:
        tb = exc.__traceback__
        file, lineno = "?", 0
        while tb is not None:
            file, lineno = os.path.basename(tb.tb_frame.f_code.co_filename), tb.tb_lineno
            tb = tb.tb_next
        sig = (where, type(exc).__name__, file, lineno)
        now = time.time()
        with self.lock:
            entry = self.seen.get(sig)
            if entry and now - entry[0] < LOG_REPEAT_S:
                entry[1] += 1
                return
            repeat = entry[1] if entry else 0
            if len(self.seen) >= LOG_SIGNATURES_MAX:
                self.seen.clear()
            self.seen[sig] = [now, 0]
            self._write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} ERROR {where} {type(exc).__name__} {file}:{lineno} repeat={repeat}")


class Snapshot:
    """Immutable snapshot read by HTTP threads."""

    __slots__ = ("etag", "body", "index", "codex_index", "tick_mono")

    def __init__(self, etag: str, body: bytes, index: dict, codex_index: dict, tick_mono: float):
        self.etag = etag
        self.body = body
        self.index = index
        self.codex_index = codex_index
        self.tick_mono = tick_mono


class Scanner(threading.Thread):
    def __init__(self, paths: Paths, settings: Settings, log: Log):
        super().__init__(name="agent-watch-scan", daemon=True)
        self.paths = paths
        self.settings = settings
        self.log = log
        self.stats = Stats()
        self.claude = ClaudeCollector(paths, settings, self.stats, log)
        self.codex = CodexCollector(paths, self.stats, log)
        self.wake = threading.Event()
        self.stop_ev = threading.Event()
        self.boot = secrets.token_hex(8)  # Avoid ETag collisions across restarts.
        self.snapshot = Snapshot(f'"{self.boot}-0"', b'{"schema":"' + STATE_SCHEMA.encode() + b'","starting":true}', {}, {}, time.monotonic())
        self.version = 0
        self.hash = None
        self.last_disc = 0.0
        self.last_req = time.monotonic() - OBSERVER_TIMEOUT_S - 1
        self.ticks = deque(maxlen=128)
        self.last_tick_ms = 0.0
        self.factor = 1
        self.slow_run = 0
        self.fast_run = 0
        self.started_mono = time.monotonic()
        self.tick_count = 0
        self.first_tick_ms: float | None = None

    @property
    def mode(self) -> str:
        return "active" if time.monotonic() - self.last_req < OBSERVER_TIMEOUT_S else "idle"

    def touch(self) -> None:
        """An observer returned; wake the tick immediately."""
        was_idle = self.mode == "idle"
        self.last_req = time.monotonic()
        if was_idle:
            self.wake.set()

    def interval(self) -> float:
        base = self.settings.tick_s * self.factor
        if self.mode == "idle":
            base = max(base, IDLE_TICK_S)
        return min(base, max(BACKOFF_MAX_S, IDLE_TICK_S))

    def run(self) -> None:
        while not self.stop_ev.is_set():
            t0 = time.perf_counter()
            try:
                self.tick_once()
            except Exception as e:  # Keep the scan thread alive.
                self.stats.parse_errors += 1
                self.log.error("tick", e)
            ms = (time.perf_counter() - t0) * 1000
            if self.first_tick_ms is None:
                self.first_tick_ms = ms  # The largest tick combines discovery and initial tail reads.
            self.last_tick_ms = ms
            self.ticks.append(ms)
            self._backoff(ms)
            self.wake.wait(self.interval())
            self.wake.clear()

    def _backoff(self, ms: float) -> None:
        if ms > SLOW_TICK_MS:
            self.slow_run += 1
            self.fast_run = 0
        elif ms < FAST_TICK_MS:
            self.fast_run += 1
            self.slow_run = 0
        else:
            self.slow_run = self.fast_run = 0
        if self.slow_run >= SLOW_TICK_RUN:
            self.factor = min(self.factor * 2, int(BACKOFF_MAX_S / max(self.settings.tick_s, 0.1)) or 1)
            self.slow_run = 0
        if self.fast_run >= FAST_TICK_RUN:
            self.factor = 1
            self.fast_run = 0

    def tick_once(self) -> None:
        t0 = time.perf_counter()
        now_ms = int(time.time() * 1000)
        budget = Budget(TICK_READ_CAP)
        mono = time.monotonic()
        if self.last_disc == 0.0 or mono - self.last_disc >= DISCOVERY_INTERVAL_S:
            self.last_disc = mono
            self._guard("discover_claude", self.claude.discover, now_ms, budget)
            self._guard("discover_codex", self.codex.discover, now_ms, budget)
        self._guard("tick_claude", self.claude.tick, now_ms, budget)
        self._guard("tick_codex", self.codex.tick, now_ms, budget)
        self._publish(now_ms)
        self.tick_count += 1
        if (time.perf_counter() - t0) * 1000 < FAST_TICK_MS and self.claude.backfill.pending():
            self._guard("backfill", self.claude.backfill.run, BACKFILL_TICK_CAP)

    def _guard(self, where: str, fn, *args) -> None:
        try:
            fn(*args)
        except Exception as e:
            self.stats.parse_errors += 1
            self.log.error(where, e)

    def _publish(self, now_ms: int) -> None:
        built = self.claude.build(now_ms)
        runs, usage, codex_index = self.codex.build(now_ms)
        sessions = built["sessions"]
        bg = built["bg_tasks"]
        counts = {
            "sessions_live": sum(1 for s in sessions if s["live"] is True),
            "sessions_busy": sum(1 for s in sessions if s["state"] == "busy" and s["live"] is True),
            "agents_running": sum(s["counts"]["running"] + s["counts"]["waiting"] for s in sessions),
            "agents_stalled": sum(s["counts"]["stalled"] for s in sessions)
            + sum(1 for s in sessions if s["live"] is True and s["main"]["status"] == "stalled"),
            "workflows_running": sum(
                1 for s in sessions for w in s["workflows"] if w["status"] in ("running", "waiting", "stalled")
            ),
            "codex_running": sum(1 for r in runs if r["status"] in ("running", "waiting")),
            "bg_running": sum(s["counts"]["bg_running"] for s in sessions),
            "bg_unknown": sum(1 for b in bg if b["status"] == "unknown"),
        }
        state = {
            "schema": STATE_SCHEMA,
            "server": {
                "version": VERSION,
                "now_ms": now_ms,
                "state_version": 0,
                "mode": "active",
                "truncated": self.claude.truncated,
                "backfill_pct": self.claude.backfill.pct(),
                "warnings": [],
            },
            "counts": counts,
            "codex_usage": usage,
            "projects": built["projects"],
            "sessions": sessions,
            "codex_runs": runs,
            "bg_tasks": bg,
        }
        model.note_caps(state, self.claude.hot_deferred, self.codex.omitted)
        body = model.finalize_json(state)
        index = built["index"]
        if state["server"].get("omitted"):
            index, codex_index = model.reachable_only(state, index, codex_index)
        h = model.content_hash(body)
        if h != self.hash:
            self.hash = h
            self.version += 1
        body = body.replace(b'"state_version":0', b'"state_version":%d' % self.version, 1)
        self.snapshot = Snapshot(f'"{self.boot}-{self.version}"', body, index, codex_index, time.monotonic())

    def healthz(self) -> tuple[int, dict]:
        age = int((time.monotonic() - self.snapshot.tick_mono) * 1000)
        ticks = sorted(self.ticks)
        p95 = ticks[int(len(ticks) * 0.95) - 1] if ticks else 0
        ok = age <= TICK_HUNG_MS
        return (200 if ok else 503), {
            "ok": ok,
            "version": VERSION,
            "uptime_s": int(time.monotonic() - self.started_mono),
            "last_tick_age_ms": age,
            "tick_interval_ms": int(self.interval() * 1000),
            "first_tick_ms": round(self.first_tick_ms, 1) if self.first_tick_ms is not None else None,
            "last_tick_ms": round(self.last_tick_ms, 1),
            "p95_tick_ms": round(p95, 1),
            "mode": self.mode,
            "hot_files": self.claude.hot_count,
            "hot_deferred": self.claude.hot_deferred,
            "hot_lag_ticks": self.claude.hot_lag,
            "rss_mb": winproc.rss_mb(),
            "peak_rss_mb": winproc.peak_rss_mb(),
            "bad_lines": self.stats.bad_lines,
            "skipped_lines": self.stats.skipped_lines,
            "parse_errors": self.stats.parse_errors,
            "backfill_pct": self.claude.backfill.pct(),
            "tick_count": self.tick_count,
        }


class DetailReader:
    """Rate-limited detail rereads for finished entries."""

    def __init__(self):
        self.lock = threading.Lock()
        self.cache: dict[tuple, tuple[float, list]] = {}
        self.last = 0.0

    def events(self, path: str, owner, end: int | None = None) -> list[dict] | None:
        now = time.monotonic()
        key = (path, end)
        with self.lock:
            hit = self.cache.get(key)
            if hit and now - hit[0] < DETAIL_CACHE_S:
                return hit[1]
            if now - self.last < DETAIL_MIN_INTERVAL_S:
                return hit[1] if hit else None
            self.last = now
        state = read_detail(path, owner, end)
        events = list(state.events) if state else []
        with self.lock:
            self.cache[key] = (now, events)
            if len(self.cache) > 64:
                self.cache.pop(next(iter(self.cache)))
        return events


class WatchServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 32

    def __init__(self, addr, scanner: Scanner, index_html: bytes, allow_lan: bool, log: Log):
        self.scanner = scanner
        self.index_html = index_html
        self.allow_lan = allow_lan
        self.log = log
        self.detail = DetailReader()
        self.bind_host = addr[0]
        self.allowed_hosts: set[str] = set()
        self.allowed_origins: set[str] = set()
        self.slots = threading.BoundedSemaphore(MAX_HANDLERS)
        self.deadlines: dict[socket.socket, float] = {}
        self.deadlines_lock = threading.Lock()
        super().__init__(addr, Handler)

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        # Bypass http.server server_bind to avoid getfqdn and possible DNS queries.
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        self.server_name = host
        self.server_port = port
        names = {"127.0.0.1", "localhost"}
        if self.allow_lan:
            if self.bind_host in ("0.0.0.0", ""):
                try:
                    names.update(socket.gethostbyname_ex(socket.gethostname())[2])
                except OSError:
                    pass
            else:
                names.add(self.bind_host)
        self.allowed_hosts = {f"{n}:{port}" for n in names}
        self.allowed_origins = {f"http://{n}:{port}" for n in names}

    def process_request(self, request, client_address) -> None:
        """Acquire a slot before starting a thread; otherwise return 503 from the accept thread and close."""
        if not self.slots.acquire(blocking=False):
            self._refuse(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.deadlines_lock:
                self.deadlines.pop(request, None)
            self.slots.release()

    def _refuse(self, request) -> None:
        """Read request bytes before sending 503; unread bytes could trigger a reset that hides the response."""
        try:
            request.setblocking(False)
            # Wait only once with select, bounding accept-thread delay by REFUSE_WAIT_S.
            if select.select([request], [], [], REFUSE_WAIT_S)[0]:
                request.recv(65536)
            request.send(BUSY_RESPONSE)
        except OSError:
            pass
        self.shutdown_request(request)

    def arm_deadline(self, connection) -> None:
        with self.deadlines_lock:
            self.deadlines[connection] = time.monotonic() + REQUEST_DEADLINE_S

    def service_actions(self) -> None:
        """Called by serve_forever each poll; close overdue connections to wake handler threads."""
        now = time.monotonic()
        with self.deadlines_lock:
            late = [c for c, t in self.deadlines.items() if t <= now]
            for c in late:
                del self.deadlines[c]
        for c in late:
            try:
                c.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def handle_error(self, request, client_address) -> None:
        exc = sys.exc_info()[1]
        if exc is not None and not isinstance(exc, (ConnectionError, TimeoutError)):
            self.log.error("http", exc)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    default_request_version = "HTTP/1.1"  # Include security headers on errors; HTTP/0.9 cannot carry headers.
    server_version = "AgentWatch"
    sys_version = ""
    timeout = 15

    def log_message(self, format, *args) -> None:  # Do not log URLs or raw text.
        return

    def handle_one_request(self) -> None:
        # Socket timeouts only bound inter-byte gaps; this deadline also covers trickle requests.
        self.server.arm_deadline(self.connection)
        super().handle_one_request()

    def version_string(self) -> str:
        return "AgentWatch"

    def _security_headers(self, nonce: str) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
            "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        )

    def _send(self, code: int, body: bytes, ctype: str, nonce: str | None = None, extra: dict | None = None) -> None:
        self.send_response(code)
        self._security_headers(nonce or secrets.token_urlsafe(16))
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, obj: dict, extra: dict | None = None) -> None:
        self._send(code, model.dumps(obj), "application/json; charset=utf-8", extra=extra)

    def _deny(self, code: int, msg: str) -> None:
        # Unread rejected request bodies would become the next request if the connection were reused.
        self.close_connection = True
        self._json(code, {"error": msg}, extra={"Connection": "close"})

    def send_error(self, code, message=None, explain=None) -> None:
        """Use JSON with the same security headers instead of default HTTP error pages."""
        self._deny(code, "bad request")

    def _check(self) -> bool:
        host = self.headers.get("Host")
        if host not in self.server.allowed_hosts:
            self._deny(403, "host")
            return False
        sfs = self.headers.get("Sec-Fetch-Site")
        if sfs is not None and sfs not in ("same-origin", "none"):
            self._deny(403, "fetch-site")
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin not in self.server.allowed_origins:
            self._deny(403, "origin")
            return False
        return True

    def do_GET(self) -> None:
        if not self._check():
            return
        try:
            self._route()
        except (ConnectionError, TimeoutError):
            raise
        except Exception as e:
            self.server.log.error("route", e)
            self._deny(500, "internal")

    do_HEAD = do_GET

    def _reject_method(self) -> None:
        self.close_connection = True
        self.send_response(405)
        self._security_headers(secrets.token_urlsafe(16))
        self.send_header("Allow", "GET, HEAD")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_TRACE = do_CONNECT = _reject_method

    def _route(self) -> None:
        raw_path = self.path
        parts = urlsplit(raw_path)
        path = parts.path
        q = parse_qs(parts.query, keep_blank_values=True)
        if path == "/":
            nonce = secrets.token_urlsafe(16)
            body = self.server.index_html.replace(b"__NONCE__", nonce.encode("ascii"))
            self._send(200, body, "text/html; charset=utf-8", nonce=nonce)
        elif path == "/healthz":
            code, obj = self.server.scanner.healthz()
            self._json(code, obj)
        elif path == "/api/state":
            self._state()
        elif path == "/api/agent":
            self._agent(q)
        elif path == "/api/codex":
            self._codex(q)
        else:
            self._deny(404, "not found")

    def _state(self) -> None:
        sc = self.server.scanner
        sc.touch()
        snap = sc.snapshot
        if self.headers.get("If-None-Match") == snap.etag:
            self.send_response(304)
            self._security_headers(secrets.token_urlsafe(16))
            self.send_header("ETag", snap.etag)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._send(200, snap.body, "application/json; charset=utf-8", extra={"ETag": snap.etag})

    def _agent(self, q: dict) -> None:
        sid = (q.get("session") or [""])[0]
        aid = (q.get("agent") or [""])[0]
        if not SID_RE.match(sid) or not AID_RE.match(aid):
            self._deny(400, "bad parameter")
            return
        sc = self.server.scanner
        entry = sc.snapshot.index.get((sid, aid))
        if entry is None:
            self._deny(404, "unknown agent")
            return
        view = entry["view"]
        private = bool(view.get("private"))
        events = entry["events"]
        if events is None:
            # Reread only retired completed entries, up to completion size, using snapshot privacy.
            events = model.redact_events(self.server.detail.events(entry["path"], aid, entry["end"]) or [], private)
        pd = path_display(entry["path"])
        self._json(
            200,
            {
                "schema": AGENT_SCHEMA,
                "session_id": sid,
                "agent_id": aid,
                "header": view,
                "events": events,
                "path_display": PRIVATE if private or is_denied(pd) else pd,
            },
        )

    def _codex(self, q: dict) -> None:
        thread = (q.get("thread") or [""])[0]
        if not THREAD_RE.match(thread):
            self._deny(400, "bad parameter")
            return
        entry = self.server.scanner.snapshot.codex_index.get(thread)
        if entry is None:
            self._deny(404, "unknown thread")
            return
        self._json(200, {"schema": AGENT_SCHEMA, "thread_id": thread, "header": entry["view"], "events": entry["events"]})


class QuietArgumentParser(argparse.ArgumentParser):
    """pythonw sets stdout and stderr to None."""

    def _print_message(self, message, file=None) -> None:
        if sys.stdout is None or sys.stderr is None:
            return
        super()._print_message(message, file)


def is_loopback_host(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class App:
    def __init__(self, paths: Paths, settings: Settings, host: str = "127.0.0.1", port: int = DEFAULT_PORT, allow_lan: bool = False):
        self.paths = paths
        self.settings = settings
        self.host = host
        self.port = port
        self.allow_lan = allow_lan
        paths.state_dir.mkdir(parents=True, exist_ok=True)
        self.log = Log(paths.state_dir)
        self.scanner = Scanner(paths, settings, self.log)
        self.server: WatchServer | None = None
        self.serve_thread: threading.Thread | None = None
        self.mutex = None
        self.stop_requested = threading.Event()

    def bind(self) -> None:
        html = (PACKAGE_DIR / "static" / "index.html").read_bytes()
        self.server = WatchServer((self.host, self.port), self.scanner, html, self.allow_lan, self.log)
        self.port = self.server.server_port

    def start(self) -> None:
        self.scanner.start()
        self.serve_thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.5}, name="agent-watch-http", daemon=True)
        self.serve_thread.start()
        self.write_run()

    def write_run(self, stopped: bool = False) -> None:
        pid = os.getpid()
        payload = {
            "pid": pid,
            "port": self.port,
            "create_filetime": winproc.process_create_filetime(pid),
            "started_ms": getattr(self, "started_ms", None) or int(time.time() * 1000),
            "version": VERSION,
        }
        self.started_ms = payload["started_ms"]
        if stopped:
            payload["stopped_ms"] = int(time.time() * 1000)
        target = self.paths.state_dir / RUN_FILE
        tmp = self.paths.state_dir / (RUN_FILE + ".tmp")
        try:
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            os.replace(tmp, target)
        except OSError as e:
            self.log.error("write_run", e)

    def consume_stop_file(self) -> bool:
        stop = self.paths.state_dir / STOP_FILE
        if not stop.exists():
            return False
        stamp = time.strftime("%Y%m%d_%H%M%S")
        try:
            os.replace(stop, self.paths.state_dir / f"{STOP_FILE}.consumed.{stamp}")
        except OSError as e:
            self.log.error("consume_stop", e)
        return True

    def run_forever(self) -> None:
        while not self.stop_requested.wait(0.5):
            if self.consume_stop_file():
                self.log.info("stop_file")
                break
        self.stop()

    def stop(self) -> None:
        self.scanner.stop_ev.set()
        self.scanner.wake.set()
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        self.write_run(stopped=True)


def load_title_denylist(path: str | None) -> None:
    """Combine environment terms with a UTF-8 file; hash starts a comment."""
    from masking import configure_title_denylist

    terms = os.environ.get("AGENT_WATCH_TITLE_DENYLIST", "").split(",")
    if path:
        text = Path(path).read_text(encoding="utf-8-sig")
        terms.extend(line.split("#", 1)[0] for line in text.splitlines())
    configure_title_denylist(terms)


def build_parser() -> argparse.ArgumentParser:
    p = QuietArgumentParser(description="Agent Watch: read-only local dashboard")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--host", default="127.0.0.1", help="Default: 127.0.0.1; non-loopback addresses require --allow-lan")
    p.add_argument("--allow-lan", action="store_true", help="Explicitly allow binding to a non-loopback address")
    p.add_argument("--window-hours", type=float, default=None, help="Recent-session window in hours (default: 24)")
    p.add_argument("--interval", type=float, default=None, help="Tick interval in seconds (default: 2)")
    p.add_argument("--state-dir", default=None)
    p.add_argument("--claude-home", default=None)
    p.add_argument("--codex-home", default=None)
    p.add_argument("--temp-claude", default=None)
    p.add_argument("--title-denylist-file", metavar="PATH", help="UTF-8 title terms, one per line; # starts a comment")
    return p


def _report(paths_state: Path, msg: str) -> None:
    if sys.stderr is not None:
        print(msg, file=sys.stderr)
    try:
        paths_state.mkdir(parents=True, exist_ok=True)
        Log(paths_state).info("startup", msg)
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        load_title_denylist(args.title_denylist_file)
    except (OSError, UnicodeError):
        parser.error("Cannot read title denylist file as UTF-8")
    paths = Paths()
    if args.state_dir:
        paths.state_dir = Path(args.state_dir)
    if args.claude_home:
        paths.claude_home = Path(args.claude_home)
    if args.codex_home:
        paths.codex_home = Path(args.codex_home)
    if args.temp_claude:
        paths.temp_claude = Path(args.temp_claude)
    settings = Settings()
    if args.window_hours is not None:
        settings.window_h = max(0.1, args.window_hours)
    if args.interval is not None:
        settings.tick_s = max(0.5, args.interval)
    if not is_loopback_host(args.host) and not args.allow_lan:
        _report(paths.state_dir, f"Refused: non-loopback address {args.host} requires --allow-lan.")
        return EXIT_USAGE
    mutex = None
    if args.port != 0:
        mutex = winproc.acquire_single_instance(f"Local\\AgentWatch_{args.port}")
        if mutex is None:
            _report(paths.state_dir, f"Already running on port {args.port}")
            return EXIT_ALREADY_RUNNING
    app = App(paths, settings, args.host, args.port, args.allow_lan)
    app.mutex = mutex
    try:
        app.bind()
    except OSError:
        _report(paths.state_dir, f"Cannot bind port: {args.port}")
        return EXIT_BIND_FAILED
    app.consume_stop_file()  # Consume any old stop file before starting so it cannot immediately stop this run.
    app.start()
    app.log.info("started", f"port={app.port}")
    app.run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
