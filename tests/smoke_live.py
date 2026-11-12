"""Manual live smoke test. Reads real data but reports only short IDs and metrics. Independent scanning does not import collectors, parsers, readers, or status logic. Stops only its own process handle or uses the stop file. Usage: python -X utf8 -B tests/smoke_live.py [--ui-only] [--backfill-wait 300] [--shots <dir>]"""
from __future__ import annotations

import argparse
import ctypes
import glob
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from ctypes import wintypes
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
SHOTS_DEFAULT = PKG.parent / "shots"
HOME = Path.home()
CLAUDE = HOME / ".claude"
CODEX = HOME / ".codex"
SLUG_RE = re.compile(r"[^A-Za-z0-9]")
TOOL_PAT = b'"type":"tool_use","id":"toolu_'


def out(*a):
    print(*a, flush=True)


# ---- Process metrics (independent ctypes) ----
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
k32.OpenProcess.restype = wintypes.HANDLE
k32.CloseHandle.argtypes = (wintypes.HANDLE,)
k32.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
k32.GetProcessTimes.restype = wintypes.BOOL
k32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))


def ft(f):
    return (f.dwHighDateTime << 32) | f.dwLowDateTime


def proc_times(pid):
    h = k32.OpenProcess(0x1000, False, pid)
    if not h:
        return None
    try:
        c, e, ke, us = (wintypes.FILETIME() for _ in range(4))
        if not k32.GetProcessTimes(h, *(ctypes.byref(x) for x in (c, e, ke, us))):
            return None
        code = wintypes.DWORD()
        k32.GetExitCodeProcess(h, ctypes.byref(code))
        return {"create": ft(c), "cpu_s": (ft(ke) + ft(us)) / 1e7, "alive": code.value == 259}
    finally:
        k32.CloseHandle(h)


def tasklist_rss_mb(pid):
    r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, timeout=20)
    text = r.stdout.decode("cp949", "replace")
    m = re.search(r'"([\d,]+) K"', text)
    return round(int(m.group(1).replace(",", "")) / 1024, 1) if m else None


def cpu_over(pid, seconds, poll=None):
    a = proc_times(pid)
    t0 = time.perf_counter()
    while time.perf_counter() - t0 < seconds:
        if poll:
            poll()
            time.sleep(2)
        else:
            time.sleep(min(1, seconds))
    b = proc_times(pid)
    span = time.perf_counter() - t0
    return round((b["cpu_s"] - a["cpu_s"]) * 100 / span, 2)


# ---- HTTP ----
def http_get(port, path, headers=None, timeout=15):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def state(port):
    return json.loads(http_get(port, "/api/state")[1])


def health(port):
    return json.loads(http_get(port, "/healthz")[1])


# ---- Independent scan ----
def tail_records(path, n=6_000_000):
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        f.seek(max(0, size - n))
        data = f.read()
    lines = data.split(b"\n")
    if size > n:
        lines = lines[1:]
    recs = []
    for ln in lines:
        if not ln or b"api-request-blob" in ln[:120]:
            continue
        try:
            r = json.loads(ln.decode("utf-8", "replace"))
        except ValueError:
            continue
        if isinstance(r, dict):
            recs.append(r)
    return recs


def unresolved_tool(path):
    """Unresolved tool_use name from the last message.id, or None if complete."""
    pend = {}
    cur = None
    for r in tail_records(path):
        t = r.get("type")
        if t == "assistant":
            msg = r.get("message") or {}
            mid = msg.get("id")
            if mid != cur:
                pend = {}
                cur = mid
            content = msg.get("content")
            if isinstance(content, list):
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "tool_use":
                        pend[b.get("id")] = b.get("name")
            sr = msg.get("stop_reason")
            if sr not in (None, "", "tool_use"):
                pend = {}
        elif t == "user":
            c = (r.get("message") or {}).get("content")
            if isinstance(c, list):
                got = False
                for b in c:
                    if isinstance(b, dict) and b.get("type") == "tool_result":
                        pend.pop(b.get("tool_use_id"), None)
                        got = True
                if not got:
                    pend = {}
            else:
                pend = {}
    return list(pend.values())[-1] if pend else None


def alive(pid, proc_start):
    p = proc_times(pid)
    return bool(p and p["alive"] and str(p["create"]) == str(proc_start))


def registry_scan():
    out_ = {}
    for p in glob.glob(str(CLAUDE / "sessions" / "*.json")):
        if not re.fullmatch(r"\d+\.json", os.path.basename(p)):
            continue
        try:
            d = json.load(open(p, encoding="utf-8"))
        except (OSError, ValueError):
            continue
        sid = d.get("sessionId")
        if sid and alive(d.get("pid"), d.get("procStart")):
            out_[sid] = {"status": d.get("status"), "cwd": d.get("cwd")}
    return out_


def main_path(sid, cwd):
    slug = SLUG_RE.sub("-", cwd or "").lower()
    for d in os.listdir(CLAUDE / "projects"):
        if d.lower() == slug:
            p = CLAUDE / "projects" / d / f"{sid}.jsonl"
            if p.exists():
                return p
    hits = glob.glob(str(CLAUDE / "projects" / "*" / f"{sid}.jsonl"))
    return Path(hits[0]) if hits else None


def recent_agents(session_dir, minutes=15):
    """Agent JSONL files updated within N minutes without completion signals."""
    rows = []
    cut = time.time() - minutes * 60
    pats = [os.path.join(session_dir, "subagents", "agent-*.jsonl"), os.path.join(session_dir, "subagents", "workflows", "wf_*", "agent-*.jsonl")]
    for pat in pats:
        for p in glob.glob(pat):
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_mtime < cut:
                continue
            aid = os.path.basename(p)[6:-6]
            finished = False
            mp = p[:-6] + ".meta.json"
            try:
                finished = json.load(open(mp, encoding="utf-8")).get("finished") is True
            except (OSError, ValueError):
                pass
            run_dir = os.path.dirname(p)
            if "workflows" in run_dir:
                run_id = os.path.basename(run_dir)
                sd = run_dir.split(os.sep + "subagents" + os.sep)[0]
                if os.path.exists(os.path.join(sd, "workflows", run_id + ".json")):
                    finished = True
                jp = os.path.join(run_dir, "journal.jsonl")
                try:
                    data = open(jp, "rb").read()
                    if (b'"type":"result"' in data or b'"type":"failed"' in data) and aid.encode() in data:
                        for ln in data.split(b"\n"):
                            if aid.encode() in ln and (b'"type":"result"' in ln or b'"type":"failed"' in ln):
                                finished = True
                except OSError:
                    pass
            if not finished:
                recs = tail_records(p, 512 * 1024)
                for r in reversed(recs):
                    t = r.get("type")
                    if t == "assistant":
                        sr = (r.get("message") or {}).get("stop_reason")
                        if sr not in (None, "", "tool_use"):
                            finished = True
                        break
                    if t == "user":
                        if r.get("toolEndsTurn"):
                            finished = True
                        break
            rows.append({"agent_id": aid, "finished": finished, "mtime": st.st_mtime, "path": p})
    return rows


def recent_terminals(session_dirs, limit=6):
    rows = []
    for sd in session_dirs:
        for p in glob.glob(os.path.join(sd, "workflows", "wf_*.json")):
            rows.append((os.path.getmtime(p), p, sd))
    rows.sort(reverse=True)
    return rows[:limit]


def codex_latest_percent():
    days = [time.strftime("%Y/%m/%d", time.localtime(time.time() - 86400 * i)) for i in range(3)]
    best = (None, None)
    for d in days:
        for p in glob.glob(str(CODEX / "sessions" / d / "rollout-*.jsonl")):
            size = os.path.getsize(p)
            with open(p, "rb") as f:
                f.seek(max(0, size - 256 * 1024))
                data = f.read()
            for ln in data.split(b"\n")[1:]:
                if b"rate_limits" not in ln or b"used_percent" not in ln:
                    continue
                try:
                    r = json.loads(ln)
                except ValueError:
                    continue
                pl = r.get("payload") or {}
                rl = pl.get("rate_limits")
                if isinstance(rl, dict) and isinstance(rl.get("primary"), dict):
                    ts = r.get("timestamp")
                    if best[0] is None or ts > best[0]:
                        best = (ts, rl["primary"].get("used_percent"))
    return best


def byte_tool_count(path):
    n = 0
    with open(path, "rb") as f:
        for ln in f:
            if b"api-request-blob" in ln[:120]:
                continue
            n += ln.count(TOOL_PAT)
    return n


def find_notification_tokens(path, agent_id):
    """Read authoritative task-notification token counts directly from the main tail."""
    for r in reversed(tail_records(path, 12_000_000)):
        text = None
        if r.get("type") == "user" and (r.get("origin") or {}).get("kind") == "task-notification":
            c = (r.get("message") or {}).get("content")
            text = c if isinstance(c, str) else None
        elif r.get("type") == "queue-operation":
            text = r.get("content") if isinstance(r.get("content"), str) else None
        if text and f"<task-id>{agent_id}</task-id>" in text:
            m = re.search(r"<subagent_tokens>(\d+)</subagent_tokens>", text.rsplit("</result>", 1)[-1])
            if m:
                return int(m.group(1))
    return None


# ---- Comparison ----
def verify(port, report):
    results = []

    def rec(name, ok, detail=""):
        results.append({"check": name, "ok": ok, "detail": detail})
        out(f"  [{'OK ' if ok else 'NG '}] {name}: {detail}")

    st = state(port)
    reg = registry_scan()
    by_id = {s["id"]: s for s in st["sessions"]}
    live_server = {s["id"] for s in st["sessions"] if s["live"] is True}
    rec("Live session set", set(reg) == live_server, f"Independent {len(reg)} / server {len(live_server)} / difference {len(set(reg) ^ live_server)}")

    busy = [sid for sid, d in reg.items() if d["status"] == "busy"]
    picks = (busy + [sid for sid in reg if sid not in busy])[:6]
    match = 0
    tried = 0
    for sid in picks:
        p = main_path(sid, reg[sid]["cwd"])
        s = by_id.get(sid)
        if p is None or s is None:
            continue
        tried += 1
        mt = int(os.stat(p).st_mtime * 1000)
        good = False
        for _ in range(3):
            tool = unresolved_tool(p)
            s = next((x for x in state(port)["sessions"] if x["id"] == sid), None)
            step = (s or {}).get("main", {}).get("step") or {}
            server_tool = step.get("tool") if step.get("kind") == "tool" else None
            if tool == server_tool:
                good = True
                break
            time.sleep(2.2)
        delta = abs((s["main"]["last_write_ms"] or 0) - mt) if s else None
        match += 1 if good else 0
        rec(f"Main step {sid[:8]}", good and delta is not None and delta <= 5000, f"Independent tool={tool} / server tool={server_tool} / mtime difference {delta}ms")

    sd_of = {}
    for sid, d in reg.items():
        p = main_path(sid, d["cwd"])
        if p is not None:
            sd_of[sid] = str(p)[:-6]
    indep_active = {}
    for sid, sd in sd_of.items():
        for a in recent_agents(sd):
            if not a["finished"]:
                indep_active[a["agent_id"]] = a
    server_active = {}
    for s in st["sessions"]:
        if s["id"] not in sd_of:
            continue
        for a in s["agents"]:
            if a["status"] in ("running", "waiting", "stalled"):
                server_active[a["agent_id"]] = a
        for w in s["workflows"]:
            for a in w["agents"]:
                if a["status"] in ("running", "waiting", "stalled"):
                    server_active[a["agent_id"]] = a
    diff = set(indep_active) ^ set(server_active)
    rec("Active agent count", abs(len(indep_active) - len(server_active)) <= 1, f"Independent {len(indep_active)} / server {len(server_active)} / difference {[x[:9] for x in list(diff)[:6]]}")

    # Current steps for three live agents.
    candidates = [a for a in server_active.values() if a["agent_id"] in indep_active]
    # Prioritize tool-running samples so tool status is checked, not just model waits.
    candidates.sort(key=lambda a: unresolved_tool(indep_active[a["agent_id"]]["path"]) is None)
    candidates = candidates[:6]
    report["tool_step_samples"] = sum(1 for a in candidates if unresolved_tool(indep_active[a["agent_id"]]["path"]) is not None)
    done = 0
    for a in candidates:
        if done >= 3:
            break
        aid = a["agent_id"]
        good = False
        for _ in range(3):
            tool = unresolved_tool(indep_active[aid]["path"])
            cur = None
            cst = state(port)
            for s in cst["sessions"]:
                for x in s["agents"] + [y for w in s["workflows"] for y in w["agents"]]:
                    if x["agent_id"] == aid:
                        cur = x
            if cur is None:
                break
            step = cur.get("step") or {}
            server_tool = step.get("tool") if step.get("kind") == "tool" else None
            if tool == server_tool:
                good = True
                break
            time.sleep(2.2)
        if cur is None:
            continue
        done += 1
        rec(f"Agent step {aid[:9]}", good, f"Independent tool={tool} / server tool={server_tool} ({step.get('kind')})")
    if done == 0:
        rec("Agent step", True, "No active agents to compare (skipped)")

    terms = recent_terminals(list(sd_of.values()))
    checked = 0
    for mtime, p, sd in terms:
        d = json.load(open(p, encoding="utf-8"))
        rid = d.get("runId")
        for s in st["sessions"]:
            for w in s["workflows"]:
                if w["run_id"] == rid:
                    checked += 1
                    ok = w["tokens"]["value"] == d.get("totalTokens") and w["agents_total"] == d.get("agentCount")
                    rec(f"terminal {rid[:12]}", ok, f"tokens {w['tokens']['value']}/{d.get('totalTokens')} agents {w['agents_total']}/{d.get('agentCount')}")
                    break
        if checked >= 2:
            break
    if checked == 0:
        rec("terminal", True, "No display items within 60 minutes (skipped)")

    a3 = 0
    a3_ok = 0
    for mtime, p, sd in terms[:3]:
        d = json.load(open(p, encoding="utf-8"))
        rid = d.get("runId")
        for pr in d.get("workflowProgress") or []:
            if pr.get("type") != "workflow_agent" or not pr.get("agentId"):
                continue
            ap = os.path.join(sd, "subagents", "workflows", rid, f"agent-{pr['agentId']}.jsonl")
            if not os.path.exists(ap):
                continue
            a3 += 1
            a3_ok += 1 if byte_tool_count(ap) == pr.get("toolCalls") else 0
            if a3 >= 12:
                break
        if a3 >= 12:
            break
    rec("Tool count from bytes", a3 == a3_ok, f"{a3_ok}/{a3} matched")

    exact = 0
    for s in st["sessions"]:
        if s["id"] not in sd_of:
            continue
        for a in s["agents"]:
            if a["tokens"].get("exact") and a["tokens"].get("source") == "notification":
                tok = find_notification_tokens(sd_of[s["id"]] + ".jsonl", a["agent_id"])
                if tok is not None:
                    exact += 1
                    rec(f"Authoritative tokens {a['agent_id'][:9]}", tok == a["tokens"]["value"], f"{tok}/{a['tokens']['value']}")
                    break
        if exact:
            break
    if not exact:
        rec("Authoritative tokens", True, "No displayed notification-based agents (skipped)")

    ts, pct = codex_latest_percent()
    cu = st.get("codex_usage") or {}
    w = (cu.get("windows") or [{}])[0]
    rec("Codex used_percent", pct == w.get("used_percent") or pct is None, f"Independent {pct} / server {w.get('used_percent')}")

    report["verify"] = results
    report["verify_passed"] = sum(1 for r in results if r["ok"])
    report["verify_total"] = len(results)
    report["counts"] = st["counts"]
    report["backfill_pct"] = st["server"]["backfill_pct"]


# ---- UI ----
def ui(port, report, shots: Path):
    from playwright.sync_api import Error as PwError, sync_playwright

    shots.mkdir(parents=True, exist_ok=True)
    res = {"shots": [], "console_errors": 0, "csp_violations": 0, "goto_retries": 0}

    def goto(page, url):
        # Memory pressure may briefly cause browser ERR_NO_BUFFER_SPACE; record retries in the report.
        for attempt in range(4):
            try:
                return page.goto(url)
            except PwError:
                if attempt == 3:
                    raise
                res["goto_retries"] += 1
                time.sleep(2)

    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        for (w, h) in ((1920, 1080), (1366, 768)):
            for scheme in ("light", "dark"):
                ctx = b.new_context(viewport={"width": w, "height": h}, color_scheme=scheme, device_scale_factor=1)
                page = ctx.new_page()
                errs = []
                page.on("console", lambda m, e=errs: e.append(m.text[:120]) if m.type == "error" else None)
                page.on("pageerror", lambda ex, e=errs: e.append(str(ex)[:120]))
                goto(page, f"http://127.0.0.1:{port}/")
                page.wait_for_selector("#updated:not(:empty)", timeout=20000)
                page.wait_for_timeout(1000)
                # Open the drawer if a first card exists.
                sw = page.evaluate("document.documentElement.scrollWidth")
                iw = page.evaluate("window.innerWidth")
                name = f"agent_watch_{w}x{h}_{scheme}.png"
                page.screenshot(path=str(shots / name), full_page=False)
                res["shots"].append(name)
                if (w, scheme) == (1366, "light"):
                    res["scroll_ok_1366"] = sw <= iw
                    res["scroll"] = [sw, iw]
                    res["cards_visible_1366"] = page.evaluate(
                        "[...document.querySelectorAll('.card')].filter(c=>{const r=c.getBoundingClientRect();return r.top>=0&&r.bottom<=innerHeight}).length"
                    )
                res["console_errors"] += len(errs)
                res["csp_violations"] += sum(1 for e in errs if "Content Security Policy" in e or "CSP" in e)
                if errs:
                    res.setdefault("first_errors", errs[:3])
                ctx.close()
        # Stop drawer polling.
        ctx = b.new_context(viewport={"width": 1366, "height": 768})
        page = ctx.new_page()
        reqs = []
        page.on("request", lambda r, q=reqs: q.append(r.url) if "/api/state" in r.url else None)
        goto(page, f"http://127.0.0.1:{port}/")
        page.wait_for_selector("#updated:not(:empty)", timeout=20000)
        page.wait_for_timeout(500)
        cards = page.locator(".card")
        res["cards"] = cards.count()
        if cards.count():
            cards.first.click()
            page.wait_for_timeout(1500)
            res["drawer_open"] = page.evaluate("document.getElementById('drawer').classList.contains('on')")
            res["drawer_events"] = page.evaluate("document.querySelectorAll('#d-events .ev').length")
            page.screenshot(path=str(shots / "agent_watch_drawer_1366.png"))
            res["shots"].append("agent_watch_drawer_1366.png")
            page.keyboard.press("Escape")
            res["drawer_closed_esc"] = not page.evaluate("document.getElementById('drawer').classList.contains('on')")
        page.evaluate("Object.defineProperty(document,'hidden',{configurable:true,get:()=>true});document.dispatchEvent(new Event('visibilitychange'))")
        page.wait_for_timeout(2500)
        before = len(reqs)
        page.wait_for_timeout(6000)
        res["requests_while_hidden"] = len(reqs) - before
        res["keyframes_in_doc"] = page.evaluate(
            "[...document.styleSheets].flatMap(s=>[...s.cssRules]).filter(r=>r.type===CSSRule.KEYFRAMES_RULE).length"
        )
        page.evaluate("Object.defineProperty(document,'hidden',{configurable:true,get:()=>false});document.dispatchEvent(new Event('visibilitychange'))")
        page.wait_for_timeout(2500)
        res["resumed_after_hidden"] = len(reqs) - before > 0
        ctx.close()
        b.close()
    report["ui"] = res
    out("  UI:", json.dumps({k: v for k, v in res.items() if k != "shots"}, ensure_ascii=False))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ui-only", action="store_true")
    ap.add_argument("--backfill-wait", type=int, default=420)
    ap.add_argument("--shots", default=str(SHOTS_DEFAULT))
    ap.add_argument("--port", type=int, default=None, help="Start on this port when supplied")
    args = ap.parse_args()
    stamp = time.strftime("%Y%m%d_%H%M%S")
    scratch = PKG / "tests" / "_scratch" / f"smoke_{stamp}"
    scratch.mkdir(parents=True, exist_ok=True)
    state_dir = scratch / "state"
    port = args.port or 8810
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        if args.port:
            raise SystemExit(f"Port {port} is in use")
        port = 0
    s.close()
    log = open(scratch / "server_stdout.log", "wb")
    cmd = [sys.executable, "-X", "utf8", "-B", str(PKG / "server.py"), "--port", str(port), "--state-dir", str(state_dir)]
    proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=str(PKG))
    report = {"stamp": stamp, "pid": proc.pid}
    out(f"Server started pid={proc.pid} port_req={port}")
    try:
        run = None
        t0 = time.time()
        while time.time() - t0 < 10 and run is None:
            try:
                run = json.loads((state_dir / "run.json").read_text(encoding="utf-8"))
            except (OSError, ValueError):
                time.sleep(0.1)
        if run is None:
            raise SystemExit("run.json missing")
        port = run["port"]
        report["port"] = port
        t0 = time.time()
        code = None
        while time.time() - t0 < 10:
            try:
                code = http_get(port, "/healthz", timeout=3)[0]
            except OSError:
                code = None
            if code == 200:
                break
            time.sleep(0.2)
        report["healthz_ms"] = int((time.time() - t0) * 1000)
        out(f"/healthz {code} ({report['healthz_ms']}ms) port={port}")
        for _ in range(100):
            st = state(port)
            if st.get("sessions"):
                break
            time.sleep(0.3)
        out("Initial /api/state counts:", st.get("counts"), "server:", {k: st["server"][k] for k in ("state_version", "backfill_pct", "mode")})
        first = health(port)
        report["healthz_first"] = first
        report["first_tick_ms"] = first.get("first_tick_ms")
        out("healthz:", first)
        if not args.ui_only:
            out("First comparison (backfill in progress)")
            first_report = {}
            verify(port, first_report)
            report["verify_early"] = first_report.get("verify")
            out("Waiting for backfill (polling every two seconds)")
            t0 = time.time()
            pct = 0
            while time.time() - t0 < args.backfill_wait:
                pct = state(port)["server"]["backfill_pct"]
                if pct >= 100:
                    break
                time.sleep(2)
            report["backfill_wait_s"] = int(time.time() - t0)
            report["backfill_final_pct"] = pct
            h = health(port)
            report["healthz_after_backfill"] = h
            out(f"Backfill {pct}% ({report['backfill_wait_s']}s) healthz={h}")
            out("Second comparison")
            verify(port, report)
            agents = []
            for x in state(port)["sessions"]:
                sid = x["id"]
                for a in x["agents"] + [y for w in x["workflows"] for y in w["agents"]]:
                    agents.append((a["status"] not in ("running", "waiting"), sid, a["agent_id"]))
            agents.sort()
            if agents:
                _, sid, aid = agents[0]
                c, b, _ = http_get(port, f"/api/agent?session={sid}&agent={aid}")
                d = json.loads(b)
                report["api_agent"] = {"code": c, "agent": aid[:9], "events": len(d.get("events", [])), "status": (d.get("header") or {}).get("status"), "step": ((d.get("header") or {}).get("step") or {}).get("kind")}
                out("/api/agent:", report["api_agent"])
            size = len(http_get(port, "/api/state")[1])
            report["state_json_kb"] = size // 1024
            out("Resource measurement: wait 65 seconds for unobserved mode")
            time.sleep(65)
            report["mode_idle"] = health(port)["mode"]
            report["cpu_idle_pct_60s"] = cpu_over(proc.pid, 60)
            report["rss_idle_mb"] = tasklist_rss_mb(proc.pid)
            out(f"Unobserved CPU {report['cpu_idle_pct_60s']}% RSS {report['rss_idle_mb']}MB mode={report['mode_idle']}")
            etag = {"v": None}

            def poll():
                hdr = {"If-None-Match": etag["v"]} if etag["v"] else {}
                c, b, h = http_get(port, "/api/state", headers=hdr)
                if c == 200:
                    etag["v"] = h.get("ETag")
                    etag["c200"] = etag.get("c200", 0) + 1
                else:
                    etag["c304"] = etag.get("c304", 0) + 1

            report["cpu_poll_pct_20s"] = cpu_over(proc.pid, 20, poll)
            report["cpu_poll_pct_60s"] = cpu_over(proc.pid, 60, poll)
            report["poll_200"] = etag.get("c200", 0)
            report["poll_304"] = etag.get("c304", 0)
            report["rss_poll_mb"] = tasklist_rss_mb(proc.pid)
            report["healthz_final"] = health(port)
            report["scan_ms"] = {"last": report["healthz_final"]["last_tick_ms"], "p95": report["healthz_final"]["p95_tick_ms"]}
            report["peak_rss_mb"] = report["healthz_final"].get("peak_rss_mb")
            out(f"Polling CPU 20s {report['cpu_poll_pct_20s']}% 60s {report['cpu_poll_pct_60s']}% RSS {report['rss_poll_mb']}MB 200/304={report['poll_200']}/{report['poll_304']}")
            out("healthz:", report["healthz_final"])
        ui(port, report, Path(args.shots))
    finally:
        (state_dir / "agent_watch.stop").write_text("", encoding="utf-8")
        t0 = time.time()
        while time.time() - t0 < 5 and proc.poll() is None:
            time.sleep(0.1)
        report["stopped_by_file"] = proc.poll() is not None
        report["pid_gone"] = proc_times(proc.pid) is None or not proc_times(proc.pid)["alive"]
        report["stop_ms"] = int((time.time() - t0) * 1000)
        if proc.poll() is None:
            proc.terminate()  # Stop only the process owned by this handle.
            proc.wait(timeout=5)
        report["exit_code"] = proc.returncode
        log.close()
        out(f"Stopped: file {report['stopped_by_file']} {report['stop_ms']}ms exit={proc.returncode}")
        (scratch / "smoke_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
        out("Report:", scratch / "smoke_report.json")


if __name__ == "__main__":
    main()
