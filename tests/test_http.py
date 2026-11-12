import http.client
import json
import os
import re
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import fixture_tree as ft  # noqa: E402
import server as srv  # noqa: E402
from config import Settings  # noqa: E402
from fixture_tree import AID, RUN, SID, Tree  # noqa: E402


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        now = int(time.time() * 1000)
        cls.tree = t = Tree("http")
        t.add_registry(SID)
        t.add_main(SID, [
            {"type": "ai-title", "aiTitle": "한글 제목 테스트"},
            ft.r_assistant_tool(now - 500, "m1", "t1", "Bash", {"description": "한글 설명"}),
        ])
        t.add_agent(SID, AID, [ft.r_assistant_tool(now - 500, "m1", "t1", "Grep", {"pattern": "x"})])
        uuid = "019a0000-0000-7000-8000-000000000009"
        t.add_rollout([
            {"timestamp": ft.iso(now - 1000), "type": "session_meta", "payload": {"id": uuid, "cwd": "c:\\x\\task_y", "source": "exec"}},
            {"timestamp": ft.iso(now - 900), "type": "event_msg", "payload": {"type": "task_started", "turn_id": "t"}},
        ], uuid=uuid)
        cls.uuid = uuid
        cls.app = srv.App(t.paths(), Settings(tick_s=0.5), port=0)
        cls.app.bind()
        cls.app.start()
        cls.port = cls.app.port
        deadline = time.time() + 10
        while time.time() < deadline:
            code, _, body = cls.get("/api/state")
            if code == 200 and b"sessions" in body and SID.encode() in body:
                break
            time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.app.stop()

    @classmethod
    def req(cls, method, path, headers=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=10)
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        c.putheader("Host", host or f"127.0.0.1:{cls.port}")
        for k, v in (headers or {}).items():
            c.putheader(k, v)
        c.endheaders()
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, dict(r.getheaders()), body

    @classmethod
    def get(cls, path, **kw):
        return cls.req("GET", path, **kw)

    def test_healthz(self):
        code, _, body = self.get("/healthz")
        d = json.loads(body)
        self.assertEqual(code, 200)
        self.assertTrue(d["ok"])
        for k in ("version", "uptime_s", "last_tick_age_ms", "tick_interval_ms", "last_tick_ms", "p95_tick_ms", "mode", "hot_files", "rss_mb", "bad_lines", "skipped_lines", "parse_errors"):
            self.assertIn(k, d)

    def test_host_rejected(self):
        for host in ("evil.com", f"127.0.0.1:{self.port + 1}", "127.0.0.1", f"evil.com:{self.port}"):
            with self.subTest(host):
                self.assertEqual(self.get("/healthz", host=host)[0], 403)

    def test_localhost_allowed(self):
        self.assertEqual(self.get("/healthz", host=f"localhost:{self.port}")[0], 200)

    def test_sec_fetch_site(self):
        self.assertEqual(self.get("/api/state", headers={"Sec-Fetch-Site": "cross-site"})[0], 403)
        self.assertEqual(self.get("/api/state", headers={"Sec-Fetch-Site": "same-site"})[0], 403)
        self.assertEqual(self.get("/api/state", headers={"Sec-Fetch-Site": "same-origin"})[0], 200)
        self.assertEqual(self.get("/api/state", headers={"Sec-Fetch-Site": "none"})[0], 200)

    def test_origin(self):
        self.assertEqual(self.get("/api/state", headers={"Origin": "http://evil.com"})[0], 403)
        self.assertEqual(self.get("/api/state", headers={"Origin": f"http://127.0.0.1:{self.port + 1}"})[0], 403)
        self.assertEqual(self.get("/api/state", headers={"Origin": f"http://127.0.0.1:{self.port}"})[0], 200)

    def test_methods_405(self):
        for m in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            with self.subTest(m):
                code, h, _ = self.req(m, "/api/state")
                self.assertEqual(code, 405)
                self.assertEqual(h.get("Allow"), "GET, HEAD")

    def test_head(self):
        code, h, body = self.req("HEAD", "/healthz")
        self.assertEqual(code, 200)
        self.assertEqual(body, b"")

    def test_traversal_paths_404(self):
        for p in ("/../server.py", "/..%2fserver.py", "/static/index.html", "/static/../server.py", "/C:/Windows/win.ini", "//etc/passwd", "/server.py", "/state/run.json"):
            with self.subTest(p):
                self.assertEqual(self.get(p)[0], 404)

    def test_agent_param_validation(self):
        for q in (
            "session=../../etc&agent=main", f"session={SID}&agent=..%2f..%2fx", f"session={SID}&agent=C:%5CWindows",
            "session=ABCDEF00-2222-4333-8444-555555555555&agent=main", "session=&agent=", f"session={SID}&agent=A123",
        ):
            with self.subTest(q):
                self.assertEqual(self.get(f"/api/agent?{q}")[0], 400)

    def test_agent_unknown_404(self):
        self.assertEqual(self.get("/api/agent?session=00000000-0000-4000-8000-000000000000&agent=main")[0], 404)
        self.assertEqual(self.get(f"/api/agent?session={SID}&agent=a00000000000000ff")[0], 404)

    def test_agent_detail(self):
        code, _, body = self.get(f"/api/agent?session={SID}&agent={AID}")
        self.assertEqual(code, 200)
        d = json.loads(body)
        self.assertEqual(d["schema"], "agent_watch.agent/1")
        self.assertEqual(d["header"]["step"]["tool"], "Grep")
        self.assertEqual(d["events"][0]["kind"], "tool_call")
        self.assertTrue(d["path_display"].endswith(f"agent-{AID}.jsonl"))

    def test_main_detail(self):
        code, _, body = self.get(f"/api/agent?session={SID}&agent=main")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["header"]["kind"], "main")

    def test_codex_detail(self):
        self.assertEqual(self.get("/api/codex?thread=../x")[0], 400)
        self.assertEqual(self.get("/api/codex?thread=00000000-0000-4000-8000-000000000000")[0], 404)
        code, _, body = self.get(f"/api/codex?thread={self.uuid}")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["header"]["packet"], "task_y")

    def test_etag_304(self):
        code, h, body = self.get("/api/state")
        self.assertEqual(code, 200)
        etag = h["ETag"]
        for _ in range(30):
            code2, h2, body2 = self.get("/api/state", headers={"If-None-Match": etag})
            if code2 == 304:
                break
            etag = h2["ETag"]
            time.sleep(0.2)
        self.assertEqual(code2, 304)
        self.assertEqual(body2, b"")

    def test_state_schema_and_utf8(self):
        code, h, body = self.get("/api/state")
        self.assertIn("charset=utf-8", h["Content-Type"])
        d = json.loads(body.decode("utf-8"))
        self.assertEqual(d["schema"], "agent_watch.state/1")
        self.assertEqual(d["sessions"][0]["title"], "한글 제목 테스트")
        self.assertIn("한글 제목 테스트".encode("utf-8"), body)
        for k in ("sessions_live", "agents_running", "agents_stalled", "workflows_running", "codex_running", "bg_running"):
            self.assertIn(k, d["counts"])
        self.assertGreaterEqual(d["server"]["state_version"], 1)

    def test_index_nonce_and_headers(self):
        code, h, body = self.get("/")
        self.assertEqual(code, 200)
        csp = h["Content-Security-Policy"]
        m = re.search(r"script-src 'nonce-([^']+)'", csp)
        self.assertTrue(m)
        nonce = m.group(1).encode()
        self.assertNotIn(b"__NONCE__", body)
        self.assertGreaterEqual(body.count(b'nonce="' + nonce + b'"'), 2)
        self.assertEqual(h["X-Content-Type-Options"], "nosniff")
        self.assertEqual(h["Referrer-Policy"], "no-referrer")
        self.assertEqual(h["X-Frame-Options"], "DENY")
        self.assertEqual(h["Cache-Control"], "no-store")
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_nonce_differs_per_response(self):
        a = self.get("/")[1]["Content-Security-Policy"]
        b = self.get("/")[1]["Content-Security-Policy"]
        self.assertNotEqual(a, b)


class Cli(unittest.TestCase):
    def test_non_loopback_refused(self):
        t = Tree("cli")
        code = srv.main(["--host", "203.0.113.99", "--port", "0", "--state-dir", str(t.state), "--claude-home", str(t.claude), "--codex-home", str(t.codex), "--temp-claude", str(t.temp)])
        self.assertEqual(code, srv.EXIT_USAGE)

    def test_wildcard_refused(self):
        t = Tree("cli")
        self.assertEqual(srv.main(["--host", "0.0.0.0", "--port", "0", "--state-dir", str(t.state)]), srv.EXIT_USAGE)

    def test_loopback_detection(self):
        self.assertTrue(srv.is_loopback_host("127.0.0.1"))
        self.assertTrue(srv.is_loopback_host("localhost"))
        self.assertFalse(srv.is_loopback_host("0.0.0.0"))
        self.assertFalse(srv.is_loopback_host("example.com"))

    def test_bind_conflict_is_exclusive(self):
        t = Tree("cli")
        a = srv.App(t.paths(), Settings(), port=0)
        a.bind()
        try:
            b = srv.App(t.paths(), Settings(), port=a.port)
            with self.assertRaises(OSError):
                b.bind()
        finally:
            a.server.server_close()

    def test_stop_file_consumed(self):
        t = Tree("cli")
        a = srv.App(t.paths(), Settings(), port=0)
        (t.state / "agent_watch.stop").write_text("", encoding="utf-8")
        self.assertTrue(a.consume_stop_file())
        self.assertFalse((t.state / "agent_watch.stop").exists())
        self.assertTrue(list(t.state.glob("agent_watch.stop.consumed.*")))
        self.assertFalse(a.consume_stop_file())

    def test_log_dedupes(self):
        t = Tree("cli")
        a = srv.App(t.paths(), Settings(), port=0)
        for _ in range(5):
            try:
                raise ValueError("Raw transcript text must not be retained here")
            except ValueError as e:
                a.log.error("x", e)
        text = (t.state / "agent_watch.log").read_text(encoding="utf-8")
        self.assertEqual(text.count("ValueError"), 1)
        self.assertNotIn("Raw text", text)

    def test_run_json(self):
        t = Tree("cli")
        a = srv.App(t.paths(), Settings(), port=0)
        a.bind()
        a.write_run()
        d = json.loads((t.state / "run.json").read_text(encoding="utf-8"))
        self.assertEqual((d["pid"], d["port"]), (os.getpid(), a.port))
        a.server.server_close()
        a.write_run(stopped=True)
        self.assertIn("stopped_ms", json.loads((t.state / "run.json").read_text(encoding="utf-8")))

    def test_default_port_literal(self):
        self.assertEqual(srv.DEFAULT_PORT, 8810)


if __name__ == "__main__":
    unittest.main()
