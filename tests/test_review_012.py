"""Synthetic regressions from an independent adversarial code review. Exercise parser, collector, snapshot, and HTTP where possible. For large inventories, reduce caps or feed real parsers in memory."""
import http.client
import json
import math
import os
import socket
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import claude_parse as cp  # noqa: E402
import collect_claude as cc  # noqa: E402
import collect_codex as cx  # noqa: E402
import fixture_tree as ft  # noqa: E402
import masking  # noqa: E402
import model  # noqa: E402
import server as srv  # noqa: E402
import status as st  # noqa: E402
from claude_parse import SessionIndex, TranscriptState  # noqa: E402
from collect_claude import AgentRec, SessionRec, Tracked  # noqa: E402
from collect_codex import CodexCollector, CodexRec  # noqa: E402
from config import CODEX_RUNS_MAX, FINISHED_KEEP_S, MAX_HANDLERS, STATE_JSON_MAX, TICK_READ_CAP, Settings  # noqa: E402
from fixture_tree import AID, AID2, RUN, SID, SID2, Tree, collector, run_ticks, scratch_dir  # noqa: E402
from masking import PRIVATE  # noqa: E402
from tailreader import Budget, IncrementalReader  # noqa: E402
from test_codex import UUID, complete, exec_call, meta, started, turn_ctx  # noqa: E402

V = "ZZSYNTHVALUEZZ"  # Synthetic marker used as a secret value.


def now_ms():
    return int(time.time() * 1000)


def j(*parts):
    return "".join(parts)


class LiveServer:
    """Run the real HTTP handler without a scanner thread; the test controls publication."""

    def __init__(self, tree):
        self.app = srv.App(tree.paths(), Settings(), port=0)
        self.app.bind()
        self.port = self.app.port
        self.sc = self.app.scanner
        self.thread = threading.Thread(target=self.app.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def publish(self):
        self.sc.last_disc = 0.0
        self.sc.tick_once()
        while self.sc.claude.backfill.pending():
            self.sc.claude.backfill.run()
        self.sc.last_disc = 0.0
        self.sc.tick_once()

    def get(self, path, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        c.putheader("Host", f"127.0.0.1:{self.port}")
        for k, v in (headers or {}).items():
            c.putheader(k, v)
        c.endheaders()
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, body, dict(r.getheaders())

    def state(self):
        return json.loads(self.get("/api/state")[1])

    def agent(self, sid=SID, aid="main"):
        return self.get(f"/api/agent?session={sid}&agent={aid}")

    def close(self):
        self.app.server.shutdown()
        self.app.server.server_close()


class Base(unittest.TestCase):
    def setUp(self):
        self.t = Tree("r012")
        self.now = now_ms()
        self.servers = []

    def tearDown(self):
        for s in self.servers:
            s.close()

    def live(self, tree=None):
        s = LiveServer(tree or self.t)
        self.servers.append(s)
        return s

    def session(self, state, sid=SID):
        return next(s for s in state["sessions"] if s["id"] == sid)

    def view(self, sid=SID, c=None):
        c = c or collector(self.t)
        self.c = c
        self.v = run_ticks(c, now_ms())
        return self.session(self.v, sid)

    def bg_start(self, tid="bx1234567", ts=None, desc="Server"):
        ts = ts or self.now - 5000
        return [
            ft.r_assistant_tool(ts, "mb", "tb", "Bash", {"description": desc, "run_in_background": True}),
            ft.r_tool_result(ts + 10, "tb", f"Command running in background with ID: {tid}. x", tur={"backgroundTaskId": tid}),
        ]


# ---- Masking ----
class Masking1(Base):
    CASES = {
        "escaped_quote": '{"password":"prefix\\"' + V + '"}',
        "unicode_key": '{"pass\\u0077ord":"' + V + '"}',
        "percent_query_key": "https://example.test/?%74oken=" + V,
        "multiline_quoted": '{"password":"line1\n' + V + '"}',
        "folded_header": j("Authorization: Bearer ", "abcdefgh12345678\n  ", V),
    }

    def test_review_inputs_never_reach_api(self):
        for name, text in self.CASES.items():
            with self.subTest(name):
                t = Tree("r012m")
                t.add_registry(SID)
                t.add_main(SID, [ft.r_assistant_text(self.now - 100, "m1", text)])
                server = self.live(t)
                server.publish()
                state_body = server.get("/api/state")[1]
                code, detail, _ = server.agent()
                self.assertEqual(code, 200)
                self.assertNotIn(V.encode(), state_body)
                self.assertNotIn(V.encode(), detail)
                # Guard against vacuous success: the input reached a display field.
                self.assertIn(b"[MASK]", detail)

    def test_same_family_variants(self):
        rows = [
            '{\\"password\\":\\"a ' + V + ' b\\"}',  # JSON inside JSON.
            '"sessionId":"a\\"' + V + '"',
            '{"authorization":"line1\n' + V + '"}',
            "x?redirect=https%3A%2F%2Fa.b%2Fcb%3Fcode%3D" + V,
            "https://example.test/?%2574oken=" + V,  # Double encoding.
            '--password "a\\"' + V + ' b" next',
            'MY_TOKEN="a\\"' + V + ' b" next',
            "password=ab," + V,
            "token: `a " + V + "` end",
            '비밀번호: "a ' + V + "\" end",
            "{\"password\":\"unterminated value " + V,
            'MY_TOKEN="ab"' + V,  # Adjacent characters remain part of the value.
            '"session_id":"ab"' + V,
            "password=ab&" + V,  # An ampersand not followed by a key belongs to the value.
            "password=ab;" + V,
        ]
        for raw in rows:
            with self.subTest(raw):
                self.assertNotIn(V, masking.safe_text(raw, 300))

    def test_no_new_false_positive_on_paths_and_identifiers(self):
        rows = [
            "tests/test_collect/fixture_tree_helpers.py",
            "C:/work/a%20b/c.py and %E2%9C%85 done",
            "max_tokens: 1234",
            "design: 3 obsession: x",
            "pattern = re.compile(r'x')",
            'session_start: 3 "quoted" text',
            "tokenizer=gpt keyboard: 1",
            "wl-orig-rights-feature-261021-Final-20261030",
        ]
        for raw in rows:
            with self.subTest(raw):
                self.assertEqual(masking.safe_text(raw, 300), raw)

    def test_separators_before_next_key_survive(self):
        cases = {
            "/api/agent?session=abc&agent=main": "/api/agent?session=[MASK]&agent=main",
            "token: 5, next": "token: [MASK], next",
            '{"token":123,"model":"gpt"}': '{"token":[MASK],"model":"gpt"}',
            "cookie_value=1; token=abc; path=/": None,
        }
        for raw, want in cases.items():
            with self.subTest(raw):
                out = masking.safe_text(raw, 200)
                self.assertNotIn("abc", out)
                if want:
                    self.assertEqual(out, want)

    def test_value_after_closing_quote_survives(self):
        self.assertEqual(masking.safe_text('{"token":"abc","model":"gpt"}', 200), '{"token":"[MASK]","model":"gpt"}')

    def test_encoded_text_without_credential_key_is_left_alone(self):
        s = "hello%20world \\u00e9 cafe%3Dlatte"
        self.assertEqual(masking.safe_text(s, 200), s)


# ---- Titles ----
class Title2(Base):
    def pad(self, tag, n=50):
        return [ft.r_assistant_text(self.now - 1000, f"{tag}{i}", "z" * 3000) for i in range(n)]

    def title(self, text, kind="custom-title"):
        return {"type": kind, ("customTitle" if kind == "custom-title" else "aiTitle"): text}

    def layout(self, head, middle, tail=()):
        """Place records within the 128KB head, between head and tail, and within the 256KB tail."""
        return [*head, *self.pad("a"), *middle, *self.pad("b", 90), *tail, ft.r_assistant_text(self.now - 100, "m9", f"Tail body {V}")]

    def test_review_head_public_backfill_private(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, self.layout([self.title("Ordinary task")], [self.title("client-x notes")]))
        server = self.live()
        server.publish()
        s = self.session(server.state())
        self.assertEqual(s["title"], PRIVATE)
        self.assertTrue(s["title_hidden"])
        self.assertEqual(s["main"]["last_text"], PRIVATE)
        self.assertNotIn(V.encode(), server.get("/api/state")[1])
        self.assertNotIn(V.encode(), server.agent()[1])

    def test_later_public_title_wins_over_older_private(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, self.layout([self.title("client-x draft")], [self.title("Ordinary task")]))
        s = self.view()
        self.assertEqual((s["title"], s["title_hidden"]), ("Ordinary task", False))

    def test_tail_title_is_latest(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, self.layout([], [self.title("client-x notes")], [self.title("Public title")]))
        s = self.view()
        self.assertEqual((s["title"], s["title_hidden"]), ("Public title", False))

    def test_either_kind_private_hides_session(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [self.title("Public user title"), self.title("client-x consultation", "ai-title"), ft.r_assistant_text(self.now, "m1", V)])
        s = self.view()
        self.assertTrue(s["title_hidden"])
        self.assertEqual(s["title"], PRIVATE)
        self.assertNotIn(V, json.dumps(self.v["sessions"], ensure_ascii=False))

    def test_head_read_not_skipped_when_tail_has_only_one_kind(self):
        # Closed sessions do not backfill; the head is the only source.
        self.t.add_registry(SID, pid=4_000_003, proc_start="1")
        self.t.add_main(SID, [self.title("client-x consultation", "ai-title"), *self.pad("a", 120), self.title("Public title")])
        self.assertTrue(self.view()["title_hidden"])

    def test_position_order_inside_index(self):
        idx = SessionIndex()
        idx.set_title("custom", "Head", 900)
        idx.set_title("custom", "Earlier backfill", 100)
        self.assertEqual(idx.title_custom, "Head")
        idx.set_title("custom", "Later backfill", 1000)
        self.assertEqual(idx.title_custom, "Later backfill")


# ---- Privacy propagation ----
class Propagation3(Base):
    def launch(self, ts, task="wabc12345"):
        return [
            ft.r_assistant_tool(ts, "mw", "tw", "Workflow", {}),
            ft.r_tool_result(ts + 10, "tw", "x", tur={"status": "async_launched", "taskId": task, "taskType": "local_workflow", "runId": RUN, "workflowName": "Ordinary"}),
        ]

    def test_review_excluded_workflow_detail_is_gone(self):
        old = self.now - 2 * 3600_000
        self.t.add_registry(SID)
        self.t.add_main(SID, [
            {"type": "custom-title", "customTitle": "client-x notes"},
            *self.launch(old),
            ft.r_notify_user(old + 60_000, ft.notification("wabc12345", "completed", "Workflow finished")),
            ft.r_assistant_text(self.now - 100, "m9", "Main"),
        ])
        self.t.add_run(SID, RUN, [{"type": "started", "agentId": AID, "label": "Label", "phase": "P"}], {AID: [ft.r_assistant_text(old, "m1", V)]})
        server = self.live()
        server.publish()
        s = self.session(server.state())
        self.assertEqual(s["workflows"], [])
        code, body, _ = server.agent(aid=AID)
        self.assertEqual(code, 404)
        self.assertNotIn(V.encode(), body)

    def test_excluded_workflow_does_not_count_as_running(self):
        old = self.now - 2 * 3600_000
        self.t.add_registry(SID)
        self.t.add_main(SID, [*self.launch(old), ft.r_notify_user(old + 60_000, ft.notification("wabc12345", "completed", "x"))])
        self.t.add_run(SID, RUN, [{"type": "started", "agentId": AID, "label": "Label", "phase": "P"}], {AID: [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Bash")]})
        s = self.view()
        self.assertEqual(s["workflows"], [])
        self.assertEqual(s["counts"]["running"], 0)

    def test_review_capped_workflow_agent_redacts_owned_bg(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        agents = {f"a{i:016x}": [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Bash")] for i in range(3)}
        hidden = f"a{99:016x}"
        agents[hidden] = self.bg_start(desc=V)
        journal = [{"type": "started", "agentId": a, "label": f"Label {a[-2:]}", "phase": "P"} for a in agents if a != hidden]
        journal += [{"type": "started", "agentId": hidden, "label": "client-x notes", "phase": "P"}, {"type": "result", "agentId": hidden}]
        self.t.add_run(SID, RUN, journal, agents)
        self.t.add_output(SID, "bx1234567")
        with mock.patch.object(cc, "AGENTS_PER_SESSION_MAX", 3):
            s = self.view()
        self.assertEqual(len(s["workflows"][0]["agents"]), 3)  # The private agent was truncated from the view.
        self.assertNotIn(hidden, {a["agent_id"] for a in s["workflows"][0]["agents"]})
        self.assertEqual(s["workflows"][0]["agents_omitted"], 1)
        self.assertEqual(self.v["bg_tasks"][0]["description"], PRIVATE)
        self.assertNotIn(V, json.dumps(self.v["bg_tasks"], ensure_ascii=False))
        self.assertNotIn((SID, hidden), self.v["index"])

    def test_capped_direct_agent_redacts_owned_bg(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        for i in range(3):
            self.t.add_agent(SID, f"a{i:016x}", [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Bash")])
        self.t.add_agent(SID, AID, self.bg_start(desc=V) + [ft.r_assistant_text(self.now - 50, "m9", "Done", stop="end_turn")], {"description": "client-x notes", "requestShape": "background", "finished": True})
        self.t.add_output(SID, "bx1234567")
        with mock.patch.object(cc, "AGENTS_PER_SESSION_MAX", 3):
            s = self.view()
        self.assertNotIn(AID, {a["agent_id"] for a in s["agents"]})
        self.assertEqual(self.v["bg_tasks"][0]["description"], PRIVATE)

    def test_owner_private_survives_tracker_eviction(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        old = self.now - 2 * 3600_000
        recs = self.bg_start(desc=V, ts=old) + [ft.r_assistant_text(old + 100, "m9", "Done", stop="end_turn")]
        p = self.t.add_agent(SID, AID, recs, {"description": "interview notes", "requestShape": "background", "finished": True})
        ft.set_mtime(p, old)
        self.t.add_output(SID, "bx1234567")
        s = self.view()
        self.assertNotIn(AID, self.c.sessions[SID].agents)
        self.assertEqual(s["agents"], [])
        self.assertEqual(self.v["bg_tasks"][0]["description"], PRIVATE)

    def test_private_decision_is_made_from_records_not_views(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        self.t.add_agent(SID, AID, [ft.r_assistant_text(self.now - 100, "m1", V)], {"description": "Ordinary", "workflowPhase": "legal review", "requestShape": "background"})
        s = self.view()
        a = s["agents"][0]
        self.assertTrue(a["private"])
        self.assertEqual(a["last_text"], PRIVATE)


# ---- Detail snapshots ----
class Snapshot4(Base):
    def test_review_private_turn_after_publish_is_not_served(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_text(self.now - 500, "m1", "Public body")])
        server = self.live()
        server.publish()
        before = json.loads(server.agent()[1])
        self.assertFalse(before["header"]["private"])
        tracked = server.sc.claude.sessions[SID].main
        tracked.state.feed({"type": "custom-title", "customTitle": "client-x notes"})
        tracked.state.feed(ft.r_assistant_text(now_ms(), "m2", V))
        code, body, _ = server.agent()
        self.assertEqual(code, 200)
        self.assertNotIn(V.encode(), body)
        self.assertEqual(json.loads(body)["events"], before["events"])  # The old decision must pair with the old events.
        server.publish()
        after = json.loads(server.agent()[1])
        self.assertTrue(after["header"]["private"])
        self.assertNotIn(V, json.dumps(after, ensure_ascii=False))

    def test_review_codex_detail_uses_snapshot(self):
        uuid = "019a0000-0000-7000-8000-00000000000a"
        self.t.add_rollout([meta(id=uuid), started()], uuid=uuid)
        server = self.live()
        server.publish()
        rec = next(iter(server.sc.codex.runs.values()))
        rec.events.append({"ts_ms": 1, "kind": "text", "tool": None, "arg": None, "ok": None, "text": V})
        code, body, _ = server.get(f"/api/codex?thread={uuid}")
        self.assertEqual(code, 200)
        self.assertNotIn(V.encode(), body)

    def test_snapshot_holds_no_live_records(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_text(self.now - 500, "m1", "x")])
        self.t.add_rollout([meta(), started()])
        server = self.live()
        server.publish()
        snap = server.sc.snapshot
        for entry in [*snap.index.values(), *snap.codex_index.values()]:
            self.assertNotIn("tracked", entry)
            self.assertNotIn("rec", entry)
            self.assertIsInstance(entry["events"], tuple)

    def test_snapshot_not_rebuilt_when_nothing_changed(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_text(self.now - 500, "m1", "x")])
        server = self.live()
        server.publish()
        first = server.sc.snapshot.index[(SID, "main")]["events"]
        server.publish()
        self.assertIs(server.sc.snapshot.index[(SID, "main")]["events"], first)

    def test_private_flip_replaces_cached_events(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_text(self.now - 500, "m1", "Body")])
        p = self.t.main_path(SID)
        server = self.live()
        server.publish()
        self.assertEqual(json.loads(server.agent()[1])["events"][0]["text"], "Body")
        ft.write_jsonl(p, [{"type": "custom-title", "customTitle": "salary case"}])
        server.publish()
        self.assertEqual(json.loads(server.agent()[1])["events"][0]["text"], PRIVATE)


# ---- Dormant Codex runs ----
class Dormant5(Base):
    def setUp(self):
        super().setUp()
        self.c = CodexCollector(self.t.paths())
        self.old = self.now - 2 * 3600_000

    def round(self):
        now = now_ms()
        self.c.discover(now, Budget(TICK_READ_CAP))
        self.c.tick(now, Budget(TICK_READ_CAP))
        return self.c.build(now)[0]

    def rollout(self, extra=()):
        recs = [meta(), turn_ctx(), started(self.old), *extra, complete(self.old + 1000)]
        return self.t.add_rollout(recs)

    def test_review_appended_turn_reactivates(self):
        p = self.rollout()
        self.assertEqual(self.round(), [])
        rec = next(iter(self.c.runs.values()))
        self.assertTrue(rec.dormant)
        ft.write_jsonl(p, [started(now_ms() - 100), exec_call(now_ms() - 50, "pytest")])
        rows = self.round()
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["status"], rows[0]["last_command"]["text"]), ("running", "pytest"))
        self.assertFalse(next(iter(self.c.runs.values())).dormant)

    def test_dormant_is_not_read_every_tick(self):
        self.rollout()
        self.round()
        rec = next(iter(self.c.runs.values()))
        with mock.patch.object(self.c, "_poll", wraps=self.c._poll) as poll:
            self.c.tick(now_ms(), Budget(TICK_READ_CAP))
        self.assertEqual(poll.call_count, 0)
        self.assertTrue(rec.dormant)

    def test_head_skipped_while_dormant_is_read_on_wake(self):
        pad = [{"timestamp": ft.iso(self.old), "type": "event_msg", "payload": {"type": "brand_new", "pad": "y" * 30_000}} for _ in range(12)]
        p = self.rollout(pad)
        self.assertGreater(p.stat().st_size, 256 * 1024)
        self.round()
        self.assertTrue(next(iter(self.c.runs.values())).head_pending)
        ft.write_jsonl(p, [started(now_ms() - 100)])
        rows = self.round()
        self.assertEqual((rows[0]["packet"], rows[0]["model"]), ("task_x", "gpt-6-astra"))

    def test_growth_without_new_turn_goes_back_to_sleep(self):
        p = self.rollout()
        self.round()
        ft.write_jsonl(p, [{"timestamp": ft.iso(self.old + 2000), "type": "event_msg", "payload": {"type": "brand_new"}}])
        self.assertEqual(self.round(), [])
        now = now_ms()
        self.c.discover(now, Budget(TICK_READ_CAP))
        self.assertTrue(next(iter(self.c.runs.values())).dormant)


# ---- Waiting for owned background jobs ----
class OwnBg6(Base):
    def test_review_workflow_agent_end_turn_with_bg_waits(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        recs = self.bg_start() + [ft.r_assistant_text(self.now - 1000, "m9", "Waiting", stop="end_turn")]
        self.t.add_run(SID, RUN, [{"type": "started", "agentId": AID, "label": "Label", "phase": "P"}], {AID: recs})
        self.t.add_output(SID, "bx1234567")
        s = self.view()
        w = s["workflows"][0]
        a = w["agents"][0]
        self.assertEqual((a["status"], a["status_label"], a["own_bg_pending"]), ("waiting", "Waiting for background jobs", 1))
        self.assertIn(w["status"], ("running", "waiting"))
        b = self.v["bg_tasks"][0]
        self.assertIn(b["status"], ("running", "waiting"))
        self.assertEqual(s["counts"]["bg_running"], 1)

    def test_workflow_agent_finishes_when_bg_ends(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000), ft.r_notify_user(self.now - 500, ft.notification("bx1234567", "completed"))])
        recs = self.bg_start() + [ft.r_assistant_text(self.now - 1000, "m9", "Done", stop="end_turn")]
        self.t.add_run(SID, RUN, [{"type": "started", "agentId": AID, "label": "Label", "phase": "P"}], {AID: recs})
        self.t.add_output(SID, "bx1234567")
        self.assertEqual(self.view()["workflows"][0]["agents"][0]["status"], "finished")

    def test_review_registryless_main_with_bg_waits(self):
        self.t.add_main(SID, self.bg_start() + [ft.r_assistant_text(self.now - 1000, "m9", "Waiting", stop="end_turn")])
        self.t.add_output(SID, "bx1234567")
        s = self.view()
        self.assertIsNone(s["live"])
        self.assertEqual((s["main"]["status"], s["main"]["status_label"], s["main"]["own_bg_pending"]), ("waiting", "Waiting for background jobs", 1))

    def test_registryless_main_without_bg_stays_idle(self):
        self.t.add_main(SID, [ft.r_assistant_text(self.now - 1000, "m9", "Done", stop="end_turn")])
        self.assertEqual(self.view()["main"]["status"], "idle")

    def test_pure_rule(self):
        base = dict(terminal_state=None, run_outcome=None, journal_state=None, tail_end=True, tail_ms=1)
        self.assertIsNone(st.resolve_workflow_finish(**base, own_bg_pending=1))
        self.assertIsNone(st.resolve_workflow_finish(**base, backfill_done=False))
        self.assertEqual(st.resolve_workflow_finish(**base).source, "tail")


# ---- File generations ----
class Generation7(Base):
    def test_reader_reports_inode_change(self):
        d = scratch_dir("r012g")
        p = d / "f.jsonl"
        p.write_bytes(b'{"a":1}\n')
        r = IncrementalReader(p, tail=1000)
        r.poll()
        new = d / "g.jsonl"
        new.write_bytes(b'{"a":2}\n')
        os.replace(new, p)
        lines = r.poll()
        self.assertEqual((r.generation, lines), (1, [b'{"a":2}']))

    def test_reader_reports_shrink(self):
        p = scratch_dir("r012g") / "f.jsonl"
        p.write_bytes(b'{"a":1}\n' * 5)
        r = IncrementalReader(p, tail=1000)
        r.poll()
        with open(p, "wb") as f:
            f.write(b'{"a":2}\n')
        r.poll()
        self.assertEqual(r.generation, 1)

    def test_review_same_size_rewrite_with_new_mtime(self):
        p = scratch_dir("r012g") / "f.jsonl"
        p.write_bytes(b'{"a":1}\n')
        r = IncrementalReader(p, tail=1000)
        r.poll()
        with open(p, "r+b") as f:
            f.write(b'{"a":2}\n')
        os.utime(p, (time.time() + 5, time.time() + 5))
        s = os.stat(p)
        self.assertTrue(r.changed(s))
        self.assertEqual(r.poll(s), [b'{"a":2}'])
        self.assertEqual(r.generation, 1)

    def test_mtime_only_change_is_not_a_new_generation(self):
        # Windows may update mtime only after the write handle closes; this must not trigger a full backfill.
        p = scratch_dir("r012g") / "f.jsonl"
        p.write_bytes(b'{"a":1}\n')
        r = IncrementalReader(p, tail=1000)
        r.poll()
        os.utime(p, (time.time() + 5, time.time() + 5))
        s = os.stat(p)
        self.assertTrue(r.changed(s))
        self.assertEqual(r.poll(s), [])
        self.assertEqual(r.generation, 0)
        self.assertFalse(r.changed(s))

    def test_rewrite_to_larger_file_on_same_inode(self):
        p = scratch_dir("r012g") / "f.jsonl"
        p.write_bytes(b'{"a":1}\n')
        r = IncrementalReader(p, tail=1000)
        r.poll()
        with open(p, "wb") as f:
            f.write(b'{"b":2}\n{"b":3}\n')
        self.assertEqual(r.poll(), [b'{"b":2}', b'{"b":3}'])
        self.assertEqual(r.generation, 1)

    def test_review_codex_replacement_drops_old_completion(self):
        p = self.t.add_rollout([meta(), started(self.now - 5000), complete(self.now - 4000)])
        c = CodexCollector(self.t.paths())
        now = now_ms()
        c.discover(now, Budget(TICK_READ_CAP))
        c.tick(now, Budget(TICK_READ_CAP))
        self.assertEqual(c.build(now)[0][0]["status"], "finished")
        new = p.with_name("next.tmp")
        ft.write_jsonl(new, [meta(), started(now_ms() - 100), exec_call(now_ms() - 50, "pytest")])
        os.replace(new, p)
        now = now_ms()
        c.tick(now, Budget(TICK_READ_CAP))
        row = c.build(now)[0][0]
        self.assertEqual((row["status"], row["last_command"]["text"]), ("running", "pytest"))
        self.assertEqual(row["turns"]["completed"], 0)

    def replace_main(self, records):
        p = self.t.main_path(SID)
        new = p.with_name("next.tmp")
        ft.write_jsonl(new, records)
        os.replace(new, p)

    def test_claude_main_replacement_rebuilds_session(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [
            {"type": "custom-title", "customTitle": "Old title"},
            *self.bg_start(),
            ft.r_assistant_tool(self.now - 900, "m2", "t2", "Grep", {"pattern": "x"}),
            ft.r_assistant_text(self.now - 800, "m3", f"Old body {V}"),
        ])
        self.t.add_output(SID, "bx1234567")
        c = collector(self.t)
        s = self.view(c=c)
        self.assertEqual(s["main"]["tool_calls"]["value"], 2)
        self.assertEqual(len(self.v["bg_tasks"]), 1)
        old_idx = c.sessions[SID].idx
        self.replace_main([ft.r_assistant_text(now_ms() - 10, "m1", "New body")])
        s = self.view(c=c)
        self.assertIsNot(c.sessions[SID].idx, old_idx)
        self.assertEqual(s["main"]["last_text"], "New body")
        self.assertEqual(s["main"]["tool_calls"]["value"], 0)
        self.assertNotEqual(s["title"], "Old title")
        self.assertNotIn(V, json.dumps(self.v["sessions"], ensure_ascii=False))
        self.assertEqual([b for b in self.v["bg_tasks"] if b.get("start_seen")], [])

    def test_replacement_restarts_backfill(self):
        pad = [ft.r_assistant_text(self.now - 1000, f"p{i}", "z" * 3000) for i in range(120)]
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 2000), *pad])
        c = collector(self.t)
        self.view(c=c)
        self.assertEqual(c.sessions[SID].main.bf, "done")
        self.replace_main([ft.r_assistant_tool(self.now - 900, "x1", "toolu_a", "Grep", {"pattern": "x"}), *pad])
        now = now_ms()
        c.tick(now, Budget(TICK_READ_CAP))
        c.tick(now, Budget(TICK_READ_CAP))
        self.assertEqual(c.sessions[SID].main.bf, "queued")
        while c.backfill.pending():
            c.backfill.run()
        self.assertEqual(c.sessions[SID].main.bf, "done")
        self.assertEqual(c.build(now)["sessions"][0]["main"]["tool_calls"], {"value": 1, "exact": True})

    def test_pending_backfill_of_old_file_is_cancelled(self):
        pad = [ft.r_assistant_text(self.now - 1000, f"p{i}", "z" * 3000) for i in range(120)]
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 2000), *pad])
        c = collector(self.t)
        now = now_ms()
        c.discover(now, Budget(TICK_READ_CAP))
        c.tick(now, Budget(TICK_READ_CAP))
        self.assertTrue(c.backfill.pending())
        self.replace_main([ft.r_assistant_text(now_ms(), "m1", "New file")])
        c.tick(now, Budget(TICK_READ_CAP))
        self.assertFalse(c.backfill.pending())

    def test_agent_replacement_forgets_owned_bg(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        p = self.t.add_agent(SID, AID, self.bg_start())
        self.t.add_output(SID, "bx1234567")
        c = collector(self.t)
        self.view(c=c)
        self.assertIn("bx1234567", c.sessions[SID].idx.bg)
        new = p.with_name("next.tmp")
        ft.write_jsonl(new, [ft.r_assistant_text(now_ms(), "m1", "New file")])
        os.replace(new, p)
        s = self.view(c=c)
        self.assertEqual(next(a for a in s["agents"])["last_text"], "New file")
        self.assertFalse(c.sessions[SID].idx.bg.get("bx1234567", {}).get("start_seen"))

    def test_journal_replacement_clears_run_state(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000), ft.r_workflow_launch(self.now - 900, RUN)])
        d = self.t.add_run(SID, RUN, [{"type": "started", "agentId": AID, "label": "Old label", "phase": "P"}], {AID: [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Bash")]})
        c = collector(self.t)
        self.view(c=c)
        new = d / "journal.next"
        ft.write_jsonl(new, [{"type": "started", "agentId": AID, "label": "New label", "phase": "P"}])
        os.replace(new, d / "journal.jsonl")
        s = self.view(c=c)
        self.assertEqual(s["workflows"][0]["agents"][0]["description"], "New label")
        self.assertEqual(s["workflows"][0]["agents_started"], 1)


# ---- Retention caps ----
class Bounds8(Base):
    def test_review_3000_calls_and_notifications_are_bounded(self):
        idx = SessionIndex()
        state = TranscriptState(None, idx)
        for i in range(3000):
            state.feed(ft.r_assistant_tool(self.now, f"m{i}", f"toolu_{i}", "Agent", {"description": "x"}))
            state.feed(ft.r_tool_result(self.now, f"toolu_{i}", "ok"))
            state.feed(ft.r_notify_queue(self.now, ft.notification(f"a{i:016x}", "completed", "x")))
            state.feed(ft.r_tool_result(self.now, f"toolu_{i}", f"Successfully stopped task: b{i}"))
        self.assertEqual(len(state.events), 30)
        self.assertLessEqual(len(idx.notifs), cp.NOTIFS_MAX)
        self.assertLessEqual(len(idx.stops), cp.STOPS_MAX)
        self.assertLessEqual(len(idx.agent_calls), cp.AGENT_CALLS_MAX)
        self.assertLessEqual(len(idx.hints), cp.HINTS_MAX)
        self.assertEqual(len(state.tool_ids), 3000)  # Counts remain exact below the cap.

    def test_tool_ids_cap_turns_count_approximate_in_api(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_assistant_tool(self.now - 100 + i, f"m{i}", f"toolu_{i}", "Grep", {"pattern": "x"}) for i in range(7)])
        with mock.patch.object(cp, "TOOL_IDS_MAX", 5):
            s = self.view()
        self.assertEqual(s["main"]["tool_calls"], {"value": 7, "exact": False})
        self.assertLessEqual(len(self.c.sessions[SID].main.state.tool_ids.seen), 5)

    def test_tool_ids_cap_shared_with_backfill(self):
        ids = cp.ToolIds()
        raw = [json.dumps(ft.r_assistant_tool(1, f"m{i}", f"toolu_{i}", "Grep"), separators=(",", ":")).encode() for i in range(6)]
        with mock.patch.object(cp, "TOOL_IDS_MAX", 4):
            total = sum(cp.scan_backfill_line(ln, SessionIndex(), None, ids) for ln in raw)
        self.assertEqual((total, len(ids), len(ids.seen), ids.exact), (6, 6, 4, False))

    def old_agent(self, aid, finished=True, text="Done"):
        old = self.now - 2 * 3600_000
        meta_ = {"description": "Old task", "requestShape": "background"}
        if finished:
            meta_["finished"] = True
        p = self.t.add_agent(SID, aid, [ft.r_assistant_text(old, "m1", text, stop="end_turn")], meta_)
        ft.set_mtime(p, old)
        return p

    def test_review_old_finished_agents_leave_memory(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        ids = [f"a{i:016x}" for i in range(6)]
        for aid in ids:
            self.old_agent(aid)
        c = collector(self.t)
        self.view(c=c)
        s = c.sessions[SID]
        self.assertEqual(s.agents, {})
        self.assertEqual(set(s.gone), set(ids))
        now = now_ms()
        with mock.patch.object(cc, "AgentRec", wraps=cc.AgentRec) as made:
            c.discover(now, Budget(TICK_READ_CAP))
        self.assertEqual(made.call_count, 0)  # A tombstone prevents metadata rereads.

    def test_review_1001_finished_agents_at_full_scale(self):
        c = collector(self.t)
        s = SessionRec(SID, str(self.t.main_path(SID)))
        s.live = True
        old = self.now - 2 * 3600_000
        for i in range(1001):
            rec = AgentRec(f"a{i:016x}", "direct", os.path.join(s.dir, f"agent-a{i:016x}.jsonl"))
            rec.meta = {"finished": True, "description": "Completed"}
            rec.mtime_ms = old
            s.agents[rec.agent_id] = rec
        c._warm(s, self.now, Budget(TICK_READ_CAP))
        self.assertEqual(len(s.agents), 0)
        self.assertEqual(len(s.gone), 1001)
        self.assertLessEqual(len(s.bf_seen), cc.BF_SEEN_MAX)

    def test_notification_finished_agent_tracker_evicted_with_indexes(self):
        self.t.add_registry(SID)
        old = self.now - 2 * 3600_000
        self.t.add_main(SID, [ft.r_notify_user(old, ft.notification(AID, "completed", 'Agent "x" finished')), ft.r_prompt(self.now - 1000)])
        self.old_agent(AID, finished=False)
        c = collector(self.t)
        self.view(c=c)
        self.view(c=c)
        s = c.sessions[SID]
        self.assertNotIn(AID, s.agents)
        self.assertNotIn(AID, s.idx.notifs)

    def test_tombstoned_agent_comes_back_on_new_write(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        p = self.old_agent(AID)
        c = collector(self.t)
        self.view(c=c)
        self.assertNotIn(AID, c.sessions[SID].agents)
        ft.write_jsonl(p, [ft.r_assistant_tool(now_ms(), "m2", "t2", "Bash")])
        ft.write_json(p.with_name(f"agent-{AID}.meta.json"), {"description": "Resumed", "requestShape": "background"})
        s = self.view(c=c)
        self.assertEqual(s["agents"][0]["status"], "running")
        self.assertNotIn(AID, c.sessions[SID].gone)

    def test_tombstones_are_capped(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000)])
        for i in range(5):
            self.old_agent(f"a{i:016x}")
        c = collector(self.t)
        with mock.patch.object(cc, "GONE_MAX", 3):
            self.view(c=c)
        self.assertLessEqual(len(c.sessions[SID].gone), 3)

    def test_expired_run_without_terminal_leaves_memory(self):
        old = self.now - 2 * 3600_000
        self.t.add_registry(SID)
        self.t.add_main(SID, [
            ft.r_assistant_tool(old, "mw", "tw", "Workflow", {}),
            ft.r_tool_result(old + 10, "tw", "x", tur={"status": "async_launched", "taskId": "wabc12345", "taskType": "local_workflow", "runId": RUN, "workflowName": "n"}),
            ft.r_notify_user(old + 60_000, ft.notification("wabc12345", "completed", "x")),
        ])
        self.t.add_run(SID, RUN, [{"type": "started", "agentId": AID, "label": "Label", "phase": "P"}], {AID: [ft.r_assistant_text(old, "m1", "x")]})
        c = collector(self.t)
        self.view(c=c)
        self.view(c=c)
        s = c.sessions[SID]
        self.assertEqual(s.runs, {})
        self.assertIn(RUN, s.runs_skip)
        self.assertNotIn(RUN, s.idx.workflows)
        self.assertNotIn("wabc12345", s.idx.wf_by_task)
        self.assertNotIn("wabc12345", s.idx.notifs)

    def test_review_stale_open_codex_runs_are_evicted(self):
        c = CodexCollector(self.t.paths())
        old = self.now - 2 * 86_400_000
        for i in range(1001):
            r = CodexRec(f"x{i}", f"x{i}", old)
            r.first_done = True
            r.last_record_ms = old + i
            c.runs[r.path] = r
        self.assertEqual(c.build(self.now)[0], [])
        c._evict(self.now)
        self.assertEqual(len(c.runs), CODEX_RUNS_MAX)
        self.assertLessEqual(len(c.evicted), 1001)

    def test_codex_finished_past_window_stops_per_tick_poll(self):
        c = CodexCollector(self.t.paths())
        t0 = self.now - 3600_000 - 60_000
        self.t.add_rollout([meta(), started(t0 + 1000), complete(self.now - 30_000)])
        c.discover(self.now, Budget(TICK_READ_CAP))
        c.tick(self.now, Budget(TICK_READ_CAP))
        rec = next(iter(c.runs.values()))
        later = self.now + (FINISHED_KEEP_S + 60) * 1000
        c.discover(later, Budget(TICK_READ_CAP))
        self.assertTrue(rec.dormant)

    def test_codex_evicted_run_returns_only_on_growth(self):
        c = CodexCollector(self.t.paths())
        p = self.t.add_rollout([meta(), started()])
        c.discover(self.now, Budget(TICK_READ_CAP))
        c.runs.clear()
        c.evicted.add(str(p))
        c.discover(self.now, Budget(TICK_READ_CAP))
        self.assertEqual(c.runs, {})
        ft.write_jsonl(p, [started()])
        c.discover(self.now, Budget(TICK_READ_CAP))
        self.assertEqual(len(c.runs), 1)
        self.assertNotIn(str(p), c.evicted)

    def test_codex_sizes_only_track_listed_files(self):
        c = CodexCollector(self.t.paths())
        c.sizes["Old path"] = 1
        self.t.add_rollout([meta(), started()])
        c.discover(self.now, Budget(TICK_READ_CAP))
        self.assertNotIn("Old path", c.sizes)
        self.assertEqual(len(c.sizes), 1)

    def test_codex_turn_stores_capped(self):
        r = CodexRec("x", "x", None)
        for i in range(200):
            r.feed({"type": "response_item", "payload": {"type": "custom_tool_call", "call_id": f"c{i}", "input": 'await tools.exec_command({cmd:"x"})'}}, None)
            r.feed({"type": "response_item", "payload": {"type": "function_call", "call_id": f"f{i}", "name": "wait"}}, None)
            r.feed({"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": f"c{i}", "output": "Script running"}}, None)
        self.assertLessEqual(len(r.running), cx.CODEX_PENDING_MAX)
        self.assertLessEqual(len(r.pending_wait_ids), cx.CODEX_PENDING_MAX)
        self.assertLessEqual(len(r.open_cells), cx.CODEX_PENDING_MAX)

    def test_path_cache_is_lru_bounded(self):
        c = collector(self.t)
        with mock.patch.object(cc, "PATH_CACHE_MAX", 3):
            for i in range(10):
                cc._remember(c.path_cache, f"s{i}", "p", cc.PATH_CACHE_MAX)
        self.assertEqual(list(c.path_cache), ["s7", "s8", "s9"])

    def test_path_miss_expires(self):
        c = collector(self.t)
        c.path_miss["old"] = time.monotonic() - cc.MISS_RETRY_S - 1
        c.path_miss["new"] = time.monotonic()
        c.discover(now_ms(), Budget(TICK_READ_CAP))
        self.assertEqual(set(c.path_miss), {"new"})

    def test_runs_skip_and_bf_seen_are_bounded(self):
        s = SessionRec(SID, str(self.t.main_path(SID)))
        with mock.patch.object(cc, "RUNS_SKIP_MAX", 3), mock.patch.object(cc, "BF_SEEN_MAX", 3):
            for i in range(10):
                cc._remember(s.runs_skip, f"wf_{i}", None, cc.RUNS_SKIP_MAX)
                cc._remember(s.bf_seen, f"p{i}", None, cc.BF_SEEN_MAX)
        self.assertEqual((len(s.runs_skip), len(s.bf_seen)), (3, 3))

    def test_bg_hard_cap_keeps_open_rows(self):
        idx = SessionIndex()
        for i in range(8):
            idx.bg[f"b{i}"] = {"task_id": f"b{i}", "kind": "bash", "owner": None, "description": None, "started_ms": self.now - 9000 + i,
                               "start_seen": True, "auto_backgrounded": False, "output_mtime_ms": self.now}
        for i in range(5):
            idx.notifs[f"b{i}"] = {"status": "completed", "ts_ms": self.now, "exit_code": 0}
        session = SessionRec(SID, str(self.t.main_path(SID)))
        session.idx = idx
        session.live = True
        with mock.patch("collect_bg.BG_PER_SESSION_MAX", 4):
            cc.collect_bg.build_bg_views(session, lambda o: (False, "Main", False), self.now)
        self.assertEqual(len(idx.bg), 4)
        self.assertTrue({"b5", "b6", "b7"} <= set(idx.bg))
        self.assertNotIn("b0", idx.notifs)

    def test_session_eviction_cancels_its_backfill(self):
        pad = [ft.r_assistant_text(self.now - 1000, f"p{i}", "z" * 3000) for i in range(120)]
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 2000), *pad])
        c = collector(self.t)
        now = now_ms()
        c.discover(now, Budget(TICK_READ_CAP))
        c.tick(now, Budget(TICK_READ_CAP))
        self.assertTrue(c.backfill.pending())
        c._drop_session(c.sessions[SID])
        self.assertFalse(c.backfill.pending())
        self.assertEqual(c.backfill.pct(), 100)


# ---- Total size ----
class StateSize9(Base):
    def fill(self, sc, sid, n, now):
        """Feed the real parser to create n active agents in memory without disk writes."""
        c = sc.claude
        s = SessionRec(sid, str(self.t.main_path(sid)))
        s.live = True
        for i in range(n):
            aid = f"a{i:016x}"
            rec = AgentRec(aid, "direct", os.path.join(s.dir, f"agent-{aid}.jsonl"))
            rec.meta = {"description": f"Task {i} " + "Description" * 20, "requestShape": "background", "agentType": "general-purpose"}
            rec.tracked = Tracked(rec.jsonl_path, s.idx, aid)
            rec.tracked.first_done = True
            rec.tracked.bf = "done"
            rec.mtime_ms = now
            lines = [json.dumps(r, ensure_ascii=False).encode() for r in (
                ft.r_assistant_text(now - 100, "m1", "Progress " + "가나다" * 40),
                ft.r_assistant_tool(now - 50, "m2", "t1", "Grep", {"pattern": "x" * 50}),
            )]
            c._feed(rec.tracked, lines)
            s.agents[aid] = rec
        c.sessions[sid] = s
        return s

    def sid(self, i):
        return f"11111111-2222-4333-8444-{i:012x}"

    def test_review_30_sessions_of_50_active_agents(self):
        server = self.live()
        sc = server.sc
        now = now_ms()
        for i in range(30):
            self.fill(sc, self.sid(i), 50, now)
        raw = sum(len(model.dumps(sc.claude._session_view(s, now)[0])) for s in sc.claude.sessions.values())
        self.assertGreater(raw, STATE_JSON_MAX)  # Input deliberately exceeds the response cap.
        sc._publish(now)
        code, body, _ = server.get("/api/state")
        self.assertEqual(code, 200)
        self.assertLessEqual(len(body), STATE_JSON_MAX)
        d = json.loads(body)
        self.assertTrue(d["server"]["truncated"])
        shown = sum(len(s["agents"]) for s in d["sessions"])
        omitted = d["server"]["omitted"]["agents"]
        self.assertEqual(shown + omitted, 1500)
        self.assertEqual(omitted, sum(s.get("agents_omitted", 0) for s in d["sessions"]))
        self.assertEqual(d["counts"]["agents_running"], 1500)  # Keep the full counts.

    def test_cut_agents_leave_detail_index(self):
        server = self.live()
        now = now_ms()
        for i in range(30):
            self.fill(server.sc, self.sid(i), 50, now)
        server.sc._publish(now)
        d = json.loads(server.sc.snapshot.body)
        kept = {(s["id"], a["agent_id"]) for s in d["sessions"] for a in s["agents"]} | {(s["id"], "main") for s in d["sessions"]}
        self.assertEqual(set(server.sc.snapshot.index), kept)

    def view_row(self, i, pad=2000):
        return {"agent_id": f"a{i}", "status": "running", "agent_type": "x", "pad": "x" * pad}

    def state(self, sessions, agents, bg=0, codex=0, wf=0):
        return {
            "server": {"truncated": False}, "counts": {}, "projects": [{"key": "k", "session_ids": [f"s{i}" for i in range(sessions)]}],
            "sessions": [{
                "id": f"s{i}", "agents": [self.view_row(j) for j in range(agents)], "main": {"pad": "m" * 2000},
                "workflows": [{"status": "running", "agents": [self.view_row(j) for j in range(agents)]} for _ in range(wf)],
            } for i in range(sessions)],
            "bg_tasks": [{"status": "running", "pad": "b" * 1000} for _ in range(bg)],
            "codex_runs": [{"status": "running", "thread_id": str(i), "pad": "c" * 1000} for i in range(codex)],
        }

    def test_progressive_steps_always_fit(self):
        for shape in ((30, 50), (5, 400), (300, 10), (40, 40, 800, 100, 2)):
            with self.subTest(shape):
                s = self.state(*shape)
                body = model.finalize_json(s)
                self.assertLessEqual(len(body), STATE_JSON_MAX)
                self.assertTrue(s["server"]["truncated"])
                self.assertTrue(s["server"]["omitted"])

    def test_last_resort_drops_whole_sessions_with_count(self):
        s = self.state(2000, 0)
        body = model.finalize_json(s)
        self.assertLessEqual(len(body), STATE_JSON_MAX)
        self.assertEqual(len(s["sessions"]) + s["sessions_omitted"], 2000)
        self.assertEqual(s["server"]["omitted"]["sessions"], s["sessions_omitted"])
        self.assertEqual(len(s["projects"][0]["session_ids"]), len(s["sessions"]))

    def test_finished_rows_are_counted_when_dropped(self):
        s = self.state(1, 0)
        s["sessions"][0]["agents"] = [dict(self.view_row(i, 30_000), status="finished") for i in range(50)]
        model.finalize_json(s)
        self.assertEqual(s["sessions"][0]["agents_omitted"], 50)
        self.assertEqual(s["server"]["omitted"]["agents"], 50)

    def test_ui_reads_every_omitted_kind(self):
        html = (Path(HERE).parent / "static" / "index.html").read_text(encoding="utf-8")
        for key in ("agents:", "workflow_agents:", "workflows:", "bg:", "codex:", "sessions:", "hot_files:"):
            self.assertIn(key, html)
        for field in ("agents_omitted", "workflows_omitted", "bg_omitted", "server.omitted"):
            self.assertIn(field, html)

    def test_hot_cap_reports_truncated_with_count(self):
        server = self.live()
        server.sc.claude.hot_deferred = 7
        server.sc._publish(now_ms())
        d = server.state()
        self.assertTrue(d["server"]["truncated"])
        self.assertEqual(d["server"]["omitted"]["hot_files"], 7)


# ---- #10 HOT_MAX ----
class HotMax10(Base):
    def build_run(self, n):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 1000), ft.r_workflow_launch(self.now - 900, RUN)])
        agents = {f"a{i:016x}": [ft.r_assistant_tool(self.now - 100, "m1", "t1", "Bash")] for i in range(n)}
        journal = [{"type": "started", "agentId": a, "label": a[-3:], "phase": "P"} for a in agents]
        self.t.add_run(SID, RUN, journal, agents)
        return list(agents)

    def test_review_every_reader_is_read_within_bound(self):
        ids = self.build_run(12)  # Reduce the cap to eight while preserving the workload shape: thirteen main/agent files.
        c = collector(self.t)
        polls: dict[str, int] = {}
        real = c._poll

        def counting(owner, t, budget):
            polls[t.owner or "main"] = polls.get(t.owner or "main", 0) + 1
            return real(owner, t, budget)

        with mock.patch.object(cc, "HOT_MAX", 8), mock.patch.object(cc, "HOT_RR_SLOTS", 2), mock.patch.object(c, "_poll", counting):
            now = now_ms()
            c.discover(now, Budget(TICK_READ_CAP))
            c.tick(now, Budget(TICK_READ_CAP))
            polls.clear()
            bound = math.ceil((13 - (8 - 2)) / 2)
            for _ in range(bound + 1):
                c.tick(now, Budget(TICK_READ_CAP))
            self.assertTrue(c.truncated)
            self.assertTrue(set(ids) <= set(polls), set(ids) - set(polls))

    def test_new_write_in_excluded_file_reaches_api_within_bound(self):
        ids = self.build_run(12)
        run_dir = self.t.session_dir(SID) / "subagents" / "workflows" / RUN
        c = collector(self.t)
        with mock.patch.object(cc, "HOT_MAX", 8), mock.patch.object(cc, "HOT_RR_SLOTS", 2):
            now = now_ms()
            c.discover(now, Budget(TICK_READ_CAP))
            for _ in range(8):
                c.tick(now, Budget(TICK_READ_CAP))
            c.build(now)
            aid = ids[-1]
            ft.write_jsonl(run_dir / f"agent-{aid}.jsonl", [ft.r_assistant_text(now_ms(), "m9", "New record")])
            for _ in range(5):
                c.tick(now_ms(), Budget(TICK_READ_CAP))
            v = c.build(now_ms())
        row = next(a for a in v["sessions"][0]["workflows"][0]["agents"] if a["agent_id"] == aid)
        self.assertEqual(row["last_text"], "New record")

    def test_bound_holds_for_1000_files(self):
        c = collector(self.t)

        class T:
            def __init__(self, i):
                self.mtime_ms = i
                self.polled_tick = 0

        rows = [(None, T(i)) for i in range(1000)]
        waits = {id(t): 0 for _, t in rows}
        worst = 0
        for tick in range(1, 60):
            c.tick_no = tick
            for _, t in c._pick_hot(list(rows)):
                t.polled_tick = tick
                waits[id(t)] = 0
            for _, t in rows:
                waits[id(t)] += 1
            worst = max(worst, max(waits.values()))
        self.assertLessEqual(worst, math.ceil((1000 - 150) / 50) + 1)

    def test_due_files_read_first_when_budget_is_short(self):
        c = collector(self.t)

        class T:
            def __init__(self, i):
                self.mtime_ms = 1000 + i
                self.polled_tick = 5

        rows = [(None, T(i)) for i in range(300)]
        rows[-1][1].mtime_ms = 0
        rows[-1][1].polled_tick = 0
        c.tick_no = 6
        picked = c._pick_hot(rows)
        self.assertEqual(picked[0][1].polled_tick, 0)
        self.assertEqual(len(picked), 200)
        self.assertEqual(c.hot_lag, 6)

    def test_healthz_reports_lag(self):
        server = self.live()
        server.sc.tick_once()
        d = json.loads(server.get("/healthz")[1])
        self.assertIn("hot_lag_ticks", d)
        self.assertIn("hot_deferred", d)


# ---- #11 ETag ----
class Etag11(Base):
    def test_review_new_process_never_answers_304_to_old_etag(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 100, text="a")])
        a = self.live()
        a.publish()
        etag = a.get("/api/state")[2]["ETag"]
        other = Tree("r012e")
        other.add_registry(SID2)
        other.add_main(SID2, [ft.r_prompt(self.now - 100, text="b")])
        b = self.live(other)
        b.publish()
        self.assertEqual(a.sc.version, b.sc.version)  # Version numbers alone would be equal.
        code, body, h = b.get("/api/state", headers={"If-None-Match": etag})
        self.assertEqual(code, 200)
        self.assertNotEqual(h["ETag"], etag)
        self.assertIn(SID2.encode(), body)

    def test_same_process_still_answers_304(self):
        self.t.add_registry(SID)
        self.t.add_main(SID, [ft.r_prompt(self.now - 100)])
        a = self.live()
        a.publish()
        etag = a.get("/api/state")[2]["ETag"]
        self.assertEqual(a.get("/api/state", headers={"If-None-Match": etag})[0], 304)

    def test_ui_clears_etag_on_connection_error(self):
        html = (Path(HERE).parent / "static" / "index.html").read_text(encoding="utf-8")
        catch = html[html.index("async function loop()"):html.index("function okBeat()")]
        self.assertIn("S.etag = null", catch[catch.index("catch (e)"):])


# ---- Concurrency ----
class Concurrency12(Base):
    def connect(self, port):
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        return s

    def wait_slots(self, server, want):
        for _ in range(100):
            if server.app.server.slots._value == want:
                return True
            time.sleep(0.02)
        return False

    def test_review_connections_beyond_cap_get_503_without_a_thread(self):
        server = self.live()
        held = [self.connect(server.port) for _ in range(MAX_HANDLERS)]
        self.assertTrue(self.wait_slots(server, 0))
        before = threading.active_count()
        extra = [self.connect(server.port) for _ in range(40)]
        answers = []
        for s in extra:
            s.settimeout(5)
            data = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            answers.append(data)
            s.close()
        self.assertEqual(threading.active_count(), before)
        self.assertTrue(all(a.startswith(b"HTTP/1.1 503 ") for a in answers), answers[:2])
        self.assertIn(b"Connection: close", answers[0])
        self.assertIn(b"X-Content-Type-Options: nosniff", answers[0])
        held.pop().close()
        self.assertTrue(self.wait_slots(server, 1))
        self.assertEqual(server.get("/healthz")[0], 200)
        for s in held:
            s.close()

    def test_slot_returns_after_each_request(self):
        server = self.live()
        for _ in range(MAX_HANDLERS * 3):
            self.assertEqual(server.get("/healthz")[0], 200)
        self.assertTrue(self.wait_slots(server, MAX_HANDLERS))
        self.assertEqual(server.app.server.deadlines, {})

    def test_review_trickling_request_hits_total_deadline(self):
        server = self.live()
        with mock.patch.object(srv, "REQUEST_DEADLINE_S", 0.4):
            s = self.connect(server.port)
            t0 = time.monotonic()
            closed = False
            for ch in (b"GET /healthz HTTP/1.1\r\n" + b"X-Pad: " + b"a" * 200):
                try:
                    s.sendall(bytes([ch]))
                except OSError:
                    closed = True
                    break
                time.sleep(0.02)
                if time.monotonic() - t0 > 4:
                    break
            if not closed:
                s.settimeout(3)
                try:
                    closed = s.recv(4096) == b""
                except OSError:
                    closed = True
            elapsed = time.monotonic() - t0
            s.close()
        self.assertTrue(closed)
        self.assertLess(elapsed, 4)  # Ends well before the 15-second socket timeout.
        self.assertTrue(self.wait_slots(server, MAX_HANDLERS))

    def test_idle_keepalive_is_rearmed_per_request(self):
        server = self.live()
        with mock.patch.object(srv, "REQUEST_DEADLINE_S", 1.0):
            c = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
            for _ in range(3):
                c.putrequest("GET", "/healthz", skip_host=True, skip_accept_encoding=True)
                c.putheader("Host", f"127.0.0.1:{server.port}")
                c.endheaders()
                r = c.getresponse()
                r.read()
                self.assertEqual(r.status, 200)
                time.sleep(0.45)
            c.close()


# ---- Additional regressions ----
class Optional(Base):
    def test_same_notification_shows_once_in_drawer(self):
        text = ft.notification("bx1234567", "completed")
        self.t.add_registry(SID)
        self.t.add_main(SID, [
            ft.r_notify_queue(self.now - 300, text, "enqueue"),
            ft.r_notify_attachment(self.now - 200, text),
            ft.r_notify_user(self.now - 100, text),
        ])
        server = self.live()
        server.publish()
        events = json.loads(server.agent()[1])["events"]
        self.assertEqual(len([e for e in events if e["kind"] == "notification"]), 1)

    def test_backfilled_bg_description_has_no_prefix(self):
        pad = [ft.r_assistant_text(self.now - 1000, f"m{i}", "z" * 3000) for i in range(100)]
        self.t.add_registry(SID)
        self.t.add_main(SID, [*self.bg_start(), *pad])
        self.t.add_output(SID, "bx1234567")
        self.view()
        self.assertEqual(self.v["bg_tasks"][0]["description"], "Server")




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
