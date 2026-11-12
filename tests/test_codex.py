import json
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import fixture_tree as ft  # noqa: E402
from collect_codex import CMD_RE, CodexCollector, filename_start_ms  # noqa: E402
from config import TICK_READ_CAP  # noqa: E402
from fixture_tree import Tree, iso  # noqa: E402
from masking import PRIVATE  # noqa: E402
from tailreader import Budget  # noqa: E402

T = int(time.time() * 1000) - 60_000
UUID = "019a0000-0000-7000-8000-000000000001"


def meta(cwd="C:\\work\\task_x", ts=T, **kw):
    p = {"id": UUID, "session_id": UUID, "cwd": cwd, "originator": "codex_exec", "cli_version": "0.153.4", "source": "exec", "base_instructions": {"text": "hidden"}}
    p.update(kw)
    return {"timestamp": iso(ts), "ordinal": 0, "type": "session_meta", "payload": p}


def turn_ctx(ts=T):
    return {"timestamp": iso(ts), "type": "turn_context", "payload": {"model": "gpt-6-astra", "effort": "high", "sandbox_policy": {"type": "workspace-write"}, "cwd": "c:\\x"}}


def ev(ts, **p):
    return {"timestamp": iso(ts), "type": "event_msg", "payload": p}


def started(ts=T):
    return ev(ts, type="task_started", turn_id="t1", started_at=ts // 1000)


def complete(ts, **kw):
    d = dict(type="task_complete", turn_id="t1", last_agent_message="Final answer first line\nSecond line", completed_at=ts // 1000, duration_ms=1000)
    d.update(kw)
    return ev(ts, **d)


def exec_call(ts, cmd_js, call="c1"):
    return {"timestamp": iso(ts), "type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": call, "status": "completed", "input": f'text(await tools.exec_command({{cmd:"{cmd_js}",shell:"bash"}}));\n'}}


def exec_output(ts, call="c1", output="hidden"):
    return {"timestamp": iso(ts), "type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": call, "output": output}}


def poll_call(ts, chars="", call="c2"):
    return {"timestamp": iso(ts), "type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": call, "input": f'const r=await tools.write_stdin({{session_id:1,chars:"{chars}",yield_time_ms:1000}});'}}


def cmd_done(ts, text="ls", exit_code=0):
    return ev(ts, type="item_completed", item={"type": "CommandExecution", "command": ["bash", "-lc", text], "parsed_cmd": [{"type": "list_files", "cmd": text}], "status": "completed", "exit_code": exit_code, "stdout": "hidden", "aggregated_output": "hidden", "formatted_output": "hidden"}, started_at_ms=ts - 1000, completed_at_ms=ts)


def tokens(ts, total=100, pct=None, resets=1793774189):
    p = dict(type="token_count", info={"total_token_usage": {"input_tokens": 60, "cached_input_tokens": 10, "output_tokens": 40, "reasoning_output_tokens": 5, "total_tokens": total}})
    if pct is not None:
        p["rate_limits"] = {"limit_id": "codex", "primary": {"used_percent": pct, "window_minutes": 10080, "resets_at": resets}, "secondary": None, "credits": {"balance": "1"}, "plan_type": "pro"}
    return ev(ts, **p)


class Base(unittest.TestCase):
    def setUp(self):
        self.t = Tree("codex")
        self.c = CodexCollector(self.t.paths())

    def run_once(self, now=None, n=1):
        now = now or int(time.time() * 1000)
        self.c.discover(now, Budget(TICK_READ_CAP))
        for _ in range(n):
            self.c.tick(now, Budget(TICK_READ_CAP))
        return self.c.build(now)


class Parse(Base):
    def test_meta_and_context(self):
        self.t.add_rollout([meta(), started(), turn_ctx()])
        runs, _, _ = self.run_once()
        r = runs[0]
        self.assertEqual(r["packet"], "task_x")
        self.assertEqual((r["model"], r["effort"], r["sandbox"]), ("gpt-6-astra", "high", "workspace-write"))
        self.assertEqual(r["source_kind"], "exec")
        self.assertEqual(r["thread_id"], UUID)

    def test_first_line_longer_than_tail_uses_regex(self):
        huge = meta(base_instructions={"text": "x" * 600_000})
        self.t.add_rollout([huge, started(), turn_ctx()] + [tokens(T + i) for i in range(5)])
        runs, _, _ = self.run_once()
        self.assertEqual(runs[0]["packet"], "task_x")

    def test_long_meta_regex_only(self):
        # A first line longer than the 256KB head window cannot be parsed as JSON.
        huge = meta(base_instructions={"text": "x" * 400_000})
        self.t.add_rollout([huge, started(), turn_ctx()] + [ev(T + 1, type="brand_new", pad="y" * 300_000)])
        runs, _, _ = self.run_once()
        self.assertEqual(runs[0]["packet"], "task_x")

    def test_subagent_source(self):
        parent = "019a0000-0000-7000-8000-00000000000a"
        self.t.add_rollout([meta(source={"subagent": {"thread_spawn": {"parent_thread_id": parent, "depth": 1}}}), started()])
        r = self.run_once()[0][0]
        self.assertEqual((r["source_kind"], r["parent_thread_id"]), ("subagent", parent))

    def test_guardian_source(self):
        self.t.add_rollout([meta(source={"subagent": {"other": "guardian"}}), started()])
        self.assertEqual(self.run_once()[0][0]["source_kind"], "guardian")

    def test_finished(self):
        self.t.add_rollout([meta(), started(), turn_ctx(), complete(T + 30_000)])
        r = self.run_once()[0][0]
        self.assertEqual((r["status"], r["outcome"]), ("finished", "completed"))
        self.assertEqual(r["finished_ms"], (T + 30_000) // 1000 * 1000)
        self.assertEqual(r["last_message"], "Final answer first line")
        self.assertEqual(r["turns"], {"started": 1, "completed": 1, "exact": True})

    def test_info_null(self):
        self.t.add_rollout([meta(), started(), ev(T, type="token_count", info=None, rate_limits=None), tokens(T + 1, 50), ev(T + 2, type="token_count", info=None)])
        self.assertEqual(self.run_once()[0][0]["tokens"]["total"], 50)

    def test_unknown_events_ignored(self):
        self.t.add_rollout([meta(), started(), ev(T, type="brand_new_event", x=1), {"timestamp": iso(T), "type": "brand_new_top", "payload": {}}, {"type": "x"}])
        self.assertEqual(self.c.stats.parse_errors, 0)
        self.assertEqual(len(self.run_once()[0]), 1)

    def test_abort_event_marks_other(self):
        self.t.add_rollout([meta(), started(), ev(T, type="turn_aborted")])
        self.run_once()
        rec = next(iter(self.c.runs.values()))
        self.assertEqual(rec.outcome, "other")

    def test_heavy_fields_not_retained(self):
        self.t.add_rollout([meta(), started(), cmd_done(T + 1, "ls")])
        runs, _, _ = self.run_once()
        self.assertNotIn("hidden", json.dumps(runs, ensure_ascii=False))


class Commands(Base):
    def test_cmd_regex_escaped_quote(self):
        m = CMD_RE.search(r'tools.exec_command({cmd:"echo \"hi\" there",shell:"x"})')
        self.assertEqual(m.group(1), r"echo \"hi\" there")

    def test_cmd_regex_quoted_key(self):
        self.assertEqual(CMD_RE.search('{"cmd":"ls -la"}').group(1), "ls -la")

    def test_cmd_regex_template_literal(self):
        self.assertEqual(CMD_RE.search("{cmd:`ls\\n-la`}").group(2), "ls\\n-la")

    def test_running_command(self):
        self.t.add_rollout([meta(), started(), exec_call(T + 1, "pytest -q")])
        lc = self.run_once()[0][0]["last_command"]
        self.assertEqual((lc["text"], lc["state"], lc["since_ms"]), ("pytest -q", "running", T + 1))

    def test_heredoc_first_line_only(self):
        self.t.add_rollout([meta(), started(), exec_call(T + 1, "python - <<'PY'\\nimport os\\nprint(os.getcwd())\\nPY")])
        self.assertEqual(self.run_once()[0][0]["last_command"]["text"], "python - <<'PY'")

    def test_secret_in_command_masked(self):
        fake = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"
        self.t.add_rollout([meta(), started(), exec_call(T + 1, f"curl -H token:{fake} x")])
        self.assertNotIn(fake, self.run_once()[0][0]["last_command"]["text"])

    def test_command_survives_output_until_item_completed(self):
        # Long-running commands return session_id instead of exit_code.
        out = 'Script completed\nOutput:\n{"wall_time_seconds":30.0,"session_id":7}'
        self.t.add_rollout([meta(), started(), exec_call(T + 1, "sleep 500"), exec_output(T + 30_000, output=out), poll_call(T + 40_000), poll_call(T + 50_000, call="c3")])
        lc = self.run_once()[0][0]["last_command"]
        self.assertEqual((lc["text"], lc["state"], lc["since_ms"]), ("sleep 500", "running", T + 1))

    def test_item_completed_finishes_command(self):
        self.t.add_rollout([meta(), started(), exec_call(T + 1, "sleep 500"), cmd_done(T + 40_000, "sleep 500", 3)])
        lc = self.run_once()[0][0]["last_command"]
        self.assertEqual((lc["state"], lc["exit_code"], lc["text"]), ("done", 3, "sleep 500"))

    def test_multiple_exec_in_one_call(self):
        inp = 'text(await tools.exec_command({cmd:"first"}));text(await tools.exec_command({cmd:"second"}));'
        rec = {"timestamp": iso(T + 1), "type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c1", "input": inp}}
        self.t.add_rollout([meta(), started(), rec, cmd_done(T + 2, "first")])
        lc = self.run_once()[0][0]["last_command"]
        self.assertEqual((lc["text"], lc["state"]), ("second", "running"))

    def test_other_tool_name_only(self):
        rec = {"timestamp": iso(T + 1), "type": "response_item", "payload": {"type": "custom_tool_call", "name": "exec", "call_id": "c1", "input": "tools.web__run({q:\"hidden\"})"}}
        self.t.add_rollout([meta(), started(), rec])
        self.assertEqual(self.run_once()[0][0]["last_command"]["text"], "web__run")

    def test_function_call_wait_tracked(self):
        a = {"timestamp": iso(T + 1), "type": "response_item", "payload": {"type": "function_call", "name": "wait", "call_id": "f1", "arguments": "{}"}}
        self.t.add_rollout([meta(), started(), a])
        self.run_once()
        self.assertEqual(next(iter(self.c.runs.values())).pending_wait, "wait")

    def test_complete_clears_running(self):
        self.t.add_rollout([meta(), started(), exec_call(T + 1, "x"), complete(T + 5000)])
        self.run_once()
        self.assertFalse(next(iter(self.c.runs.values())).running)


class Usage(Base):
    def test_max_timestamp_wins(self):
        self.t.add_rollout([meta(), started(), tokens(T + 5000, pct=79.0)], uuid="019a0000-0000-7000-8000-000000000002")
        self.t.add_rollout([meta(), started(), tokens(T + 1000, pct=70.0)], when=time.time() - 3600, uuid="019a0000-0000-7000-8000-000000000003")
        _, u, _ = self.run_once()
        self.assertEqual(u["windows"][0]["used_percent"], 79.0)
        self.assertEqual(u["snapshot_ms"], T + 5000)

    def test_older_file_with_newer_record(self):
        self.t.add_rollout([meta(), started(), tokens(T + 9000, pct=81.0)], when=time.time() - 7200, uuid="019a0000-0000-7000-8000-000000000004")
        self.t.add_rollout([meta(), started(), tokens(T + 1000, pct=60.0)], uuid="019a0000-0000-7000-8000-000000000005")
        _, u, _ = self.run_once()
        self.assertEqual(u["windows"][0]["used_percent"], 81.0)

    def test_tags_levels(self):
        self.t.add_rollout([meta(), started(), tokens(T, pct=85.0)])
        _, u, _ = self.run_once()
        w = u["windows"][0]
        self.assertEqual((w["tag"], w["level"], w["resets_at_ms"]), ("WK", "crit", 1793774189000))
        self.assertEqual(u["plan"], "pro")

    def test_secondary_5h(self):
        p = dict(type="token_count", rate_limits={"primary": {"used_percent": 10.0, "window_minutes": 10080, "resets_at": 1}, "secondary": {"used_percent": 60.0, "window_minutes": 300, "resets_at": 2}})
        self.t.add_rollout([meta(), started(), ev(T, **p)])
        _, u, _ = self.run_once()
        self.assertEqual([(w["tag"], w["level"]) for w in u["windows"]], [("WK", "ok"), ("5H", "warn")])

    def test_credits_not_exposed(self):
        self.t.add_rollout([meta(), started(), tokens(T, pct=1.0)])
        _, u, _ = self.run_once()
        self.assertNotIn("balance", json.dumps(u))

    def test_fallback_when_recent_folders_empty(self):
        old = time.time() - 6 * 86400
        p = self.t.add_rollout([meta(), started(), tokens(T - 5 * 86_400_000, pct=33.0)], when=old)
        self.assertTrue(p.exists())
        _, u, _ = self.run_once()
        self.assertEqual(u["windows"][0]["used_percent"], 33.0)


class Liveness(Base):
    def test_stale_mtime_with_growth_is_running(self):
        now = int(time.time() * 1000)
        p = self.t.add_rollout([meta(ts=now - 2 * 3600_000), started(now - 2 * 3600_000), turn_ctx(now - 2 * 3600_000)])
        old = now - 2 * 3600_000
        ft.set_mtime(p, old)
        runs, _, _ = self.run_once(now)
        self.assertEqual(runs[0]["status"], "stalled")
        size = p.stat().st_size
        ft.write_jsonl(p, [ev(now - 2 * 3600_000 + 1, type="brand_new")])  # Old timestamp but increased size.
        ft.set_mtime(p, old)
        self.assertGreater(p.stat().st_size, size)
        self.c.tick(now, Budget(TICK_READ_CAP))
        runs, _, _ = self.c.build(now)
        self.assertEqual(runs[0]["status"], "running")

    def test_mtime_alone_never_marks_alive(self):
        now = int(time.time() * 1000)
        p = self.t.add_rollout([meta(ts=now - 3 * 3600_000), started(now - 3 * 3600_000)], when=time.time() - 3600)
        ft.set_mtime(p, now)
        runs, _, _ = self.run_once(now)
        self.assertEqual(runs[0]["status"], "stalled")

    def test_filename_time(self):
        self.assertIsNone(filename_start_ms("rollout-x.jsonl"))
        self.assertIsNotNone(filename_start_ms(f"rollout-2026-10-30T17-06-19-{UUID}.jsonl"))

    def test_old_finished_run_skips_head(self):
        now = int(time.time() * 1000)
        pad = [ev(now - 5 * 3600_000, type="brand_new", pad="y" * 2000)] * 200
        self.t.add_rollout([meta(ts=now - 5 * 3600_000), started(now - 5 * 3600_000)] + pad + [complete(now - 4 * 3600_000)], when=time.time() - 5 * 3600)
        runs, _, _ = self.run_once(now)
        self.assertEqual(runs, [])
        self.assertTrue(next(iter(self.c.runs.values())).dormant)

    def test_outside_window_ignored_until_growth(self):
        now = int(time.time() * 1000)
        p = self.t.add_rollout([meta(ts=now - 20 * 3600_000), started(now - 20 * 3600_000)], when=time.time() - 20 * 3600)
        self.c.discover(now, Budget(TICK_READ_CAP))
        self.assertEqual(self.c.runs, {})
        ft.write_jsonl(p, [ev(now, type="brand_new")])
        self.c.discover(now, Budget(TICK_READ_CAP))
        self.assertEqual(len(self.c.runs), 1)


class Privacy(Base):
    def test_denied_packet_hides_run(self):
        self.t.add_rollout([meta(cwd="C:\\x\\interview_materials_task"), started(), exec_call(T + 1, "ls -la")])
        r = self.run_once()[0][0]
        self.assertEqual((r["packet"], r["cwd_display"], r["last_command"]["text"]), (PRIVATE, PRIVATE, PRIVATE))
        self.assertTrue(r["private"])

    def test_denied_packet_hides_last_message(self):
        self.t.add_rollout([meta(cwd="C:\\x\\interview_materials_task"), started(), complete(T + 5000, last_agent_message="Ordinary answer")])
        self.assertEqual(self.run_once()[0][0]["last_message"], PRIVATE)

    def test_denied_cwd_hides_run(self):
        self.t.add_rollout([meta(cwd="C:\\legal\\task_ok"), started(), exec_call(T + 1, "ls -la")])
        r = self.run_once()[0][0]
        self.assertEqual(r["last_command"]["text"], PRIVATE)
        self.assertEqual(r["packet"], PRIVATE)

    def test_denied_command_only(self):
        self.t.add_rollout([meta(), started(), exec_call(T + 1, "cat client-x.txt")])
        r = self.run_once()[0][0]
        self.assertEqual(r["last_command"]["text"], PRIVATE)
        self.assertEqual(r["packet"], "task_x")




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
