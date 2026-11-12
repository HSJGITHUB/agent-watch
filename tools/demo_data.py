"""Generate synthetic dashboard inputs without accessing real agent homes."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shlex
import time


def iso(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def prompt(ms, text):
    return {"type": "user", "timestamp": iso(ms), "cwd": "C:/work/developer_day",
            "origin": {"kind": "human"}, "message": {"content": text}}


def assistant(ms, ident, tool=None, inputs=None, text="", done=False):
    content = ([{"type": "tool_use", "id": ident, "name": tool, "input": inputs or {}}]
               if tool else [{"type": "text", "text": text}])
    return {"type": "assistant", "timestamp": iso(ms), "message": {
        "id": ident, "model": "claude-sonnet-4-5", "stop_reason": "end_turn" if done else "tool_use",
        "content": content, "usage": {"input_tokens": 3240, "cache_creation_input_tokens": 1820,
                                    "cache_read_input_tokens": 18360, "output_tokens": 976}}}


def result(ms, ident, extra):
    return {"type": "user", "timestamp": iso(ms), "message": {"content": [
        {"type": "tool_result", "tool_use_id": ident, "content": "Started"}]}, "toolUseResult": extra}


def generate(out_dir):
    """Require an existing parent and a new/empty destination; do not overwrite data."""
    root = Path(out_dir).absolute()
    if root.is_symlink() or (hasattr(root, "is_junction") and root.is_junction()):
        raise ValueError("OUT_DIR must not be a link")
    root.mkdir(exist_ok=True)
    if any(root.iterdir()):
        raise ValueError("OUT_DIR must be new or empty; choose a fresh directory to refresh the demo")
    root = root.resolve()
    now = int(time.time() * 1000)

    def write(relative, value, age=0, lines=False):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        body = "\n".join(json.dumps(r, ensure_ascii=False) for r in value) if lines else json.dumps(value, ensure_ascii=False)
        path.write_text(body + "\n", encoding="utf-8", newline="\n")
        os.utime(path, ((now - age) / 1000,) * 2)

    for name in ("claude/sessions", "codex/sessions", "temp", "state"):
        (root / name).mkdir(parents=True, exist_ok=True)
    slug = "C--work-developer-day"
    project = f"claude/projects/{slug}"
    titles = ["Ship checkout A/B test", "Nightly data pipeline", "Refactor auth middleware",
              "Weekly metrics report", "Investigate flaky e2e tests", "Docs: API reference refresh"]
    sessions = [f"11111111-2222-4333-8444-{i + 1:012d}" for i in range(6)]
    for i, (sid, title) in enumerate(zip(sessions, titles)):
        start = now - (48 - i * 4) * 60_000
        records = [{"type": "ai-title", "aiTitle": title}, prompt(start, title)]
        if i == 0:
            for j, description in enumerate(("Watch unit tests", "Build docs site", "Load test against staging")):
                tid, toolid = f"bdemo00{j + 1}", f"shell-{j}"
                records += [assistant(start + 60_000 + j * 1000, toolid, "Bash", {
                    "command": "python -m unittest", "description": description, "run_in_background": True}),
                    result(start + 60_100 + j * 1000, toolid, {"backgroundTaskId": tid})]
                write(f"temp/{slug.lower()}/{sid}/tasks/{tid}.output", "Synthetic progress", age=1000 if j == 0 else 180_000)
                if j == 1:
                    notice = (f"<task-notification><task-id>{tid}</task-id><tool-use-id>{toolid}</tool-use-id>"
                              '<status>completed</status><summary>Background command "Build docs site" completed (exit code 0)</summary></task-notification>')
                    records.append({"type": "user", "timestamp": iso(now - 120_000),
                                    "origin": {"kind": "task-notification", "producer": "session-task"},
                                    "message": {"content": notice}})
            for j, (kind, description, tool, inputs, age) in enumerate([
                ("Explore", "Find payment retry handler", "Grep", {"pattern": "payment retry handler"}, 2000),
                ("general-purpose", "Update auth middleware", "Edit", {"file_path": "src/auth/middleware.ts"}, 110_000),
                ("general-purpose", "Verify checkout tests", "Bash", {"description": "run unit tests"}, 180_000),
            ]):
                aid = f"a{j + 1:015x}"
                recs = [prompt(start + 120_000, description), assistant(now - age, f"agent-{j}", tool, inputs)]
                if j == 2:
                    recs.append(assistant(now - age + 1000, "verified", text="Checkout tests passed.", done=True))
                base = f"{project}/{sid}/subagents/agent-{aid}"
                write(base + ".jsonl", recs, lines=True, age=age - 1000)
                write(base + ".meta.json", {"agentType": kind, "description": description,
                      "requestShape": "background", "finished": j == 2})
        if i == 1:
            run = "wf_12345678-demo"
            records += [assistant(start + 60_000, "workflow", "Workflow"),
                        result(start + 60_100, "workflow", {"status": "async_launched", "taskId": "wdemo001",
                               "taskType": "local_workflow", "runId": run, "workflowName": "Pipeline quality checks"})]
            journal = [{"type": "launched", "timestamp": iso(start + 60_000)}]
            for j, (label, phase) in enumerate((("Review schema", "Review"), ("Review retries", "Review"), ("Verify pipeline", "Verify"))):
                aid = f"a{j + 10:015x}"
                journal.append({"type": "started", "key": f"check:{j}", "agentId": aid, "label": label, "phase": phase})
                if j < 2:
                    journal.append({"type": "result", "agentId": aid, "result": {}})
                base = f"{project}/{sid}/subagents/workflows/{run}/agent-{aid}"
                write(base + ".jsonl", [prompt(start + 180_000, label),
                      assistant(now - 3000, f"check-{j}", "Bash", {"description": "run pipeline validation"})], lines=True)
                write(base + ".meta.json", {"agentType": "workflow-subagent", "description": label,
                      "workflowPhase": phase, "requestShape": "foreground"})
            write(f"{project}/{sid}/subagents/workflows/{run}/journal.jsonl", journal, lines=True)
        # Headless sessions with child activity are visible in the UI's active view.
        if i in (2, 4):
            child_age = 2000 if i == 2 else 18 * 60_000
            aid = f"a{i + 20:015x}"
            description = "Check middleware behavior" if i == 2 else "Trace flaky browser timeout"
            base = f"{project}/{sid}/subagents/agent-{aid}"
            write(base + ".jsonl", [prompt(start + 120_000, description),
                  assistant(now - child_age, f"worker-{i}", "Bash", {"description": description})],
                  age=child_age, lines=True)
            write(base + ".meta.json", {"agentType": "general-purpose", "description": description,
                  "requestShape": "background"})
        age = 18 * 60_000 if i == 4 else 2000
        if i == 3:
            records.append(assistant(now - 120_000, "main", "AskUserQuestion", {"questions": [{"question": "Which reporting window should we use?"}]}))
        elif i == 5:
            records.append(assistant(now - 240_000, "main", text="API examples refreshed and links checked.", done=True))
            write("claude/sessions/0.json", {"pid": 0, "sessionId": sid, "cwd": "C:/work/developer_day", "status": "idle"})
        else:
            records.append(assistant(now - age, "main", "Bash", {"description": [
                "run checkout tests", "validate daily partitions", "check middleware types", "", "rerun flaky browser tests"][i]}))
        write(f"{project}/{sid}.jsonl", records, age=age, lines=True)

    for i, task in enumerate(("billing_api_v2", "e2e_flake_triage", "docs_refresh")):
        start = now - (35 + i * 7) * 60_000
        uid = f"019a0000-0000-7000-8000-{i + 1:012d}"
        def event(ms, kind, **payload):
            return {"timestamp": iso(ms), "type": "event_msg", "payload": {"type": kind, **payload}}
        recs = [{"timestamp": iso(start), "type": "session_meta", "payload": {
                    "id": uid, "cwd": f"C:/work/{task}", "originator": "codex_exec", "source": "exec", "cli_version": "0.153.4"}},
                {"timestamp": iso(start), "type": "turn_context", "payload": {
                    "model": "gpt-6-astra", "effort": "high", "sandbox_policy": {"type": "workspace-write"}}},
                event(start, "task_started", turn_id="turn-1", started_at=start // 1000),
                event(now - 5000, "token_count", info={"total_token_usage": {
                    "input_tokens": 24120 + i * 3900, "cached_input_tokens": 18400,
                    "output_tokens": 4230, "reasoning_output_tokens": 1620, "total_tokens": 28350 + i * 3900}},
                    rate_limits={"primary": {"used_percent": 47, "window_minutes": 10080,
                                             "resets_at": now // 1000 + 3 * 86400}, "plan_type": "pro"})]
        if i == 2:
            recs.append(event(now - 4000, "task_complete", turn_id="turn-1", last_agent_message="Reference pages updated.",
                              completed_at=(now - 4000) // 1000, duration_ms=now - 4000 - start))
        else:
            command = "python -m unittest tests.test_billing" if i == 0 else "npm run test:e2e"
            recs.append({"timestamp": iso(now - 2000), "type": "response_item", "payload": {
                "type": "custom_tool_call", "name": "exec", "call_id": "command-1",
                "input": 'text(await tools.exec_command(' + json.dumps({"cmd": command}) + '));'}})
        date = datetime.fromtimestamp(start / 1000, timezone.utc)
        write(f"codex/sessions/{date:%Y/%m/%d}/rollout-{date:%Y-%m-%dT%H-%M-%S}-{uid}.jsonl", recs, lines=True)
    return root


def server_command(root):
    args = ["python", "-B", "server.py", "--claude-home", str(root / "claude"),
            "--codex-home", str(root / "codex"), "--temp-claude", str(root / "temp"),
            "--state-dir", str(root / "state"), "--port", "8815"]
    if os.name == "nt":
        # PowerShell single quotes preserve spaces, dollar signs and apostrophes.
        return " ".join("'" + arg.replace("'", "''") + "'" if i in (4, 6, 8, 10) else arg
                        for i, arg in enumerate(args))
    return shlex.join(args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out_dir", type=Path)
    args = parser.parse_args()
    try:
        root = generate(args.out_dir)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    print(server_command(root))


if __name__ == "__main__":
    main()