"""Generate synthetic source trees without real transcript excerpts. Keep all outputs in tests/_scratch without cleanup."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRATCH = HERE / "_scratch"
CWD = "c:\\fixture\\proj"
SLUG = "C--fixture-proj"
_seq = [0]


def scratch_dir(tag: str = "t") -> Path:
    _seq[0] += 1
    p = SCRATCH / f"{time.strftime('%Y%m%d_%H%M%S')}_{os.getpid()}_{tag}_{_seq[0]}"
    p.mkdir(parents=True, exist_ok=True)
    return p


def iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def write_jsonl(path: Path, records: list[dict], mode: str = "a") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, mode, encoding="utf-8", newline="\n") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")


def set_mtime(path: Path, ms: int) -> None:
    os.utime(path, (ms / 1000, ms / 1000))


# ---- Claude records ----
def r_assistant_tool(ts, mid, tool_id, name, inp=None, stop="tool_use", usage=None):
    return {
        "type": "assistant", "timestamp": iso(ts), "cwd": CWD, "effort": "high",
        "message": {
            "id": mid, "model": "claude-test-1", "stop_reason": stop,
            "content": [{"type": "tool_use", "id": tool_id, "name": name, "input": inp or {}}],
            "usage": usage or {"input_tokens": 100, "cache_creation_input_tokens": 10, "cache_read_input_tokens": 1000, "output_tokens": 50},
        },
    }


def r_assistant_text(ts, mid, text, stop=None, usage=None):
    return {
        "type": "assistant", "timestamp": iso(ts),
        "message": {
            "id": mid, "model": "claude-test-1", "stop_reason": stop,
            "content": [{"type": "text", "text": text}],
            "usage": usage or {"input_tokens": 100, "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0, "output_tokens": 20},
        },
    }


def r_assistant_thinking(ts, mid):
    return {
        "type": "assistant", "timestamp": iso(ts),
        "message": {"id": mid, "model": "claude-test-1", "stop_reason": None, "content": [{"type": "thinking", "thinking": ""}]},
    }


def r_tool_result(ts, tool_id, text="ok", is_error=False, tur=None, ends_turn=False):
    r = {
        "type": "user", "timestamp": iso(ts),
        "message": {"content": [{"type": "tool_result", "tool_use_id": tool_id, "content": text, "is_error": is_error}]},
    }
    if tur is not None:
        r["toolUseResult"] = tur
    if ends_turn:
        r["toolEndsTurn"] = True
    return r


def r_prompt(ts, kind="human", text="Task instructions"):
    r = {"type": "user", "timestamp": iso(ts), "message": {"content": text}}
    if kind:
        r["origin"] = {"kind": kind}
    return r


def r_api_request(ts):
    return {"type": "api-request", "timestamp": iso(ts), "id": "req", "querySource": "sdk", "params": {"model": "claude-test-1"}}


def r_system(ts, subtype, **kw):
    return dict({"type": "system", "subtype": subtype, "timestamp": iso(ts)}, **kw)


def notification(task_id, status="completed", summary="Background command \"x\" completed (exit code 0)", tool_use="toolu_x", usage="", event=False):
    parts = [f"<task-id>{task_id}</task-id>", f"<tool-use-id>{tool_use}</tool-use-id>", "<output-file>C:/x.output</output-file>"]
    if status:
        parts.append(f"<status>{status}</status>")
    parts.append(f"<summary>{summary}</summary>")
    if event:
        parts.append("<event>line</event>")
    if usage:
        parts.append(f"<usage>{usage}</usage>")
    return "<task-notification>\n" + "\n".join(parts) + "\n</task-notification>"


def r_workflow_launch(ts, run_id, name="Synthetic workflow", task_id="wabc12345", tool_id="tw"):
    """Workflow launch result; add to the main transcript to create a named run."""
    return r_tool_result(ts, tool_id, "launched", tur={"status": "async_launched", "taskId": task_id, "taskType": "local_workflow", "runId": run_id, "workflowName": name})


def r_notify_user(ts, text):
    return {"type": "user", "timestamp": iso(ts), "origin": {"kind": "task-notification", "producer": "session-task"}, "message": {"content": text}}


def r_notify_queue(ts, text, op="enqueue"):
    return {"type": "queue-operation", "operation": op, "timestamp": iso(ts), "content": text}


def r_notify_attachment(ts, text):
    return {
        "type": "attachment", "timestamp": iso(ts),
        "attachment": {"type": "queued_command", "commandMode": "task-notification", "prompt": text, "timestamp": iso(ts)},
    }


# ---- Tree ----
class Tree:
    def __init__(self, tag: str = "tree"):
        self.root = scratch_dir(tag)
        self.claude = self.root / "claude"
        self.codex = self.root / "codex"
        self.temp = self.root / "temp"
        self.state = self.root / "state"
        (self.claude / "sessions").mkdir(parents=True)
        (self.claude / "projects" / SLUG).mkdir(parents=True)
        (self.codex / "sessions").mkdir(parents=True)
        self.temp.mkdir(parents=True)

    def paths(self):
        from config import Paths

        return Paths(claude_home=self.claude, codex_home=self.codex, temp_claude=self.temp, state_dir=self.state)

    def main_path(self, sid: str) -> Path:
        return self.claude / "projects" / SLUG / f"{sid}.jsonl"

    def session_dir(self, sid: str) -> Path:
        return self.claude / "projects" / SLUG / sid

    def add_registry(self, sid: str, pid=None, status="busy", proc_start=None, **extra):
        import winproc

        pid = pid if pid is not None else os.getpid()
        if proc_start is None:
            proc_start = str(winproc.process_create_filetime(pid))
        d = {
            "pid": pid, "sessionId": sid, "cwd": CWD, "startedAt": int(time.time() * 1000) - 3600_000,
            "procStart": proc_start, "version": "2.1.301", "kind": "interactive", "entrypoint": "claude-vscode",
            "name": "fixture-ab", "status": status, "statusUpdatedAt": 0, "updatedAt": int(time.time() * 1000),
            "messagingSocketPath": "\\\\.\\pipe\\secret-pipe",
        }
        d.update(extra)
        write_json(self.claude / "sessions" / f"{pid}.json", d)
        # This file must never be opened.
        (self.claude / "sessions" / f"{pid}.abcdef.key").write_text("synthetic-not-a-secret", encoding="utf-8")

    def add_main(self, sid: str, records: list[dict]) -> Path:
        p = self.main_path(sid)
        write_jsonl(p, records)
        return p

    def add_agent(self, sid: str, aid: str, records: list[dict], meta: dict | None = None) -> Path:
        p = self.session_dir(sid) / "subagents" / f"agent-{aid}.jsonl"
        write_jsonl(p, records)
        write_json(p.with_name(f"agent-{aid}.meta.json"), meta or {"agentType": "general-purpose", "description": "Synthetic task", "requestShape": "background"})
        return p

    def add_run(self, sid: str, run_id: str, journal: list[dict], agents: dict[str, list[dict]] | None = None) -> Path:
        d = self.session_dir(sid) / "subagents" / "workflows" / run_id
        write_jsonl(d / "journal.jsonl", journal)
        for aid, recs in (agents or {}).items():
            write_jsonl(d / f"agent-{aid}.jsonl", recs)
            write_json(d / f"agent-{aid}.meta.json", {"agentType": "workflow-subagent", "description": "Label", "workflowPhase": "Scout", "requestShape": "foreground"})
        return d

    def add_terminal(self, sid: str, run_id: str, obj: dict) -> Path:
        p = self.session_dir(sid) / "workflows" / f"{run_id}.json"
        write_json(p, obj)
        return p

    def add_output(self, sid: str, task_id: str, content: bytes = b"x") -> Path:
        d = self.temp / SLUG.lower() / sid / "tasks"
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{task_id}.output"
        p.write_bytes(content)
        return p

    def add_rollout(self, records: list[dict], when: float | None = None, uuid: str = "019a0000-0000-7000-8000-000000000001") -> Path:
        t = time.localtime(when or time.time())
        d = self.codex / "sessions" / f"{t.tm_year:04d}" / f"{t.tm_mon:02d}" / f"{t.tm_mday:02d}"
        name = time.strftime("rollout-%Y-%m-%dT%H-%M-%S-", t) + uuid + ".jsonl"
        p = d / name
        write_jsonl(p, records)
        return p


def collector(tree: Tree):
    from collect_claude import ClaudeCollector, Stats
    from config import Settings

    return ClaudeCollector(tree.paths(), Settings(), Stats())


def run_ticks(c, now_ms: int, n: int = 2):
    from config import TICK_READ_CAP
    from tailreader import Budget

    c.discover(now_ms, Budget(TICK_READ_CAP))
    for _ in range(n):
        c.tick(now_ms, Budget(TICK_READ_CAP))
        while c.backfill.pending():
            c.backfill.run()
    return c.build(now_ms)


SID = "11111111-2222-4333-8444-555555555555"
SID2 = "11111111-2222-4333-8444-666666666666"
AID = "a0123456789abcdef"
AID2 = "afedcba9876543210"
RUN = "wf_12345678-abc"
