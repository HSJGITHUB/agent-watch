"""Agent Watch constants and default paths. CLI overrides flow through Paths and Settings in server.py."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "0.1.4"
STATE_SCHEMA = "agent_watch.state/1"
AGENT_SCHEMA = "agent_watch.agent/1"

# Status thresholds.
N_WAIT_S = 60
M_STALL_S = 720
TOOL_TIMEOUT_GRACE_S = 120
TOOL_TIMEOUT_CAP_MS = 600_000  # Clamp timeouts above ten minutes to the Bash limit.
ORPHAN_QUIET_S = 3600
CODEX_N_S = 60
CODEX_M_S = 900  # 900 seconds accommodates observed gaps within turns.
CODEX_ORPHAN_S = 21_600
BG_OUTPUT_ACTIVE_S = 60
BG_PROCESS_SLACK_MS = 5000  # Slack when comparing process and background-job start times.
HUMAN_WAIT_TOOLS = ("AskUserQuestion", "ExitPlanMode")  # critic MUST-10
FINISH_RESUME_SLACK_MS = 5000  # Slack for detecting resumption after completion.

# Tick scheduling.
TICK_INTERVAL_S = 2.0
DISCOVERY_INTERVAL_S = 30.0
IDLE_TICK_S = 15.0
OBSERVER_TIMEOUT_S = 60.0
SLOW_TICK_MS = 200.0
FAST_TICK_MS = 100.0
SLOW_TICK_RUN = 3
FAST_TICK_RUN = 10
BACKOFF_MAX_S = 10.0
RELIST_HOLD_MS = 8000  # Subagent relisting period after Agent/Workflow tool_use.

# Watch set.
RECENT_WINDOW_H = 24
MAP_CACHE_S = 60.0

# Limits.
HOT_MAX = 200
HOT_RR_SLOTS = 50  # HOT_MAX slots reserved for least-recently-read files; each of N files is read within ceil((N-150)/50) ticks.
INIT_TAIL = 256 * 1024
MAX_TAIL = 8 * 1024 * 1024
PER_FILE_TICK_CAP = 8 * 1024 * 1024
TICK_READ_CAP = 32 * 1024 * 1024
LINE_CAP = 4 * 1024 * 1024
BACKFILL_TICK_CAP = 8 * 1024 * 1024
BACKFILL_MAX_FILE = 1024 * 1024 * 1024
EVENTS_PER_AGENT = 30
PENDING_TOOLS_MAX = 64
MSG_USAGE_KEEP = 8
BG_PER_SESSION_MAX = 500
BG_STAT_PER_TICK = 64  # Open background stat limit; round-robin reads cover N files within ceil(N/64) ticks.
CODEX_RUNS_MAX = 100
SESSIONS_MAX = 300
STATE_JSON_MAX = 1024 * 1024
AGENTS_PER_SESSION_MAX = 100
STATE_AGENTS_SHRUNK = 50  # Agents retained per session/workflow when STATE_JSON_MAX is exceeded.
STATE_BG_SHRUNK = 200
STATE_CODEX_SHRUNK = 100
# Reduce agent, background, and Codex caps in stages, then remove sessions from the end.
STATE_SHRINK_STEPS = (
    (STATE_AGENTS_SHRUNK, STATE_BG_SHRUNK, STATE_CODEX_SHRUNK),
    (25, 100, 50), (12, 50, 25), (6, 25, 12), (3, 12, 6), (1, 6, 3), (0, 0, 0),
)
FINISHED_KEEP_S = 3600
STALE_KEEP_S = 86_400
TITLE_HEAD_BYTES = 128 * 1024
TERMINAL_MAX_BYTES = 64 * 1024 * 1024
REGISTRY_MAX_BYTES = 256 * 1024

# Resident storage limits, separate from display limits.
TOOL_IDS_MAX = 20_000  # Unique tool_use IDs per file; above this, keep counting with exact=false.
NOTIFS_MAX = 1024  # Notifications per session.
STOPS_MAX = 1024
AGENT_CALLS_MAX = 2048
WORKFLOWS_MAX = 256  # Launch records for finished runs; open runs may exceed this limit.
WORKFLOWS_OPEN_MAX = 4096  # Final limit including open runs; runs that lose their names remain private.
HINTS_MAX = 1024
RUNS_SKIP_MAX = 512
BF_SEEN_MAX = 8192
GONE_MAX = 2048  # Retired-agent tombstones: last mtime, owner label, privacy decision.
PATH_CACHE_MAX = 1024

# 4.9 Codex
CODEX_WINDOW_H = 12  # Discovery candidate filter based on filename timestamps.
CODEX_DAY_FOLDERS = 3
CODEX_USAGE_FALLBACK_DAYS = 14
CODEX_USAGE_FALLBACK_FILES = 5
CODEX_EVENTS_KEEP = 30
CODEX_GAP_TICK_CAP = 2 * 1024 * 1024  # Per-tick read cap for counting turns between head and tail.
CODEX_OUTPUT_SCAN = 64 * 1024  # Tool-output prefix scanned for markers; bodies are not stored.
CODEX_PENDING_MAX = 64  # Unresolved commands, waits, and cells within a turn.

# /api/agent
DETAIL_MIN_INTERVAL_S = 1.0  # Rate limit for detail rereads.
DETAIL_CACHE_S = 5.0

# HTTP
MAX_HANDLERS = 16  # Concurrent handler cap; return 503 without creating more threads.
REQUEST_DEADLINE_S = 30.0  # Whole-request deadline; socket timeout covers only gaps between bytes.

# Logging.
LOG_MAX_BYTES = 1024 * 1024
LOG_REPEAT_S = 600


def default_temp_claude() -> Path:
    """Avoid tempfile because its first call creates and deletes a probe in the system temporary directory."""
    base = os.environ.get("TEMP") or os.environ.get("TMP")
    if not base:
        base = str(Path.home() / "AppData" / "Local" / "Temp")
    return Path(base) / "claude"


@dataclass(slots=True)
class Paths:
    claude_home: Path = field(default_factory=lambda: Path.home() / ".claude")
    codex_home: Path = field(default_factory=lambda: Path.home() / ".codex")
    temp_claude: Path = field(default_factory=default_temp_claude)
    state_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent / "state")

    @property
    def registry_dir(self) -> Path:
        return self.claude_home / "sessions"

    @property
    def projects_dir(self) -> Path:
        return self.claude_home / "projects"

    @property
    def codex_sessions_dir(self) -> Path:
        return self.codex_home / "sessions"


@dataclass(slots=True)
class Settings:
    tick_s: float = TICK_INTERVAL_S
    window_h: float = RECENT_WINDOW_H
