"""Manual live-data leak scan. Scan all outgoing JSON with regexes independent of masking.py. Never print values: only pattern names, counts, and field paths. Synthetic positive controls check the scanner. Usage: python -X utf8 -B tests/leak_scan.py [--ticks 6]"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from pathlib import Path

PKG = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PKG))

from collect_claude import ClaudeCollector, Stats  # noqa: E402
from collect_codex import CodexCollector  # noqa: E402
from config import Paths, Settings, TICK_READ_CAP  # noqa: E402
from tailreader import Budget  # noqa: E402

RX = {
    "slack": re.compile(r"xox[a-z]-[A-Za-z0-9-]{10,}"),
    "xapp": re.compile(r"xapp-[A-Za-z0-9-]{10,}"),
    "openai_anthropic": re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    "github": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"),
    "meta": re.compile(r"\bEAA[A-Za-z0-9]{20,}"),
    "aws": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "google": re.compile(r"\bAIza[0-9A-Za-z_-]{30,}|\bya29\.[0-9A-Za-z_-]{20,}|GOCSPX-[A-Za-z0-9_-]{10,}"),
    "shopify_stripe": re.compile(r"\bshp(?:at|ss|ca|pa)_[A-Fa-f0-9]{20,}|\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "bearer": re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}"),
    "kv_secret": re.compile(r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd)\s*[:=]\s*[\"']?(?!\[MASK\])[^\s\"'\[]{6,}"),
    "hex32": re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32,}(?![A-Fa-f0-9])"),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "mixed_40": re.compile(r"(?<![A-Za-z0-9+/_=-])(?=[A-Za-z0-9+/_=-]*\d)(?=[A-Za-z0-9+/_=-]*[A-Z])(?=[A-Za-z0-9+/_=-]*[a-z])[A-Za-z0-9+/_=-]{40,}"),
}
FORBIDDEN_KEYS = {
    "messagingSocketPath", "bridgeSessionId", "pidDomain", "lastPrompt", "script", "result", "summary", "logs",
    "promptPreview", "resultPreview", "lastToolSummary", "balance", "stdout", "stderr", "aggregated_output",
    "formatted_output", "world_state", "base_instructions", "old_string", "new_string", "content", "prompt",
}
# Do not skip identifier fields; they also require validation.
SKIP_VALUE_KEYS: set[str] = set()


def walk(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield ("key", f"{path}.{k}", k)
            yield from walk(v, f"{path}.{k}")
    elif isinstance(o, list):
        for v in o:
            yield from walk(v, f"{path}[]")
    elif isinstance(o, str):
        yield ("str", path, o)


def scan(obj) -> tuple[Counter, Counter, Counter, int]:
    hits: Counter = Counter()
    where: Counter = Counter()
    bad_keys: Counter = Counter()
    n = 0
    for kind, path, v in walk(obj):
        if kind == "key":
            if v in FORBIDDEN_KEYS:
                bad_keys[path] += 1
            continue
        if path.rsplit(".", 1)[-1] in SKIP_VALUE_KEYS:
            continue
        n += 1
        for name, rx in RX.items():
            c = len(rx.findall(v))
            if c:
                hits[name] += c
                where[f"{name} @ {re.sub(r'[0-9a-f]{8,}', '*', path)}"] += c
    return hits, where, bad_keys, n


def self_check() -> None:
    fake = {
        "a": "xo" + "xb-1234567890-abcdefghij", "b": "gh" + "p_abcdefghijklmnopqrstuvwxyz012345",
        "c": "AK" + "IAABCDEFGHIJKLMNOP", "d": "0123456789abcdef" * 3, "e": "someone" + "@example.com",
        "f": "aB3dE5gH7jK9mN1pQ3sT5vW7xY9zA1cE3gI5kM7oQ9",
    }
    hits, _, _, _ = scan(fake)
    missing = {"slack", "github", "aws", "hex32", "email", "mixed_40"} - set(hits)
    if missing:
        raise SystemExit(f"Scanner positive control failed: {missing}")
    print("Scanner positive control passed", dict(hits))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ticks", type=int, default=6)
    args = ap.parse_args()
    self_check()
    paths, settings, stats = Paths(), Settings(), Stats()
    c = ClaudeCollector(paths, settings, stats)
    x = CodexCollector(paths, stats)
    now = int(time.time() * 1000)
    b = Budget(TICK_READ_CAP)
    c.discover(now, b)
    x.discover(now, b)
    for _ in range(args.ticks):
        now = int(time.time() * 1000)
        b = Budget(TICK_READ_CAP)
        c.tick(now, b)
        x.tick(now, b)
        c.backfill.run()
    built = c.build(now)
    runs, usage, xindex = x.build(now)
    details = []
    for key, e in built["index"].items():
        details.extend(e.get("events") or ())
    for e in xindex.values():
        details.extend(e["events"])
    body = {
        "sessions": built["sessions"], "bg": built["bg_tasks"], "projects": built["projects"],
        "codex": runs, "usage": usage, "events": details,
    }
    hits, where, bad_keys, n = scan(body)
    print(f"Strings: {n}, sessions: {len(built['sessions'])}, bg {len(built['bg_tasks'])}, Codex {len(runs)}, events: {len(details)}, JSON {len(json.dumps(body, ensure_ascii=False)) // 1024}KB")
    print("Pattern matches:", dict(hits) or "None")
    for k, v in where.most_common(20):
        print("  ", k, v)
    print("Forbidden keys:", dict(bad_keys) or "None")


if __name__ == "__main__":
    main()
