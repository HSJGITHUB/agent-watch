"""Incremental reader for tails and offset ranges, never whole files. Release handles between ticks."""
from __future__ import annotations

import os

from config import BACKFILL_TICK_CAP, INIT_TAIL, LINE_CAP, MAX_TAIL, PER_FILE_TICK_CAP
from winproc import open_shared

FINGERPRINT_BYTES = 256  # Last bytes read, used to detect overwrites missed by size and inode checks.


class Budget:
    """Per-tick read budget."""

    __slots__ = ("left", "deferred")

    def __init__(self, cap: int):
        self.left = cap
        self.deferred = False

    def allow(self, want: int) -> int:
        n = min(want, self.left)
        if n <= 0:
            self.deferred = True
            return 0
        return n

    def spend(self, n: int) -> None:
        self.left -= n


class IncrementalReader:
    __slots__ = (
        "path", "tail", "line_cap", "offset", "partial", "skip", "first_start",
        "started", "file_index", "skipped_lines", "seen_size", "last_read", "first_cut",
        "generation", "seen_mtime_ns", "fp",
    )

    def __init__(self, path, tail: int = INIT_TAIL, line_cap: int = LINE_CAP):
        self.path = path
        self.tail = tail
        self.line_cap = line_cap
        self.skipped_lines = 0
        self.last_read = 0
        self.generation = 0  # Incremented on replacement; callers rebuild parsers and aggregates.
        self._reset()

    def _reset(self) -> None:
        self.offset = 0
        self.partial = b""
        self.skip = False
        self.first_start = 0
        self.first_cut = False  # Advance first_start past a partial line discarded at the tail boundary.
        self.started = False
        self.file_index = 0
        self.seen_size = 0
        self.seen_mtime_ns = 0
        self.fp = b""

    def _rotate(self) -> None:
        self._reset()
        self.generation += 1

    def changed(self, st: os.stat_result) -> bool:
        return (
            not self.started
            or st.st_size != self.offset
            or bool(st.st_ino and self.file_index and st.st_ino != self.file_index)
            or st.st_mtime_ns != self.seen_mtime_ns
        )

    def caught_up(self) -> bool:
        return self.started and self.offset >= self.seen_size

    def can_expand(self) -> bool:
        return self.first_start > 0 and self.tail < MAX_TAIL

    def expand(self) -> None:
        """Expand the tail window fourfold and reread; callers must rebuild parser state too."""
        self.tail = min(self.tail * 4, MAX_TAIL)
        self._reset()

    def poll(self, st: os.stat_result | None = None, cap: int = PER_FILE_TICK_CAP) -> list[bytes]:
        if st is None:
            st = os.stat(self.path)
        size = st.st_size
        self.last_read = 0
        if self.started and (
            size < self.offset or (st.st_ino and self.file_index and st.st_ino != self.file_index)
        ):
            self._rotate()
        if not self.started:
            start = max(0, size - self.tail)
            self.offset = start
            self.first_start = start
            self.skip = start > 0  # Discard the partial first line.
            self.first_cut = self.skip
            self.started = True
            self.file_index = st.st_ino
        self.seen_size = size
        end = min(size, self.offset + cap)
        keep = len(self.fp)
        if end <= self.offset and (not keep or st.st_mtime_ns == self.seen_mtime_ns):
            self.seen_mtime_ns = st.st_mtime_ns
            return []
        # Compare previously read trailing bytes; an mtime-only change must not trigger expensive full backfill.
        with open_shared(self.path) as f:
            f.seek(self.offset - keep)
            data = f.read(keep + max(0, end - self.offset))
        if keep:
            if data[:keep] != self.fp:
                self._rotate()
                return self.poll(st, cap)
            data = data[keep:]
        self.seen_mtime_ns = st.st_mtime_ns
        if not data:
            return []
        self.fp = (self.fp + data)[-FINGERPRINT_BYTES:]
        self.offset += len(data)
        self.last_read = len(data)
        return self._split(data)

    def _split(self, data: bytes) -> list[bytes]:
        buf = self.partial + data if self.partial else data
        lines = buf.split(b"\n")
        self.partial = lines.pop()
        if self.skip:
            if lines:
                dropped = lines.pop(0)
                self.skip = False
                if self.first_cut:
                    # End backfill at a line boundary so neither reader loses the boundary line.
                    self.first_start += len(dropped) + 1
                    self.first_cut = False
            else:
                if self.first_cut:
                    self.first_start += len(self.partial)
                self.partial = b""
        if len(self.partial) > self.line_cap:
            self.partial = b""
            self.skip = True
            self.skipped_lines += 1
        out: list[bytes] = []
        for ln in lines:
            if len(ln) > self.line_cap:
                self.skipped_lines += 1
                continue
            if ln.endswith(b"\r"):
                ln = ln[:-1]
            if ln:
                out.append(ln)
        return out


class RangeScanner:
    """Line-oriented forward scanner over [0, end) for backfill."""

    __slots__ = ("path", "end", "offset", "partial", "skip", "line_cap", "skipped_lines")

    def __init__(self, path, end: int, line_cap: int = LINE_CAP):
        self.path = path
        self.end = end
        self.offset = 0
        self.partial = b""
        self.skip = False
        self.line_cap = line_cap
        self.skipped_lines = 0

    @property
    def done(self) -> bool:
        return self.offset >= self.end

    def step(self, cap: int = BACKFILL_TICK_CAP) -> list[bytes]:
        stop = min(self.end, self.offset + cap)
        if stop <= self.offset:
            return []
        with open_shared(self.path) as f:
            f.seek(self.offset)
            data = f.read(stop - self.offset)
        if not data:
            self.offset = self.end
            return []
        self.offset += len(data)
        buf = self.partial + data if self.partial else data
        lines = buf.split(b"\n")
        self.partial = lines.pop()
        if self.skip:
            if lines:
                lines.pop(0)
                self.skip = False
            else:
                self.partial = b""
        if len(self.partial) > self.line_cap:
            self.partial = b""
            self.skip = True
            self.skipped_lines += 1
        out = []
        for ln in lines:
            if len(ln) > self.line_cap:
                self.skipped_lines += 1
                continue
            out.append(ln)
        if self.done and self.partial and len(self.partial) <= self.line_cap:
            out.append(self.partial)
            self.partial = b""
        return out


def read_head(path, n: int) -> bytes:
    with open_shared(path) as f:
        return f.read(n)


def read_tail(path, size: int, n: int) -> bytes:
    with open_shared(path) as f:
        f.seek(max(0, size - n))
        return f.read(n)


def read_all(path, cap: int) -> bytes:
    """Read a small JSON file completely; raise OSError above cap."""
    with open_shared(path) as f:
        data = f.read(cap + 1)
    if len(data) > cap:
        raise OSError("file exceeds cap")
    return data
