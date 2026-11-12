import json
import os
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

from config import LINE_CAP, MAX_TAIL  # noqa: E402
from fixture_tree import scratch_dir  # noqa: E402
from tailreader import Budget, IncrementalReader, RangeScanner, read_all, read_head, read_tail  # noqa: E402
from winproc import open_shared  # noqa: E402


def line(i, pad=0):
    return json.dumps({"i": i, "p": "x" * pad}).encode() + b"\n"


class Reader(unittest.TestCase):
    def setUp(self):
        self.d = scratch_dir("tail")
        self.p = self.d / "f.jsonl"

    def test_first_tail_drops_cut_line(self):
        self.p.write_bytes(b"".join(line(i, 100) for i in range(100)))
        r = IncrementalReader(self.p, tail=500)
        lines = r.poll()
        self.assertTrue(lines)
        self.assertLess(len(lines), 10)
        for ln in lines:
            json.loads(ln)
        self.assertEqual(json.loads(lines[-1])["i"], 99)

    def test_small_file_from_start(self):
        self.p.write_bytes(line(0) + line(1))
        r = IncrementalReader(self.p, tail=1000)
        self.assertEqual(len(r.poll()), 2)
        self.assertEqual(r.first_start, 0)

    def test_incremental_append(self):
        self.p.write_bytes(line(0))
        r = IncrementalReader(self.p, tail=1000)
        r.poll()
        with open(self.p, "ab") as f:
            f.write(line(1) + line(2))
        lines = r.poll()
        self.assertEqual([json.loads(x)["i"] for x in lines], [1, 2])

    def test_partial_line_carried(self):
        self.p.write_bytes(line(0) + b'{"i": 1')
        r = IncrementalReader(self.p, tail=1000)
        self.assertEqual(len(r.poll()), 1)
        with open(self.p, "ab") as f:
            f.write(b"}\n")
        lines = r.poll()
        self.assertEqual([json.loads(x)["i"] for x in lines], [1])

    def test_shrink_restarts(self):
        self.p.write_bytes(line(0) * 10)
        r = IncrementalReader(self.p, tail=10_000)
        r.poll()
        self.p.write_bytes(line(5))
        self.assertEqual([json.loads(x)["i"] for x in r.poll()], [5])

    def test_replace_restarts(self):
        self.p.write_bytes(line(0))
        r = IncrementalReader(self.p, tail=1000)
        r.poll()
        new = self.d / "g.jsonl"
        new.write_bytes(line(7) + line(8) + line(9))
        os.replace(new, self.p)
        self.assertEqual(json.loads(r.poll()[-1])["i"], 9)

    def test_changed_uses_size(self):
        self.p.write_bytes(line(0))
        r = IncrementalReader(self.p, tail=1000)
        self.assertTrue(r.changed(os.stat(self.p)))
        r.poll()
        self.assertFalse(r.changed(os.stat(self.p)))
        with open(self.p, "ab") as f:
            f.write(line(1))
        self.assertTrue(r.changed(os.stat(self.p)))

    def test_line_cap_skip_complete(self):
        self.p.write_bytes(line(0) + b"y" * 200 + b"\n" + line(2))
        r = IncrementalReader(self.p, tail=10_000, line_cap=100)
        out = r.poll()
        self.assertEqual([json.loads(x)["i"] for x in out], [0, 2])
        self.assertEqual(r.skipped_lines, 1)

    def test_line_cap_skip_partial(self):
        self.p.write_bytes(line(0) + b"y" * 200)
        r = IncrementalReader(self.p, tail=10_000, line_cap=100)
        self.assertEqual(len(r.poll()), 1)
        with open(self.p, "ab") as f:
            f.write(b"y" * 50 + b"\n" + line(2))
        self.assertEqual([json.loads(x)["i"] for x in r.poll()], [2])
        self.assertEqual(r.skipped_lines, 1)

    def test_expand_window(self):
        self.p.write_bytes(b"".join(line(i, 2000) for i in range(100)))
        r = IncrementalReader(self.p, tail=1024)
        first = r.poll()
        self.assertLessEqual(len(first), 1)
        self.assertTrue(r.can_expand())
        r.expand()
        self.assertEqual(r.tail, 4096)
        self.assertGreater(len(r.poll()), len(first))

    def test_expand_cap(self):
        self.p.write_bytes(b"x\n")
        r = IncrementalReader(self.p, tail=MAX_TAIL)
        r.poll()
        self.assertFalse(r.can_expand())

    def test_tick_cap_carries_over(self):
        self.p.write_bytes(b"".join(line(i, 100) for i in range(100)))
        size = self.p.stat().st_size
        r = IncrementalReader(self.p, tail=size + 1)
        got = []
        for _ in range(100):
            got += r.poll(cap=2000)
            if r.caught_up():
                break
        self.assertEqual([json.loads(x)["i"] for x in got], list(range(100)))

    def test_large_file_first_read_fast(self):
        big = self.d / "big.jsonl"
        chunk = (json.dumps({"p": "z" * 4000}) + "\n").encode() * 2500  # Approximately 10MB.
        with open(big, "wb") as f:
            for _ in range(5):
                f.write(chunk)
        self.assertGreater(big.stat().st_size, 50_000_000)
        r = IncrementalReader(big)
        t0 = time.perf_counter()
        lines = r.poll()
        ms = (time.perf_counter() - t0) * 1000
        self.assertTrue(lines)
        self.assertLess(ms, 200)

    def test_budget(self):
        b = Budget(100)
        self.assertEqual(b.allow(30), 30)
        b.spend(100)
        self.assertEqual(b.allow(30), 0)
        self.assertTrue(b.deferred)

    def test_default_line_cap_above_measured_max(self):
        self.assertGreater(LINE_CAP, 2_400_000)


class Shared(unittest.TestCase):
    def test_open_shared_allows_replace_while_open(self):
        d = scratch_dir("share")
        p = d / "a.json"
        p.write_bytes(b"old")
        n = d / "b.json"
        n.write_bytes(b"new")
        moved = d / "moved.json"
        with open_shared(p) as f:
            self.assertEqual(f.read(3), b"old")
            os.replace(p, moved)  # Without FILE_SHARE_DELETE, this raises PermissionError.
        self.assertEqual(moved.read_bytes(), b"old")
        self.assertFalse(p.exists())

    def test_builtin_open_blocks_rename_control(self):
        d = scratch_dir("share")
        p = d / "a.json"
        p.write_bytes(b"old")
        with open(p, "rb"):
            with self.assertRaises(PermissionError):
                os.replace(p, d / "moved.json")

    def test_open_shared_missing(self):
        with self.assertRaises(FileNotFoundError):
            open_shared(scratch_dir("share") / "none")

    def test_helpers(self):
        p = scratch_dir("share") / "a.txt"
        p.write_bytes(b"0123456789")
        self.assertEqual(read_head(p, 3), b"012")
        self.assertEqual(read_tail(p, 10, 3), b"789")
        self.assertEqual(read_all(p, 100), b"0123456789")
        with self.assertRaises(OSError):
            read_all(p, 5)


class Scanner(unittest.TestCase):
    def test_range_scanner_splits_chunks(self):
        p = scratch_dir("scan") / "f.jsonl"
        p.write_bytes(b"".join(line(i, 50) for i in range(50)))
        size = p.stat().st_size
        s = RangeScanner(p, size)
        got = []
        while not s.done:
            got += s.step(400)
        self.assertEqual([json.loads(x)["i"] for x in got], list(range(50)))

    def test_range_scanner_end_limit(self):
        p = scratch_dir("scan") / "f.jsonl"
        p.write_bytes(line(0) + line(1) + line(2))
        s = RangeScanner(p, len(line(0)))
        got = s.step(10_000)
        self.assertEqual([json.loads(x)["i"] for x in got], [0])
        self.assertTrue(s.done)


if __name__ == "__main__":
    unittest.main()
