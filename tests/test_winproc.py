import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

import winproc  # noqa: E402


class Alive(unittest.TestCase):
    def test_self_with_real_start(self):
        ft = winproc.process_create_filetime(os.getpid())
        self.assertIsNotNone(ft)
        self.assertIs(winproc.check_alive(os.getpid(), str(ft)), True)

    def test_wrong_proc_start(self):
        ft = winproc.process_create_filetime(os.getpid())
        self.assertIs(winproc.check_alive(os.getpid(), str(ft + 1)), False)

    def test_missing_pid(self):
        self.assertIs(winproc.check_alive(4_000_000), False)

    def test_bad_pid_values(self):
        for v in (None, "1", 0, -1, True):
            self.assertIs(winproc.check_alive(v), False)

    def test_started_at_fallback(self):
        ft = winproc.process_create_filetime(os.getpid())
        ms = winproc.filetime_to_ms(ft)
        self.assertIs(winproc.check_alive(os.getpid(), None, ms + 1000), True)
        self.assertIs(winproc.check_alive(os.getpid(), None, ms + 10_000), False)

    def test_cache(self):
        c = winproc.LivenessCache(ttl_s=60)
        ft = winproc.process_create_filetime(os.getpid())
        self.assertIs(c.check(os.getpid(), str(ft), None), True)
        self.assertEqual(len(c._c), 1)
        self.assertIs(c.check(os.getpid(), str(ft), None), True)


class Misc(unittest.TestCase):
    def test_rss(self):
        v = winproc.rss_mb()
        self.assertIsNotNone(v)
        self.assertGreater(v, 1)

    def test_mutex(self):
        name = f"Local\\AgentWatch_test_{os.getpid()}"
        h = winproc.acquire_single_instance(name)
        self.assertIsNotNone(h)
        self.assertIsNone(winproc.acquire_single_instance(name))


if __name__ == "__main__":
    unittest.main()
