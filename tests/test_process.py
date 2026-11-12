"""Test real child processes, pythonw, exit codes, and stop files. Stop only via the stop file or the owned process handle."""
import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.request
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, os.path.dirname(HERE)]

from fixture_tree import Tree  # noqa: E402

PKG = Path(HERE).parent
SERVER = str(PKG / "server.py")
PY = sys.executable


def free_port() -> int:
    """OS-selected ephemeral port outside registered service ranges."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def args_for(t: Tree, port: int) -> list[str]:
    return ["-X", "utf8", "-B", SERVER, "--port", str(port), "--state-dir", str(t.state), "--claude-home", str(t.claude), "--codex-home", str(t.codex), "--temp-claude", str(t.temp)]


def wait_port(port: int, timeout: float = 10.0) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=2) as r:
                if r.status == 200:
                    return True
        except OSError:
            time.sleep(0.1)
    return False


def stop(t: Tree, proc: subprocess.Popen) -> None:
    t.state.mkdir(parents=True, exist_ok=True)
    (t.state / "agent_watch.stop").write_text("", encoding="utf-8")
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()  # Owned process handle.
        proc.wait(timeout=5)


class Process(unittest.TestCase):
    def test_pythonw_serves_and_stops_by_file(self):
        pyw = str(Path(PY).with_name("pythonw.exe"))
        if not os.path.exists(pyw):
            self.skipTest("pythonw unavailable")
        t = Tree("proc")
        port = free_port()
        proc = subprocess.Popen([pyw] + args_for(t, port))
        try:
            self.assertTrue(wait_port(port), "pythonw server did not respond")
        finally:
            stop(t, proc)
        self.assertEqual(proc.returncode, 0)
        d = json.loads((t.state / "run.json").read_text(encoding="utf-8"))
        self.assertEqual((d["pid"], d["port"]), (proc.pid, port))
        self.assertIn("stopped_ms", d)
        self.assertTrue(list(t.state.glob("agent_watch.stop.consumed.*")))

    def test_pythonw_bad_argument_does_not_crash_on_none_stderr(self):
        pyw = str(Path(PY).with_name("pythonw.exe"))
        if not os.path.exists(pyw):
            self.skipTest("pythonw unavailable")
        proc = subprocess.run([pyw, "-X", "utf8", "-B", SERVER, "--no-such-option"], timeout=15)
        self.assertEqual(proc.returncode, 2)

    def test_second_instance_exit_3(self):
        t = Tree("proc")
        port = free_port()
        proc = subprocess.Popen([PY] + args_for(t, port), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self.assertTrue(wait_port(port))
            t2 = Tree("proc")
            r = subprocess.run([PY] + args_for(t2, port), capture_output=True, timeout=20)
            self.assertEqual(r.returncode, 3)
        finally:
            stop(t, proc)

    def test_bind_conflict_exit_4(self):
        t = Tree("proc")
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        s.bind(("127.0.0.1", 0))
        s.listen(1)
        port = s.getsockname()[1]
        try:
            r = subprocess.run([PY] + args_for(t, port), capture_output=True, timeout=20)
            self.assertEqual(r.returncode, 4)
        finally:
            s.close()

    def test_stale_stop_file_does_not_kill_startup(self):
        t = Tree("proc")
        t.state.mkdir(parents=True, exist_ok=True)
        (t.state / "agent_watch.stop").write_text("", encoding="utf-8")
        port = free_port()
        proc = subprocess.Popen([PY] + args_for(t, port), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            self.assertTrue(wait_port(port))
            time.sleep(1.2)
            self.assertIsNone(proc.poll())
        finally:
            stop(t, proc)

    def test_stop_cmd(self):
        state = PKG / "state"
        port = free_port()
        t = Tree("proc")
        proc = subprocess.Popen(
            [PY, "-X", "utf8", "-B", SERVER, "--port", str(port), "--state-dir", str(state), "--claude-home", str(t.claude), "--codex-home", str(t.codex), "--temp-claude", str(t.temp)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            self.assertTrue(wait_port(port))
            r = subprocess.run(["cmd", "/c", str(PKG / "stop_agent_watch.cmd")], capture_output=True, timeout=15)
            self.assertEqual(r.returncode, 0)
            proc.wait(timeout=5)
            self.assertEqual(proc.returncode, 0)
        finally:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
