"""REAL Docker tests for agentsec.sandbox: hostile code must be contained, killed and reported, and the containers must not be left behind.
Skips (does not fail) when Docker or the python:3.12-slim image is not available. Run: python3 -W ignore -I agentic/tests/test_sandbox_docker.py (~30 s)"""
import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agentsec.sandbox import DEFAULT_IMAGE, docker_available, run_command, run_python  # noqa: E402


def have_image():
    return docker_available() and subprocess.run(["docker", "image", "inspect", DEFAULT_IMAGE], capture_output=True).returncode == 0


@unittest.skipUnless(have_image(), f"docker + image {DEFAULT_IMAGE} needed")
class SandboxTests(unittest.TestCase):
    def tearDown(self):
        left = subprocess.run(["docker", "ps", "-aq", "--filter", "name=warden-sbx-"], capture_output=True, text=True).stdout.split()
        self.assertEqual(left, [], "sandbox containers were left behind")

    def test_normal_code_runs_and_returns_output(self):
        r = run_python("import sys; print('hello'); print('err', file=sys.stderr); print(sum(range(10)))")
        self.assertTrue(r.ok, r)
        self.assertEqual(r.stdout.split(), ["hello", "45"])
        self.assertIn("err", r.stderr)
        self.assertEqual(r.exit_code, 0)

    def test_stdin_and_nonzero_exit_are_reported(self):
        r = run_python("import sys; d=sys.stdin.read(); print(d.upper()); sys.exit(3)", stdin="abc")
        self.assertEqual((r.stdout.strip(), r.exit_code, r.ok), ("ABC", 3, False))
        r = run_python("raise RuntimeError('boom')")
        self.assertFalse(r.ok)
        self.assertIn("RuntimeError", r.stderr)

    def test_no_network(self):
        r = run_python("import socket\ntry:\n    socket.create_connection(('1.1.1.1', 53), timeout=3); print('NET_OK')\nexcept OSError as e: print('NET_BLOCKED', e.errno)\n"
                       "try:\n    import urllib.request; urllib.request.urlopen('http://example.com', timeout=3); print('HTTP_OK')\nexcept Exception: print('HTTP_BLOCKED')\n"
                       "import os; print('IFACES', sorted(os.listdir('/sys/class/net')))")
        self.assertIn("NET_BLOCKED", r.stdout)
        self.assertIn("HTTP_BLOCKED", r.stdout)
        self.assertNotIn("NET_OK", r.stdout)
        self.assertIn("['lo']", r.stdout)                                    # only loopback exists

    def test_read_only_root_and_writable_tmpfs_only(self):
        r = run_python("for p in ['/etc/pwned', '/usr/pwned', '/bin/pwned', '/pwned']:\n    try:\n        open(p, 'w'); print('WROTE', p)\n    except OSError as e: print('RO', e.errno)\n"
                       "open('/work/ok.txt', 'w').write('x'); print('WORK_OK')\n"
                       "try:\n    open('/work/big', 'wb').write(b'x' * (64 * 1024 * 1024)); print('BIG_OK')\nexcept OSError as e: print('TMPFS_FULL', e.errno)")
        self.assertNotIn("WROTE", r.stdout)
        self.assertEqual(r.stdout.count("RO "), 4)
        self.assertIn("WORK_OK", r.stdout)
        self.assertIn("TMPFS_FULL", r.stdout)                                # 16 MB tmpfs: a 64 MB write fails

    def test_non_root_no_capabilities_no_new_privileges(self):
        r = run_python("import os\nprint('UID', os.getuid(), os.getgid())\nst = open('/proc/self/status').read()\n"
                       "print('CAP', [l.split()[1] for l in st.splitlines() if l.startswith('CapEff')][0])\n"
                       "print('NNP', [l.split()[1] for l in st.splitlines() if l.startswith('NoNewPrivs')][0])\n"
                       "try:\n    os.setuid(0); print('BECAME_ROOT')\nexcept OSError: print('SETUID_DENIED')")
        self.assertIn("UID 65534 65534", r.stdout)
        self.assertIn("CAP 0000000000000000", r.stdout)
        self.assertIn("NNP 1", r.stdout)
        self.assertIn("SETUID_DENIED", r.stdout)

    def test_host_files_and_environment_are_invisible(self):
        canary = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        canary.write("HOST_SECRET_CANARY")
        canary.close()
        os.environ["WARDEN_TEST_HOST_ENV"] = "HOST_ENV_CANARY"
        try:
            r = run_python(f"import os\nfor p in [{canary.name!r}, '/etc/shadow', '/root', '/var/run/docker.sock', '/home']:\n"
                           "    print(p, 'EXISTS' if os.path.exists(p) else 'GONE')\n"
                           "print('ENV', 'HOST_ENV_CANARY' in str(dict(os.environ)))\nprint('HOST', os.uname().nodename)")
        finally:
            os.environ.pop("WARDEN_TEST_HOST_ENV", None)
            os.unlink(canary.name)
        self.assertNotIn("HOST_SECRET_CANARY", r.stdout)
        self.assertIn(f"{canary.name} GONE", r.stdout)
        self.assertIn("/var/run/docker.sock GONE", r.stdout)
        self.assertIn("ENV False", r.stdout)
        self.assertIn("HOST sandbox", r.stdout)

    def test_fork_bomb_is_contained_by_the_pid_limit(self):
        t = time.time()
        r = run_python("import os, time\nn = 0\nwhile n < 5000:\n    try:\n        if os.fork() == 0:\n            time.sleep(30); os._exit(0)\n        n += 1\n    except OSError:\n"
                       "        print('FORK_LIMIT_HIT_AT', n, flush=True); break\nelse:\n    print('NO_LIMIT', flush=True)\nos._exit(0)", pids=32, timeout=20)
        self.assertLess(time.time() - t, 25)
        self.assertIn("FORK_LIMIT_HIT_AT", r.stdout)
        self.assertNotIn("NO_LIMIT", r.stdout)
        n = int(r.stdout.split("FORK_LIMIT_HIT_AT")[1].split()[0])
        self.assertLessEqual(n, 32)

    def test_memory_bomb_is_oom_killed(self):
        r = run_python("x = []\nwhile True:\n    x.append(bytearray(32 * 1024 * 1024))", memory="64m", timeout=30)
        self.assertFalse(r.ok)
        self.assertTrue(r.oom_killed, r)
        self.assertEqual(r.exit_code, 137)

    def test_infinite_loop_is_killed_at_the_timeout(self):
        t = time.time()
        r = run_python("while True: pass", timeout=2)
        self.assertTrue(r.timed_out)
        self.assertFalse(r.ok)
        self.assertLess(time.time() - t, 15)

    def test_sleep_forever_and_ignored_sigterm_are_killed(self):
        r = run_python("import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(3600)", timeout=2)
        self.assertTrue(r.timed_out)

    def test_output_flood_is_capped_and_stopped(self):
        t = time.time()
        r = run_python("import sys\nwhile True:\n    sys.stdout.write('A' * 65536)\n    sys.stdout.flush()", max_output=100_000, timeout=30)
        self.assertTrue(r.truncated)
        self.assertFalse(r.ok)
        self.assertLessEqual(len(r.stdout), 100_000)
        self.assertLess(time.time() - t, 20)

    def test_cpu_limit_slows_a_busy_loop(self):
        r = run_python("import time\nt=time.process_time()\nw=time.time()\nwhile time.time()-w < 2: pass\nprint(round((time.process_time()-t)/(time.time()-w), 2))", cpus=0.25, timeout=15)
        self.assertTrue(r.ok, r)
        self.assertLess(float(r.stdout.strip()), 0.6)                        # got well under one full core

    def test_ptrace_and_mount_are_denied(self):
        r = run_python("import ctypes, os\nlibc = ctypes.CDLL(None, use_errno=True)\n"
                       "print('MOUNT', libc.mount(b'none', b'/mnt', b'tmpfs', 0, None), ctypes.get_errno())\n"
                       "print('UNSHARE', libc.unshare(0x10000000), ctypes.get_errno())")      # CLONE_NEWUSER
        self.assertIn("MOUNT -1 1", r.stdout)                                # EPERM
        self.assertNotIn("UNSHARE 0", r.stdout)                              # user namespaces blocked by the default seccomp profile

    def test_refuses_instead_of_running_on_the_host(self):
        r = run_python("print('x')", docker="docker-does-not-exist")
        self.assertFalse(r.ok)
        self.assertIn("no host fallback", r.error)
        self.assertEqual(r.stdout, "")
        r = run_python("print('x')", image="no-such-image-xyz:1")
        self.assertIn("not present locally", r.error)

    def test_bad_parameters_are_refused(self):
        for kw in ({"memory": "1g; rm -rf /"}, {"image": "ubuntu; id"}, {"cpus": 99}, {"pids": 0}, {"timeout": 0}, {"timeout": 9999}, {"runtime": "x y"}, {"workdir_mb": 0}):
            r = run_python("print(1)", **kw)
            self.assertFalse(r.ok, kw)
            self.assertTrue(r.error.startswith("refused"), (kw, r.error))
        self.assertTrue(run_python(123).error.startswith("refused"))
        self.assertTrue(run_command([]).error.startswith("refused"))

    def test_unknown_runtime_fails_without_running_code(self):
        r = run_python("print('SHOULD_NOT_RUN')", runtime="runsc-not-installed")
        self.assertFalse(r.ok)
        self.assertNotIn("SHOULD_NOT_RUN", r.stdout)

    def test_each_run_is_isolated(self):
        run_python("open('/work/state', 'w').write('left behind')")
        r = run_python("import os; print(os.path.exists('/work/state'))")
        self.assertEqual(r.stdout.strip(), "False")


if __name__ == "__main__":
    unittest.main()
