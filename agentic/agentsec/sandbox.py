"""P2 Hardened execution sandbox: run model-generated (untrusted) code in a locked-down, throw-away Docker container.

Every run gets: no network, read-only root filesystem, a small tmpfs as the only writable place, a non-root user, all Linux
capabilities dropped, no-new-privileges, pid / memory / cpu / file-descriptor limits, a wall-clock timeout (the container is killed and
removed), capped output, no host mounts and no environment variables from the host. If Docker is missing or anything about the setup
is wrong, the run is REFUSED (ok=False): it never falls back to running the code on the host.

Stronger isolation: pass runtime="runsc" (gVisor) or "kata" if your Docker host has it installed.
Limits (be honest with yourself): a container shares the host kernel, so a kernel exploit can escape it; gVisor/Firecracker reduce that
risk, a separate VM / node pool removes it. This module is the reference building block, not a multi-tenant code-execution service.
Standard library only; needs the `docker` CLI and a local image such as python:3.12-slim.
"""
import re
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass

DEFAULT_IMAGE = "python:3.12-slim"
_MEM = re.compile(r"^\d{1,5}[kmg]?$", re.I)
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/:@-]{0,200}$", re.I)
_RUNTIME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,40}$", re.I)


@dataclass
class SandboxResult:
    ok: bool                 # the code ran and exited 0 within limits
    exit_code: int = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    oom_killed: bool = False
    truncated: bool = False  # output exceeded max_output and the run was stopped
    duration: float = 0.0
    error: str = ""          # why the run was refused or failed to start (never "the code failed")


def docker_available(docker="docker"):
    if not shutil.which(docker):
        return False
    try:
        return subprocess.run([docker, "info"], capture_output=True, timeout=15).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _validate(image, memory, cpus, pids, timeout, runtime, workdir_mb):
    if not _IMAGE.match(image or ""):
        raise ValueError("bad image name")
    if not _MEM.match(str(memory)):
        raise ValueError("memory must look like 128m / 1g")
    if not (0.05 <= float(cpus) <= 8):
        raise ValueError("cpus must be between 0.05 and 8")
    if not (1 <= int(pids) <= 4096):
        raise ValueError("pids must be between 1 and 4096")
    if not (0 < float(timeout) <= 600):
        raise ValueError("timeout must be between 0 and 600 seconds")
    if runtime is not None and not _RUNTIME.match(runtime):
        raise ValueError("bad runtime name")
    if not (1 <= int(workdir_mb) <= 1024):
        raise ValueError("workdir_mb must be between 1 and 1024")


def _docker_args(name, image, argv, *, memory, cpus, pids, runtime, workdir_mb, stdin):
    a = ["run", "--name", name, "--network", "none", "--read-only", "--user", "65534:65534", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges", "--pids-limit", str(pids), "--memory", str(memory), "--memory-swap", str(memory),
         "--cpus", str(cpus), "--ulimit", "nofile=256:256", "--ulimit", "core=0", "--ipc", "none", "--log-driver", "none",
         "--tmpfs", f"/work:rw,nosuid,nodev,size={int(workdir_mb)}m,uid=65534,gid=65534,mode=0700", "--workdir", "/work", "--env", "HOME=/work",
         "--env", "PYTHONDONTWRITEBYTECODE=1", "--hostname", "sandbox"]
    if runtime:
        a += ["--runtime", runtime]
    if stdin is not None:
        a += ["-i"]
    return a + [image] + list(argv)


def run_command(argv, *, image=DEFAULT_IMAGE, timeout=10, memory="128m", cpus=0.5, pids=64, runtime=None, workdir_mb=16, stdin=None,
                max_output=65536, docker="docker"):
    """Run argv inside the sandbox image. See module doc for what is enforced. Returns SandboxResult; never raises for the code's misbehaviour."""
    try:
        _validate(image, memory, cpus, pids, timeout, runtime, workdir_mb)
        if not all(isinstance(x, str) for x in argv) or not argv or len(" ".join(argv)) > 400_000:
            raise ValueError("argv must be a non-empty list of strings (< 400 KB)")
    except (ValueError, TypeError) as e:
        return SandboxResult(False, error=f"refused: {e}")
    if not docker_available(docker):
        return SandboxResult(False, error="refused: docker is not available; the code was NOT run (there is no host fallback)")
    if subprocess.run([docker, "image", "inspect", image], capture_output=True).returncode != 0:
        return SandboxResult(False, error=f"refused: image {image!r} is not present locally (pull it first; the sandbox never pulls)")
    name = "warden-sbx-" + uuid.uuid4().hex[:12]
    args = [docker] + _docker_args(name, image, argv, memory=memory, cpus=cpus, pids=pids, runtime=runtime, workdir_mb=workdir_mb, stdin=stdin)
    t0 = time.time()
    res = SandboxResult(False)
    bufs = {"out": bytearray(), "err": bytearray()}
    over = threading.Event()
    try:
        p = subprocess.Popen(args, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        return SandboxResult(False, error=f"could not start docker: {e}")

    def pump(stream, key):
        for chunk in iter(lambda: stream.read(4096), b""):
            if len(bufs[key]) < max_output:
                bufs[key] += chunk[: max_output - len(bufs[key])]
            else:
                over.set()   # keep draining so the pipe never blocks, but stop the run
    readers = [threading.Thread(target=pump, args=(p.stdout, "out"), daemon=True), threading.Thread(target=pump, args=(p.stderr, "err"), daemon=True)]
    for r in readers:
        r.start()
    if stdin is not None:
        try:
            p.stdin.write(stdin.encode() if isinstance(stdin, str) else stdin)
            p.stdin.close()
        except OSError:
            pass
    deadline = t0 + float(timeout)
    while p.poll() is None:
        if time.time() > deadline:
            res.timed_out = True
            break
        if over.is_set():
            res.truncated = True
            break
        time.sleep(0.05)
    if p.poll() is None:  # timeout or output flood: kill the CONTAINER (killing the CLI alone would leave it running)
        subprocess.run([docker, "kill", name], capture_output=True, timeout=30)
        try:
            p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            p.kill()
    for r in readers:
        r.join(timeout=5)
    res.truncated = res.truncated or over.is_set()
    res.exit_code = p.returncode
    def oom_flag():
        try:
            insp = subprocess.run([docker, "inspect", "-f", "{{.State.OOMKilled}}", name], capture_output=True, text=True, timeout=15)
            return insp.stdout.strip() == "true"
        except (OSError, subprocess.TimeoutExpired):
            return False
    res.oom_killed = oom_flag()
    if not res.oom_killed and res.exit_code == 137 and not (res.timed_out or res.truncated):
        # Docker sets OOMKilled from an asynchronous cgroup event, so right after a memory kill it can still read false (seen ~1 run in 10).
        # We did not kill this container ourselves (no timeout, no output flood), so exit 137 (SIGKILL) means the memory limit did.
        time.sleep(0.3)
        res.oom_killed = oom_flag() or True
    subprocess.run([docker, "rm", "-f", name], capture_output=True, timeout=60)
    res.duration = round(time.time() - t0, 2)
    res.stdout = bufs["out"].decode("utf-8", "replace")
    res.stderr = bufs["err"].decode("utf-8", "replace")
    res.ok = res.exit_code == 0 and not (res.timed_out or res.oom_killed or res.truncated)
    return res


def run_python(code, **kw):
    """Run Python source in the sandbox (`python -I -c code`; isolated mode ignores PYTHON* env vars and the working directory)."""
    if not isinstance(code, str):
        return SandboxResult(False, error="refused: code must be a string")
    return run_command(["python", "-I", "-c", code], **kw)
