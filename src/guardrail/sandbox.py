"""Docker sandbox for shell commands.

Each command runs in a new, disposable container with:
  - no network,
  - a read-only root filesystem, with writable tmpfs for /tmp (and /work, see below),
  - no host folders mounted, except a private copy of approved script files,
  - no Linux capabilities, no privilege escalation, a non-root user,
  - memory, CPU and process limits.

A destructive command can therefore only damage its own container. If Docker
is not available, the call is refused (see ExecutionError), never run on the host.

Script files. A command that runs a script (`sh deploy.sh`) cannot see the host's
files. When the caller passes the approved script hashes, each script is read once,
checked against its approved hash, and copied into a private temp folder. That copy
is mounted read-only as /work. The container never sees the live host file, so the
file cannot change between the check and the run.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import uuid
from collections.abc import Mapping
from pathlib import Path

from guardrail.models import CommandResult, ExecutionError

DEFAULT_IMAGE = "alpine:3.20"
DEFAULT_TIMEOUT_SECONDS = 30


def build_docker_argv(
    command: str,
    container_name: str,
    image: str = DEFAULT_IMAGE,
    stage_dir: str | Path | None = None,
) -> list[str]:
    """Return the docker command that runs `command` in a locked-down container.

    With stage_dir, that folder is mounted read-only as /work (the working directory).
    Otherwise /work is empty, writable scratch space.
    """
    if stage_dir is None:
        work_mount = ["--tmpfs", "/work:rw,size=64m,mode=1777"]
    else:
        work_mount = ["--mount", f"type=bind,source={stage_dir},target=/work,readonly"]
    return [
        "docker",
        "run",
        "--rm",
        "--name", container_name,
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        *work_mount,
        "--workdir", "/work",
        "--user", "65534:65534",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--memory", "256m",
        "--cpus", "1",
        "--pids-limit", "128",
        image,
        "sh", "-c", command,
    ]


def stage_scripts(files: Mapping[str, str | None], base: Path, dest: Path) -> bool:
    """Copy approved script files into `dest`, keeping their paths relative to `base`.

    Each file is read once, and those exact bytes are checked against the approved
    SHA-256 before they are written. Returns True if any file was staged.
    """
    staged = False
    for written, expected in files.items():
        if expected is None:
            continue  # the file did not exist at approval time; the command will fail inside the container
        source = Path(written)
        try:
            relative = source.relative_to(base)
        except ValueError:
            raise ExecutionError(
                f"{written} is outside the working directory, so it cannot be run in the sandbox"
            ) from None
        try:
            data = source.read_bytes()
        except OSError as exc:
            raise ExecutionError(f"could not read {relative}: {exc.strerror or exc}") from None
        if hashlib.sha256(data).hexdigest() != expected:
            raise ExecutionError(f"{relative} changed after approval; refusing to run it")

        target = dest / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        _make_readable(target)
        for parent in target.relative_to(dest).parents:
            _make_readable(dest / parent)
        staged = True
    if staged:
        _make_readable(dest)
    return staged


def _make_readable(path: Path) -> None:
    """The container runs as an unprivileged user, so staged files and folders must be world-readable."""
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass  # not every filesystem supports this; Docker Desktop on Windows does not need it


def run_in_sandbox(
    command: str,
    image: str = DEFAULT_IMAGE,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    files: Mapping[str, str | None] | None = None,
) -> CommandResult:
    """Run a shell command in a sandbox container and return its result.

    `files` maps approved script paths to their SHA-256; see the module docstring.
    """
    name = f"guardrail-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory(prefix="guardrail-stage-") as stage:
        staged = stage_scripts(files or {}, Path.cwd(), Path(stage))
        argv = build_docker_argv(command, name, image, stage_dir=stage if staged else None)
        try:
            result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            raise ExecutionError("docker is not installed or not on PATH; shell sandbox unavailable") from None
        except subprocess.TimeoutExpired:
            _kill_container(name)
            return CommandResult(
                text=f"command timed out after {timeout} seconds (container stopped)",
                ok=False,
                summary="timed out",
            )
        except OSError as exc:
            raise ExecutionError(f"could not run docker: {exc.strerror or exc}") from None

    if result.returncode == 125:
        # docker itself failed (daemon not running, bad image, etc.), not the command.
        raise ExecutionError(f"docker could not start the sandbox: {result.stderr.strip()[:300]}")

    text = f"exit code: {result.returncode}\nstdout:\n{result.stdout}stderr:\n{result.stderr}"
    return CommandResult(text=text, ok=result.returncode == 0, summary=f"exit code {result.returncode}")


def _kill_container(name: str) -> None:
    try:
        subprocess.run(["docker", "kill", name], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        pass
