"""Docker sandbox for shell commands.

Each command runs in a new, disposable container with:
  - no network,
  - a read-only root filesystem, with writable tmpfs for /tmp and /work only,
  - no host folders mounted,
  - no Linux capabilities, no privilege escalation, a non-root user,
  - memory, CPU and process limits.

A destructive command can therefore only damage its own container. If Docker
is not available, the call is refused (see ExecutionError), never run on the host.
"""

from __future__ import annotations

import subprocess
import uuid

from guardrail.models import CommandResult, ExecutionError

DEFAULT_IMAGE = "alpine:3.20"
DEFAULT_TIMEOUT_SECONDS = 30


def build_docker_argv(command: str, container_name: str, image: str = DEFAULT_IMAGE) -> list[str]:
    """Return the docker command that runs `command` in a locked-down container."""
    return [
        "docker",
        "run",
        "--rm",
        "--name", container_name,
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:rw,size=64m,mode=1777",
        "--tmpfs", "/work:rw,size=64m,mode=1777",
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


def run_in_sandbox(command: str, image: str = DEFAULT_IMAGE, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> CommandResult:
    """Run a shell command in a sandbox container and return its result."""
    name = f"guardrail-{uuid.uuid4().hex[:12]}"
    argv = build_docker_argv(command, name, image)
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
