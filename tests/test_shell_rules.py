"""Shell rules in the default policy, including attempts to hide a command behind a wrapper."""

from pathlib import Path

import pytest

from guardrail.matchers import UnparseableInput, _simple_commands
from guardrail.models import Decision, ToolCall
from guardrail.policy import load_policy

POLICY = Path(__file__).resolve().parent.parent / "policies" / "default.toml"


@pytest.fixture(scope="module")
def policy():
    return load_policy(POLICY)


def shell(command):
    return ToolCall(tool="shell", arguments={"command": command})


BLOCKED = [
    # rm of the root or a system or home directory
    "rm -rf /",
    "rm -rf /*",
    "rm -rf ~",
    "rm -rf $HOME",
    "rm -rf /etc",
    "rm -rf /home/*",
    # hiding a command behind wrappers
    "sudo rm -rf /",
    "sudo -n rm -rf /",
    "sudo -u root rm -rf /",
    "env FOO=1 rm -rf /",
    "nohup rm -rf /",
    "timeout 10 rm -rf /",
    "nice -n 5 rm -rf /",
    "! rm -rf /",
    "(rm -rf /)",
    "true && sudo rm -rf /",
    # hiding a command behind a shell
    "sh -c 'rm -rf /'",
    'bash -c "rm -fr /*"',
    "bash -lc 'rm -rf /'",
    "sh -c 'sh -c \"rm -rf /\"'",
    # other destructive patterns
    "find / -name x -delete",
    "find /tmp -exec rm {} \\;",
    "dd if=/dev/zero of=/dev/sda",
    "echo x > /dev/sda",
    "cat image.img >> /dev/nvme0n1",
    "mkfs.ext4 /dev/sdb1",
    "mkfs /dev/sdb1",
    "shutdown -h now",
    "sudo reboot",
    "chmod -R 777 /",
    "sudo chown -R nobody /usr",
    ":(){ :|:& };:",
]

ALLOWED = [
    "ls -la",
    "ls /",
    "rm -rf ./build",
    "rm -rf /tmp/cache",
    "rm -r ./old-dir",
    "rm -f /",  # forced but not recursive
    "rm -r /",  # recursive but not forced
    "echo rm -rf /",  # rm is an argument, not the command
    "echo /dev/sda",  # a device name, not a redirect
    "echo hi > /dev/null",
    "find . -name '*.pyc'",
    "find . -name x -print",
    "dd if=input.bin of=output.bin",
    "chmod 644 notes.txt",
    "chmod -R 755 ./build",
    "sudo ls /",
    "sh -c 'echo hi'",
    "git status && git diff",
    "python -m pytest -q",
]


@pytest.mark.parametrize("command", BLOCKED)
def test_blocks_dangerous_commands(policy, command):
    verdict = policy.evaluate(shell(command))
    assert verdict.decision == Decision.BLOCK, f"{command!r} was {verdict.decision}: {verdict.reason}"
    assert verdict.rule is not None


@pytest.mark.parametrize("command", ALLOWED)
def test_allows_ordinary_commands(policy, command):
    verdict = policy.evaluate(shell(command))
    assert verdict.decision == Decision.ALLOW, f"{command!r} was blocked by {verdict.rule}: {verdict.reason}"


def test_root_rm_reason_still_mentions_root(policy):
    assert "root" in policy.evaluate(shell("rm -rf /")).reason


def test_wrapper_bypass_is_attributed_to_the_rule(policy):
    assert policy.evaluate(shell("sudo rm -rf /")).rule == "block-recursive-forced-rm-of-root"
    assert policy.evaluate(shell("sh -c 'rm -rf /'")).rule == "block-recursive-forced-rm-of-root"


def test_nesting_is_limited_so_it_cannot_run_forever():
    import shlex

    deep = "echo x"
    for _ in range(10):
        deep = f"sh -c {shlex.quote(deep)}"
    with pytest.raises(UnparseableInput, match="nested too deeply"):
        _simple_commands(deep)


def test_unknown_wrapper_is_not_stripped():
    # `myrunner rm -rf /` is not a known wrapper, so the program is myrunner.
    assert _simple_commands("myrunner rm -rf /") == [["myrunner", "rm", "-rf", "/"]]
