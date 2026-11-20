import pytest

from guardrail.models import Decision, ToolCall
from guardrail.policy import evaluate


def shell(command):
    return ToolCall(tool="shell", arguments={"command": command})


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "rm -fr /",
        "rm -r -f /",
        "rm -Rf /",
        "rm --recursive --force /",
        "rm -rf /*",
        "rm -rf / --no-preserve-root",
        "echo starting && rm -rf /",
        "ls; rm -rf /",
        "true || rm -rf /",
    ],
)
def test_blocks_recursive_forced_rm_of_root(command):
    verdict = evaluate(shell(command))
    assert verdict.decision == Decision.BLOCK
    assert "root" in verdict.reason


@pytest.mark.parametrize(
    "command",
    [
        "ls -la",
        "rm -rf ./build",
        "rm -rf /tmp/project-cache",
        "rm file.txt",
        "rm -r ./old-dir",
        "rm -f /",  # forced but not recursive
        "rm -r /",  # recursive but not forced
        "echo rm -rf /",  # rm is an argument here, not the command
    ],
)
def test_allows_safe_commands(command):
    verdict = evaluate(shell(command))
    assert verdict.decision == Decision.ALLOW


def test_blocks_unparseable_command():
    verdict = evaluate(shell('echo "unclosed'))
    assert verdict.decision == Decision.BLOCK
    assert "parsed" in verdict.reason


def test_blocks_shell_call_without_string_command():
    verdict = evaluate(ToolCall(tool="shell", arguments={"command": ["rm", "-rf", "/"]}))
    assert verdict.decision == Decision.BLOCK


def test_allows_non_shell_tools_when_no_rule_applies():
    verdict = evaluate(ToolCall(tool="terraform", arguments={"command": "destroy"}))
    assert verdict.decision == Decision.ALLOW
