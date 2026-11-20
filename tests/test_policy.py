from pathlib import Path

import pytest

from guardrail.models import Decision, ToolCall
from guardrail.policy import PolicyError, load_policy

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policies" / "default.toml"


@pytest.fixture(scope="module")
def policy():
    return load_policy(DEFAULT_POLICY)


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
def test_blocks_recursive_forced_rm_of_root(policy, command):
    verdict = policy.evaluate(shell(command))
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
def test_allows_safe_commands(policy, command):
    assert policy.evaluate(shell(command)).decision == Decision.ALLOW


def test_blocks_unparseable_command(policy):
    verdict = policy.evaluate(shell('echo "unclosed'))
    assert verdict.decision == Decision.BLOCK
    assert "parsed" in verdict.reason


def test_blocks_shell_call_without_string_command(policy):
    verdict = policy.evaluate(ToolCall(tool="shell", arguments={"command": ["rm", "-rf", "/"]}))
    assert verdict.decision == Decision.BLOCK


def test_allows_tools_no_rule_applies_to(policy):
    verdict = policy.evaluate(ToolCall(tool="terraform", arguments={"command": "destroy"}))
    assert verdict.decision == Decision.ALLOW
    assert verdict.reason == "no rule matched"


def test_default_policy_loads_one_rule(policy):
    assert [r.name for r in policy.rules] == ["block-recursive-forced-rm-of-root"]
    assert policy.default_decision == Decision.ALLOW


# --- Policy file validation ---


def write_policy(tmp_path, text):
    path = tmp_path / "policy.toml"
    path.write_text(text, encoding="utf-8")
    return path


VALID_RULE = """
[[rules]]
name = "r1"
tool = "shell"
matcher = "shell.rm_recursive_force"
params = { targets = ["/"] }
decision = "block"
reason = "test"
"""


def test_custom_policy_rule_is_applied(tmp_path):
    policy = load_policy(write_policy(tmp_path, VALID_RULE))
    assert policy.evaluate(shell("rm -rf /")).decision == Decision.BLOCK


def test_default_decision_can_be_changed(tmp_path):
    policy = load_policy(write_policy(tmp_path, 'default_decision = "escalate"\n'))
    verdict = policy.evaluate(shell("ls"))
    assert verdict.decision == Decision.ESCALATE


@pytest.mark.parametrize(
    "text, message",
    [
        ('default_decision = "maybe"\n', "unknown decision"),
        ('surprise = 1\n', "unknown top-level keys"),
        (VALID_RULE.replace('"block"', '"explode"'), "unknown decision"),
        (VALID_RULE.replace('matcher = "shell.rm_recursive_force"', 'matcher = "shell.nope"'), "unknown matcher"),
        (VALID_RULE.replace('params = { targets = ["/"] }', 'params = { targets = ["/"], extra = 1 }'), "unknown params"),
        (VALID_RULE.replace('params = { targets = ["/"] }', ""), "requires param 'targets'"),
        (VALID_RULE.replace('reason = "test"', ""), "missing required key 'reason'"),
        (VALID_RULE.replace('reason = "test"', 'reason = "test"\nbogus = 1'), "unknown keys"),
        (VALID_RULE + VALID_RULE, "duplicate rule names"),
    ],
)
def test_invalid_policy_is_rejected(tmp_path, text, message):
    with pytest.raises(PolicyError, match=message):
        load_policy(write_policy(tmp_path, text))
