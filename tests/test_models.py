import pytest

from guardrail.models import Decision, ToolCall


def test_decision_has_exactly_the_four_outcomes():
    assert {d.value for d in Decision} == {"allow", "block", "dry_run", "escalate"}


def test_toolcall_holds_tool_and_arguments():
    call = ToolCall(tool="shell", arguments={"command": "ls -la"})
    assert call.tool == "shell"
    assert call.arguments == {"command": "ls -la"}


def test_toolcall_arguments_default_to_empty_dict():
    assert ToolCall(tool="shell").arguments == {}


def test_toolcall_is_immutable():
    call = ToolCall(tool="shell")
    with pytest.raises(AttributeError):
        call.tool = "other"  # type: ignore[misc]


@pytest.mark.parametrize("bad_tool", ["", "   "])
def test_toolcall_rejects_blank_tool_name(bad_tool):
    with pytest.raises(ValueError):
        ToolCall(tool=bad_tool)


def test_toolcall_rejects_non_dict_arguments():
    with pytest.raises(TypeError):
        ToolCall(tool="shell", arguments=["ls"])  # type: ignore[arg-type]
