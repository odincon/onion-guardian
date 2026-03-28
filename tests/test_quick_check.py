from __future__ import annotations

from onion_guardian import ActionVerdict, OnionGuardian


def build_guardian() -> OnionGuardian:
    return OnionGuardian.from_config(enable_llm=False)


def test_allows_safe_python_execution() -> None:
    guardian = build_guardian()

    result = guardian.quick_check(
        action="execute_code",
        params={"language": "python", "code": "print('ok')"},
        session_id="test_session",
        user_id="test_user",
    )

    assert result.verdict == ActionVerdict.ALLOW
    assert result.execution_output is not None
    assert result.execution_output["action"] == "sandbox_executor.run"


def test_blocks_privilege_escalation_command() -> None:
    guardian = build_guardian()

    result = guardian.quick_check(
        action="run_command",
        params={"command": "sudo ls", "working_dir": "."},
        session_id="test_session",
        user_id="test_user",
    )

    assert result.verdict == ActionVerdict.BLOCK
    assert result.reason is not None
    assert "privilege" in result.reason.lower()


def test_blocks_parent_directory_read() -> None:
    guardian = build_guardian()

    result = guardian.quick_check(
        action="read_file",
        params={"path": "../secret.txt"},
        session_id="test_session",
        user_id="test_user",
    )

    assert result.verdict == ActionVerdict.BLOCK
    assert result.reason is not None
    assert "relative path" in result.reason.lower()
