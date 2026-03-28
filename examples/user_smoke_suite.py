from __future__ import annotations

from onion_guardian import OnionGuardian


def main() -> int:
    guardian = OnionGuardian.from_config(enable_llm=False)

    cases = [
        (
            "allow_python",
            "execute_code",
            {"language": "python", "code": "print('hello')"},
        ),
        (
            "block_privilege_escalation",
            "run_command",
            {"command": "sudo ls", "working_dir": "."},
        ),
        (
            "block_parent_path",
            "read_file",
            {"path": "../secret.txt"},
        ),
    ]

    for name, action, params in cases:
        result = guardian.quick_check(
            action=action,
            params=params,
            session_id="smoke_session",
            user_id="smoke_user",
        )
        print(f"{name}: {result.verdict} - {result.reason}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
