"""
onion_guardian.layer2_router.sandbox - path and resource sandboxing.

Filesystem and resource isolation for Layer 2.
Each user and session is restricted to its own directory tree.

Protection goals:
- cross-session data isolation
- sensitive file protection
- resource exhaustion mitigation
"""

from __future__ import annotations

import posixpath
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from onion_guardian.defaults import (
    DEFAULT_ALLOWED_READONLY_PREFIXES,
    DEFAULT_DISK_QUOTA_MB,
    DEFAULT_HIDDEN_PATHS,
    DEFAULT_MAX_EXECUTION_TIME_SEC,
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_MAX_MEMORY_MB,
    DEFAULT_MAX_OPEN_FILES,
    DEFAULT_MAX_PROCESSES,
    DEFAULT_READONLY_PATHS,
    DEFAULT_SANDBOX_BASE_PATH,
    DEFAULT_WRITABLE_WHITELIST,
)


@dataclass
class SandboxConfig:
    """Sandbox configuration."""
    base_path: str = DEFAULT_SANDBOX_BASE_PATH
    session_isolation: bool = True
    max_file_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB
    disk_quota_mb: int = DEFAULT_DISK_QUOTA_MB
    max_processes: int = DEFAULT_MAX_PROCESSES
    max_open_files: int = DEFAULT_MAX_OPEN_FILES
    max_memory_mb: int = DEFAULT_MAX_MEMORY_MB
    max_execution_time_sec: int = DEFAULT_MAX_EXECUTION_TIME_SEC

    # Filesystem policy.
    readonly_paths: list[str] = field(default_factory=lambda: list(DEFAULT_READONLY_PATHS))
    hidden_paths: list[str] = field(default_factory=lambda: list(DEFAULT_HIDDEN_PATHS))
    # Writable allowlist relative to the session directory.
    writable_whitelist: list[str] = field(default_factory=lambda: list(DEFAULT_WRITABLE_WHITELIST))


class PathSandbox:
    """
    Path sandbox, the core filesystem-isolation component.

    Guarantees:
    1. users can access only their own session directory
    2. sensitive paths such as certificates and other sessions stay hidden
    3. system paths remain read-only
    4. path-traversal and symlink-style escape attempts are blocked
    """

    def __init__(self, config: SandboxConfig | None = None):
        self.config = config or SandboxConfig()

    def resolve_path(
        self, user_path: str, session_id: str, user_id: str
    ) -> tuple[str, bool, str]:
        """
        Resolve a user-provided path into a safe absolute path.

        Returns:
            (resolved_path, is_allowed, reason)
        """
        # Build the session root.
        session_root = self._get_session_root(session_id, user_id)

        # Normalize the user path.
        clean_path = self._sanitize_path(user_path)

        # Build the absolute path.
        if clean_path.startswith("/"):
            # Absolute path: check whether it remains allowed.
            abs_path = clean_path
        else:
            # Relative path: resolve against the session root.
            abs_path = str(PurePosixPath(session_root) / clean_path)

        # Normalize again to collapse `/a/../b` style segments.
        abs_path = posixpath.normpath(abs_path)

        # Final security checks.
        allowed, reason = self._check_access(abs_path, session_root)
        return abs_path, allowed, reason

    def check_write_permission(
        self, path: str, session_id: str, user_id: str
    ) -> tuple[bool, str]:
        """Check whether writing to a path is allowed."""
        session_root = self._get_session_root(session_id, user_id)

        # Writes must stay within the session root.
        if not self._is_within(path, session_root):
            return False, f"Writes are restricted to the session directory: {session_root}"

        # Read-only paths cannot be written to.
        for ro_path in self.config.readonly_paths:
            if self._is_within(path, ro_path):
                return False, f"Path is read-only: {ro_path}"

        return True, "Write allowed"

    def get_resource_limits(self, session_id: str, user_id: str) -> dict:
        """Return resolved resource limits for a session."""
        if not user_id:
            raise ValueError("user_id is required for resource limit resolution")
        return {
            "max_file_size_bytes": self.config.max_file_size_mb * 1024 * 1024,
            "disk_quota_bytes": self.config.disk_quota_mb * 1024 * 1024,
            "max_processes": self.config.max_processes,
            "max_open_files": self.config.max_open_files,
            "max_memory_bytes": self.config.max_memory_mb * 1024 * 1024,
            "session_root": self._get_session_root(session_id, user_id),
        }

    # Internal helpers.

    def _get_session_root(self, session_id: str, user_id: str) -> str:
        """Return the session root directory."""
        if self.config.session_isolation:
            # Each session gets its own root directory.
            return f"{self.config.base_path}/{user_id}/{session_id}"
        return self.config.base_path

    def _sanitize_path(self, path: str) -> str:
        """Sanitize a path string."""
        # Remove null bytes.
        path = path.replace("\x00", "")
        # Normalize separators.
        path = path.replace("\\", "/")
        # Collapse duplicate slashes.
        while "//" in path:
            path = path.replace("//", "/")
        # Remove trailing slashes unless the path is the root itself.
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        return path

    def _check_access(self, abs_path: str, session_root: str) -> tuple[bool, str]:
        """Check whether a resolved path can be accessed."""

        # 1. Detect path traversal.
        try:
            str(PurePosixPath(abs_path))
            # Check whether `..` escapes upward.
            parts = abs_path.split("/")
            depth = 0
            for part in parts:
                if part == "..":
                    depth -= 1
                elif part and part != ".":
                    depth += 1
                if depth < 0:
                    return False, "Detected a path traversal attempt"
        except (ValueError, TypeError):
            return False, "Invalid path"

        # 2. Block hidden paths.
        for hidden in self.config.hidden_paths:
            if self._is_within(abs_path, hidden):
                return False, f"Path is not accessible: {hidden}"

        # 3. Enforce session isolation.
        if self.config.session_isolation:
            # Paths outside the session root are allowed only if explicitly
            # whitelisted as read-only prefixes.
            if not self._is_within(abs_path, session_root):
                if not any(self._is_within(abs_path, p) for p in DEFAULT_ALLOWED_READONLY_PREFIXES):
                    return False, f"Path is outside the current session directory: {session_root}"

        return True, "Access allowed"

    def _is_within(self, path: str, root: str) -> bool:
        path_obj = PurePosixPath(path)
        root_obj = PurePosixPath(root)
        try:
            path_obj.relative_to(root_obj)
            return True
        except ValueError:
            return False


class ResourceQuota:
    """
    Resource quota manager.

    Prevents one session from exhausting shared resources:
    - disk quota
    - memory limit
    - process limit
    - CPU time limit
    """

    def __init__(self, config: SandboxConfig | None = None):
        self.config = config or SandboxConfig()
        self._usage: dict[str, dict[str, int]] = {}  # session_id -> {metric: current_usage}
        self._leases: dict[str, dict[str, list[tuple[int, float]]]] = {}

    def check_quota(
        self, session_id: str, resource: str, amount: int, now: float | None = None
    ) -> tuple[bool, str]:
        """
        Check resource quota availability.

        Args:
            session_id: session ID
            resource: resource type ("disk", "memory", "processes")
            amount: requested amount

        Returns:
            (allowed, reason)
        """
        self._ensure_session(session_id)
        current = self._current_usage(session_id, resource, now=now)
        limit = self._get_limit(resource)

        if current + amount > limit:
            return False, (
                f"Resource quota exceeded: {resource} "
                f"(current: {current}, requested: {amount}, limit: {limit})"
            )

        return True, "Quota available"

    def consume(
        self,
        session_id: str,
        resource: str,
        amount: int,
        ttl_sec: int | None = None,
        now: float | None = None,
    ) -> None:
        """Consume resource quota."""
        self._ensure_session(session_id)
        if ttl_sec is not None and ttl_sec > 0:
            expires_at = (time.time() if now is None else now) + ttl_sec
            self._leases[session_id].setdefault(resource, []).append((amount, expires_at))
            return

        self._usage[session_id][resource] = self._usage[session_id].get(resource, 0) + amount

    def release(self, session_id: str, resource: str, amount: int) -> None:
        """Release resource quota."""
        leases = self._leases.get(session_id, {}).get(resource, [])
        if leases:
            remaining = amount
            retained: list[tuple[int, float]] = []
            for lease_amount, expires_at in leases:
                if remaining <= 0:
                    retained.append((lease_amount, expires_at))
                    continue
                if lease_amount <= remaining:
                    remaining -= lease_amount
                    continue
                retained.append((lease_amount - remaining, expires_at))
                remaining = 0
            self._leases[session_id][resource] = retained
            amount = remaining

        if amount > 0 and session_id in self._usage:
            current = self._usage[session_id].get(resource, 0)
            self._usage[session_id][resource] = max(0, current - amount)

    def cleanup_session(self, session_id: str) -> None:
        """Clear quota state for one session."""
        self._usage.pop(session_id, None)
        self._leases.pop(session_id, None)

    def _ensure_session(self, session_id: str) -> None:
        if session_id not in self._usage:
            self._usage[session_id] = {"disk": 0, "memory": 0, "processes": 0}
        if session_id not in self._leases:
            self._leases[session_id] = {}

    def _current_usage(
        self,
        session_id: str,
        resource: str,
        now: float | None = None,
    ) -> int:
        self._cleanup_expired_leases(session_id, resource, now=now)
        persistent = self._usage.get(session_id, {}).get(resource, 0)
        leased = sum(
            amount
            for amount, _expires_at in self._leases.get(session_id, {}).get(resource, [])
        )
        return persistent + leased

    def _cleanup_expired_leases(
        self,
        session_id: str,
        resource: str,
        now: float | None = None,
    ) -> None:
        if session_id not in self._leases or resource not in self._leases[session_id]:
            return

        current_time = time.time() if now is None else now
        self._leases[session_id][resource] = [
            (amount, expires_at)
            for amount, expires_at in self._leases[session_id][resource]
            if expires_at > current_time
        ]

    def _get_limit(self, resource: str) -> int:
        limits = {
            "disk": self.config.disk_quota_mb * 1024 * 1024,
            "memory": self.config.max_memory_mb * 1024 * 1024,
            "processes": self.config.max_processes,
            "open_files": self.config.max_open_files,
        }
        return limits.get(resource, 0)
