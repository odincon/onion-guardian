"""
onion_guardian.defaults - default values for all tunable parameters.

This file is the single source of truth for default numeric limits and list
values. Modules should import `DEFAULT_*` constants from here instead of
hardcoding them locally.

Ways to override defaults:
  - simplest: edit this file directly
  - recommended: pass explicit constructor arguments
  - production: use YAML config plus environment overrides

Priority: this file < YAML config < environment variables < constructor args
"""

from __future__ import annotations

# ═══════════════════════════════════════════════════════════
# Network policy
# ═══════════════════════════════════════════════════════════

DEFAULT_NETWORK_MODE = "restricted"

DEFAULT_ALLOWED_DOMAINS: list[str] = [
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "github.com",
    "raw.githubusercontent.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
]

DEFAULT_ALLOWED_PORTS: list[int] = [80, 443, 8080, 8443]

DEFAULT_BLOCKED_PORTS: list[int] = [
    22, 23, 25, 53, 135, 137, 138, 139, 445, 3389,
]

DEFAULT_BLOCKED_NETWORKS: list[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "0.0.0.0/8",
    "100.64.0.0/10",
    "198.18.0.0/15",
    "fc00::/7",
    "fe80::/10",
    "::1/128",
]

DEFAULT_DNS_SERVERS: list[str] = ["8.8.8.8", "8.8.4.4"]

DEFAULT_MAX_CONCURRENT_CONNECTIONS = 10
DEFAULT_MAX_DOWNLOAD_SIZE_MB = 100

# ═══════════════════════════════════════════════════════════
# Sandbox / resource limits
# ═══════════════════════════════════════════════════════════

DEFAULT_SANDBOX_BASE_PATH = "/workspace"
DEFAULT_MAX_FILE_SIZE_MB = 100
DEFAULT_DISK_QUOTA_MB = 500
DEFAULT_MAX_PROCESSES = 10
DEFAULT_MAX_OPEN_FILES = 256
DEFAULT_MAX_MEMORY_MB = 512
DEFAULT_MAX_EXECUTION_TIME_SEC = 30
DEFAULT_TMPFS_SIZE_MB = 64
DEFAULT_CPU_PERIOD = 100_000
DEFAULT_CPU_PERCENT = 80
DEFAULT_NOBODY_UID = 65534
DEFAULT_NOBODY_GID = 65534

DEFAULT_READONLY_PATHS: list[str] = [
    "/user_data",
    "/etc",
    "/usr",
    "/opt",
]

DEFAULT_HIDDEN_PATHS: list[str] = [
    "/user_data/certificates",
    "/user_data/sessions",
    "/proc/1/environ",
    "/etc/shadow",
    "/etc/ssh",
    "/root/.ssh",
]

DEFAULT_WRITABLE_WHITELIST: list[str] = [
    ".",
    "src",
    "output",
    "tmp",
    "node_modules",
    "__pycache__",
]

DEFAULT_ALLOWED_READONLY_PREFIXES: list[str] = [
    "/usr/lib/",
    "/usr/share/",
    "/opt/venv/",
]

# ═══════════════════════════════════════════════════════════
# Rate limiting
# ═══════════════════════════════════════════════════════════

DEFAULT_RATE_LIMIT_PER_MINUTE = 30

# ═══════════════════════════════════════════════════════════
# Parameter length limits (DoS protection)
# ═══════════════════════════════════════════════════════════

DEFAULT_MAX_LENGTHS: dict[str, int] = {
    "code": 100_000,
    "source": 100_000,
    "content": 500_000,
    "data": 500_000,
    "command": 10_000,
    "cmd": 10_000,
    "query": 5_000,
    "pattern": 5_000,
    "url": 2_048,
    "target_url": 2_048,
}

DEFAULT_MAX_STRING_LENGTH = 50_000  # Default cap for keys not listed above.
 
# ═══════════════════════════════════════════════════════════
# Guardian model
# ═══════════════════════════════════════════════════════════

DEFAULT_GUARDIAN_BACKEND = "local"
DEFAULT_LOCAL_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_ANTHROPIC_MODEL = "claude-3-haiku-20240307"
DEFAULT_GUARDIAN_TEMPERATURE = 0.1
DEFAULT_GUARDIAN_MAX_TOKENS = 512

# ═══════════════════════════════════════════════════════════
# Intent analysis
# ═══════════════════════════════════════════════════════════

# Minimum number of distinct sensitive-keyword hits in recent history
# to trigger a context-drift signal.  This is an honest discrete count —
# no density formula or continuous scoring is involved.
DEFAULT_DRIFT_MIN_HITS = 3

DEFAULT_SENSITIVE_KEYWORDS: set[str] = {
    "password", "secret", "key", "token",
    "private_key", "certificate",
    "/etc/shadow", "/etc/passwd", "environment variables",
    "host machine", "host ip",
    "docker socket", "/var/run/docker.sock",
}

# ═══════════════════════════════════════════════════════════
# Audit
# ═══════════════════════════════════════════════════════════

DEFAULT_AUDIT_LOG_PATH = "/tmp/onion-guardian/audit.jsonl"
DEFAULT_AUDIT_LEVEL = "INFO"
