"""RTOSploit exception hierarchy.

Exit codes:
    0   Success
    1   User/configuration error
    2   Runtime error (QEMU crash, OOM)
    3   Operation failure (target not vulnerable, analysis inconclusive)
    99  Internal error (bug)
    130 Interrupted (Ctrl+C)
"""

from __future__ import annotations


class RTOSploitError(Exception):
    """Base exception for all RTOSploit errors."""
    exit_code: int = 99


# --- User / Configuration Errors (exit code 1) ---

class UserError(RTOSploitError):
    """Invalid user input or missing argument."""
    exit_code = 1


class InvalidPathError(UserError):
    """File or directory path does not exist or is not accessible."""


class MissingArgumentError(UserError):
    """Required argument was not provided."""


class ConfigError(RTOSploitError):
    """Configuration file or value error."""
    exit_code = 1


class InvalidConfigError(ConfigError):
    """Configuration file has invalid format or values."""


class UnknownMachineError(ConfigError):
    """QEMU machine type is not recognized."""


# --- Runtime Errors (exit code 2) ---

class RuntimeError(RTOSploitError):  # noqa: A001
    """Error during runtime operation."""
    exit_code = 2


class QEMUCrashError(RuntimeError):
    """QEMU process crashed or failed to start."""


class FuzzerError(RuntimeError):
    """Fuzzer runtime error."""


# --- Operation Failure (exit code 3) ---

class OperationError(RTOSploitError):
    """Operation completed but did not achieve expected result."""
    exit_code = 3


class TargetNotVulnerableError(OperationError):
    """Target does not appear to be vulnerable to the selected technique."""


class AnalysisInconclusiveError(OperationError):
    """Analysis could not determine a definitive result."""


# --- Internal Error (exit code 99) ---

class InternalError(RTOSploitError):
    """Internal RTOSploit bug. Please report this."""
    exit_code = 99
