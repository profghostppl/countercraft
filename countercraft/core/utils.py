"""
Shared low-level helpers: subprocess execution, privilege detection, and
platform identification. Every module goes through `run_command` so we get
consistent timeout handling and never let a hung external tool (chipsec,
binwalk, osquery...) stall the whole audit.

Also owns the global mock-mode toggle (`--mock`/`--dry-run`): when enabled,
`which`, `run_command`, `run_powershell`, and `is_elevated` all answer from
`countercraft.mocks` instead of touching the real OS/hardware, so the entire suite
can run and produce a full report with no root, no TPM, no CHIPSEC driver,
and none of the external tools actually installed. This is the single
interception point -- individual modules never need to know mock mode
exists.
"""

from __future__ import annotations

import ctypes
import dataclasses
import os
import platform
import shutil
import subprocess
from typing import Optional


class OS:
    WINDOWS = "Windows"
    LINUX = "Linux"
    DARWIN = "Darwin"


_mock_mode = False


def set_mock_mode(enabled: bool) -> None:
    """Enable/disable global mock mode. Call once, early, from the CLI."""
    global _mock_mode
    _mock_mode = enabled


def is_mock_mode() -> bool:
    return _mock_mode


def current_os() -> str:
    return platform.system()


def is_windows() -> bool:
    return current_os() == OS.WINDOWS


def is_linux() -> bool:
    return current_os() == OS.LINUX


def is_macos() -> bool:
    return current_os() == OS.DARWIN


def is_elevated() -> bool:
    """
    True if running as root (POSIX) or an elevated Administrator (Windows).
    Several modules degrade to read-only / partial checks instead of
    failing outright when this is False -- see each module's docstring.

    In mock mode this always returns True: mock mode's purpose is to
    exercise the "elevated" code paths too (e.g. CHIPSEC register checks),
    safely, since `run_command`/`run_powershell` are themselves mocked and
    never touch anything real regardless of what this returns.
    """
    if _mock_mode:
        return True
    if is_windows():
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        return False


def which(binary: str) -> Optional[str]:
    """
    Locate an external tool on PATH, or None.

    In mock mode, real PATH is ignored entirely -- only binaries with a
    registered mock fixture (`countercraft.mocks.MOCK_AVAILABLE_BINARIES`)
    report as present, so mock runs are fully deterministic and independent
    of what happens to be installed on the machine running them.
    """
    if _mock_mode:
        from countercraft.mocks import mock_which

        return mock_which(binary)
    return shutil.which(binary)


@dataclasses.dataclass(slots=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def run_command(
    args: list[str],
    timeout: float = 30.0,
    shell: bool = False,
    input_text: Optional[str] = None,
) -> CommandResult:
    """
    Run an external command defensively: never raises on a missing binary
    or non-zero exit, always bounds runtime with a timeout, and normalizes
    output to text. Callers inspect `.ok` / `.returncode` themselves.

    Output is sanitized (control/escape sequences stripped, length capped)
    before it's ever returned to a caller -- see `countercraft.utils.security`
    -- and decoding never raises on malformed bytes from a buggy or hostile
    external tool (`errors="replace"`).

    In mock mode, this never touches the real subprocess layer at all:
    it always returns a canned/synthesized result from `countercraft.mocks`.
    """
    if _mock_mode:
        from countercraft.mocks import mock_command

        return mock_command(args)

    from countercraft.utils.security import sanitize_output

    try:
        proc = subprocess.run(
            args,
            shell=shell,
            input=input_text,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            args=args,
            returncode=proc.returncode,
            stdout=sanitize_output(proc.stdout or ""),
            stderr=sanitize_output(proc.stderr or ""),
        )
    except FileNotFoundError:
        return CommandResult(args=args, returncode=127, stdout="", stderr="binary not found")
    except subprocess.TimeoutExpired:
        return CommandResult(
            args=args, returncode=-1, stdout="", stderr="command timed out", timed_out=True
        )
    except Exception as exc:  # noqa: BLE001 - defensive by design, surfaced to caller
        return CommandResult(args=args, returncode=-1, stdout="", stderr=str(exc))


def run_powershell(script: str, timeout: float = 30.0) -> CommandResult:
    """Convenience wrapper for one-off PowerShell probes on Windows."""
    return run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
    )
