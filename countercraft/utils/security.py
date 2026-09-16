"""
Privilege-aware execution helpers and output sanitization.

Distinct from `countercraft.core.utils` (which owns the raw subprocess/platform
primitives -- `run_command`, `is_elevated`, `which`, ...): this module is
the policy layer on top of those primitives, covering two concerns the
brief calls out specifically:

1. Elevated commands should fail *gracefully*, with a message that says
   exactly what's missing (a permission, or a package) and how to fix it
   -- not a raw "Access is denied" / "Operation not permitted" traceback.
2. Output from external tools -- which on a compromised or simply buggy
   system may contain malformed byte sequences, embedded ANSI/terminal
   control sequences, or unbounded garbage -- must be sanitized before it
   is parsed or ever printed to a terminal, since a malicious peripheral
   or firmware string is attacker-controlled input reaching our process.

`countercraft.core.utils.run_command` calls `sanitize_output` on every command's
stdout/stderr as a blanket defense; this module additionally exposes
`run_privileged` for the specific case of a command that is *known* to
require elevation, so a module can skip the doomed attempt entirely and
surface a clear remediation message on the spot.
"""

from __future__ import annotations

import re

from countercraft.core.utils import CommandResult, is_elevated, is_linux, is_macos, is_windows, run_command

# -- output sanitization -------------------------------------------------

# ANSI/VT100 escape sequences: CSI (`\x1b[...<letter>`), OSC (`\x1b]...BEL`),
# and other two-byte Fe escapes. A malicious device/firmware string (DMI,
# SMBIOS, a scheduled task name, a USB device descriptor) could embed these
# to spoof or corrupt terminal output when a finding is later printed.
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]")

# C0 control characters other than tab (\x09) and newline (\x0a), plus DEL.
# This also strips \r (0x0d), which can otherwise be used to overwrite a
# previously printed line in a terminal.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

DEFAULT_MAX_OUTPUT_LEN = 200_000


def sanitize_output(text: str, max_len: int = DEFAULT_MAX_OUTPUT_LEN) -> str:
    """
    Strip terminal escape sequences and control characters from external
    command output, and cap its length. Safe to call on already-clean
    text (a no-op in that case) -- applied unconditionally by
    `core.utils.run_command`/`run_powershell` to every command's
    stdout/stderr, so individual modules don't need to remember to.
    """
    if not text:
        return text
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _CONTROL_CHARS_RE.sub("", text)
    if len(text) > max_len:
        text = text[:max_len] + "\n...[output truncated]"
    return text


# -- missing-dependency / privilege remediation messages -----------------

# Best-effort install hints per binary. Not exhaustive -- covers the
# external tools CounterCraft's modules shell out to. A binary absent from this
# table still gets a generic "not found on PATH" message, just without
# the package-manager-specific hint.
_BINARY_PACKAGE_HINTS: dict[str, dict[str, str]] = {
    "chipsec_main": {"pip": "chipsec", "note": "also requires installing CHIPSEC's kernel driver"},
    "mokutil": {"apt": "mokutil", "dnf": "mokutil"},
    "UEFIExtract": {"note": "part of UEFITool -- https://github.com/LongSoft/UEFITool/releases"},
    "binwalk": {"apt": "binwalk", "dnf": "binwalk", "brew": "binwalk"},
    "flashrom": {"apt": "flashrom", "dnf": "flashrom", "brew": "flashrom"},
    "osqueryi": {"note": "https://osquery.io/downloads"},
    "tpm2_pcrread": {"apt": "tpm2-tools", "dnf": "tpm2-tools", "brew": "tpm2-tools"},
    "intelmetool": {"note": "part of coreboot -- build from https://github.com/coreboot/coreboot (util/intelmetool)"},
    "openssl": {"apt": "openssl", "dnf": "openssl", "brew": "openssl"},
}


def describe_missing_binary(binary: str) -> str:
    """
    Compose a specific, actionable "how do I get this tool" message for a
    binary that was not found on PATH, instead of a bare "not found".
    """
    hints = _BINARY_PACKAGE_HINTS.get(binary, {})
    parts = [f"'{binary}' was not found on PATH."]
    pkg_hints = []
    if "apt" in hints:
        pkg_hints.append(f"apt install {hints['apt']} (Debian/Ubuntu)")
    if "dnf" in hints:
        pkg_hints.append(f"dnf install {hints['dnf']} (Fedora/RHEL)")
    if "brew" in hints:
        pkg_hints.append(f"brew install {hints['brew']} (macOS)")
    if "pip" in hints:
        pkg_hints.append(f"pip install {hints['pip']}")
    if pkg_hints:
        parts.append("Install with: " + "; or ".join(pkg_hints) + ".")
    if "note" in hints:
        parts.append(hints["note"] + ".")
    return " ".join(parts)


def describe_elevation_required(context: str) -> str:
    """
    Platform-aware "how do I get elevated" message, naming the specific
    action being blocked so the remediation reads as instructions, not a
    generic permission error.
    """
    if is_windows():
        how = (
            "Re-run this terminal as Administrator (right-click the "
            "terminal/shortcut and choose 'Run as Administrator', or from "
            "an existing elevated PowerShell run the same command again)."
        )
    elif is_macos() or is_linux():
        how = "Re-run with sudo, e.g.: sudo countercraft ..."
    else:
        how = "Re-run this process with elevated/root privileges."
    return f"{context} requires elevated privileges. {how}"


def elevation_required_result(context: str) -> CommandResult:
    """
    A CommandResult-shaped stand-in for a command that was never attempted
    because the process isn't elevated -- used instead of letting the real
    command run and fail with a raw, less helpful OS permission error.
    """
    return CommandResult(
        args=[],
        returncode=126,  # conventional "found but not executable/permitted"
        stdout="",
        stderr=describe_elevation_required(context),
    )


def run_privileged(args: list[str], context: str, timeout: float = 30.0) -> CommandResult:
    """
    Run a command known to require elevation, failing gracefully with a
    clear remediation message instead of attempting it when unprivileged.

    `context` should name the specific check being performed (e.g. "SPI
    flash write-protection register read"), not just the binary -- it
    goes directly into the user-facing message.
    """
    if not is_elevated():
        return elevation_required_result(context)
    return run_command(args, timeout=timeout)
