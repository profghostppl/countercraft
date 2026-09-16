"""
Module 4: Persistence & System Partition Audit.

Queries startup items, active kernel modules, and scheduled tasks, then
flags anything executing from a non-standard location (temp directories,
unusual OEM/AppData folders) -- a common signature for both commodity
persistence malware and more targeted implants that avoid installing as
an obviously-named service.

Primary path: osquery (`osqueryi`), which normalizes most of this across
platforms via its `startup_items`, `scheduled_tasks`, `services`, and
`kernel_modules` tables.

Fallback path (osquery absent): native OS commands per platform --
`driverquery` / `schtasks` / `Get-CimInstance Win32_StartupCommand` on
Windows, `lsmod` / crontab / systemd unit inspection on Linux.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterable, Optional

from anchorroot.core.base import BaseAuditor
from anchorroot.core.models import Severity
from anchorroot.core.utils import is_linux, is_mock_mode, is_windows, run_command, run_powershell, which

_WINDOWS_STANDARD_DIRS = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows",
    r"c:\program files",
    r"c:\program files (x86)",
)
_WINDOWS_SUSPECT_MARKERS = (
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\users\public",
    # ProgramData is deliberately NOT in this list: legitimate OEM/vendor
    # tools commonly install there too, so it only earns a WARNING via the
    # non-standard-directory fallthrough below, not an automatic CRITICAL.
)

_LINUX_STANDARD_DIRS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib", "/usr/libexec", "/opt")
_LINUX_SUSPECT_MARKERS = ("/tmp/", "/var/tmp/", "/dev/shm/", "/.hidden", "/var/run/")

_EXECUTABLE_EXTENSIONS = (".exe", ".com", ".bat", ".cmd", ".ps1", ".sys", ".dll", ".vbs", ".scr")

# NT-namespace path prefixes seen in driverquery/service image paths, e.g.
# "\??\C:\Windows\system32\drv.sys" or "\SystemRoot\System32\drivers\x.sys".
_NT_DEVICE_PATH_PREFIXES = ("\\??\\", "\\\\?\\")


class PersistenceAuditor(BaseAuditor):
    name = "persistence"
    description = "Startup items, kernel modules, and scheduled tasks outside standard paths."
    requires_root = False  # most sources are readable unprivileged; degrades per-check

    @staticmethod
    def list_loaded_kernel_module_names() -> list[str]:
        """
        Raw list of currently-loaded kernel module/driver names, with no
        Finding side effects -- shared by `_audit_kernel_modules_native`
        above and by `core.diff`'s snapshot collector, which only wants
        the names to diff against a baseline.
        """
        if is_mock_mode():
            from anchorroot.mocks import MOCK_KERNEL_MODULES

            return list(MOCK_KERNEL_MODULES)
        if is_linux():
            result = run_command(["lsmod"])
            if not result.ok:
                return []
            return [line.split()[0] for line in result.stdout.splitlines()[1:] if line.strip()]
        if is_windows():
            import csv
            import io

            result = run_command(["driverquery", "/fo", "csv"])
            if not result.ok:
                return []
            reader = csv.DictReader(io.StringIO(result.stdout))
            names = []
            for row in reader:
                name = row.get("Module Name") or row.get("MODULE NAME")
                if name:
                    names.append(name)
            return names
        return []

    def audit(self) -> None:
        if which("osqueryi"):
            self._audit_via_osquery()
        else:
            self.add_finding(
                "osquery not available",
                Severity.INFO,
                "osqueryi not found on PATH; using native OS commands "
                "instead. Install osquery for more consistent cross-platform "
                "coverage.",
            )
            self._audit_native()

    # -- osquery path -----------------------------------------------------

    def _osquery(self, sql: str) -> Optional[list[dict]]:
        result = run_command(["osqueryi", "--json", sql], timeout=30.0)
        if not result.ok:
            return None
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None

    def _audit_via_osquery(self) -> None:
        startup = self._osquery("SELECT name, path, source FROM startup_items;")
        if startup is not None:
            self._evaluate_paths(
                ((row.get("name", "?"), row.get("path", "")) for row in startup),
                context="startup item",
            )
        else:
            self.add_finding(
                "osquery startup_items query failed",
                Severity.WARNING,
                "Falling back to native startup enumeration for this check.",
            )
            self._audit_startup_native()

        modules = self._osquery(
            "SELECT name, path FROM kernel_modules;"
            if is_linux()
            else "SELECT name, image FROM services WHERE type = 'KERNEL_DRIVER';"
        )
        if modules is not None:
            self._evaluate_paths(
                ((row.get("name", "?"), row.get("path") or row.get("image", "")) for row in modules),
                context="kernel module/driver",
                require_path=False,
            )
        else:
            self._audit_kernel_modules_native()

        tasks = self._osquery(
            "SELECT name, action FROM scheduled_tasks;"
            if is_windows()
            else "SELECT command, path FROM crontab;"
        )
        if tasks is not None:
            self._evaluate_paths(
                (
                    (row.get("name") or row.get("path", "?"), row.get("action") or row.get("command", ""))
                    for row in tasks
                ),
                context="scheduled task",
            )
        else:
            self._audit_scheduled_tasks_native()

    # -- native fallbacks: dispatch -----------------------------------------

    def _audit_native(self) -> None:
        self._audit_startup_native()
        self._audit_kernel_modules_native()
        self._audit_scheduled_tasks_native()

    # -- native: startup items --------------------------------------------

    def _audit_startup_native(self) -> None:
        if is_windows():
            result = run_powershell(
                "Get-CimInstance Win32_StartupCommand | "
                "Select-Object Name,Command | ConvertTo-Json -Compress"
            )
            rows = self._parse_json_rows(result.stdout)
            self._evaluate_paths(
                ((r.get("Name", "?"), r.get("Command", "")) for r in rows),
                context="startup item",
            )
        elif is_linux():
            candidates = [
                Path("/etc/xdg/autostart"),
                Path.home() / ".config" / "autostart",
            ]
            for directory in candidates:
                if not directory.is_dir():
                    continue
                for entry in directory.glob("*.desktop"):
                    exec_line = self._extract_desktop_exec(entry)
                    if exec_line:
                        self._evaluate_paths(
                            [(entry.name, exec_line)], context="startup item (autostart)"
                        )

    @staticmethod
    def _extract_desktop_exec(path: Path) -> Optional[str]:
        try:
            for line in path.read_text(errors="ignore").splitlines():
                if line.startswith("Exec="):
                    return line[len("Exec=") :].strip()
        except OSError:
            pass
        return None

    # -- native: kernel modules / drivers -----------------------------------

    def _audit_kernel_modules_native(self) -> None:
        if is_linux():
            result = run_command(["lsmod"])
            if not result.ok:
                self.add_finding(
                    "Could not enumerate kernel modules",
                    Severity.WARNING,
                    f"lsmod failed: {result.stderr.strip()}",
                )
                return
            module_names = [
                line.split()[0] for line in result.stdout.splitlines()[1:] if line.strip()
            ]
            unsigned = self._linux_unsigned_modules(module_names)
            if unsigned:
                self.add_finding(
                    "Unsigned kernel modules loaded",
                    Severity.WARNING,
                    f"{len(unsigned)} loaded module(s) are unsigned: "
                    f"{', '.join(unsigned[:10])}"
                    + (f" (+{len(unsigned) - 10} more)" if len(unsigned) > 10 else ""),
                    remediation="Unsigned modules are expected for "
                    "out-of-tree/DKMS drivers (e.g. GPU, VPN clients) but "
                    "worth a manual review if unrecognized.",
                )
            else:
                self.add_finding(
                    "All loaded kernel modules signed",
                    Severity.INFO,
                    f"Checked {len(module_names)} loaded modules.",
                )
        elif is_windows():
            result = run_command(["driverquery", "/v", "/fo", "csv"])
            if not result.ok:
                self.add_finding(
                    "Could not enumerate drivers",
                    Severity.WARNING,
                    f"driverquery failed: {result.stderr.strip()}",
                )
                return
            self._evaluate_driverquery_csv(result.stdout)

    def _linux_unsigned_modules(self, module_names: Iterable[str]) -> list[str]:
        unsigned = []
        for name in module_names:
            info = run_command(["modinfo", "-F", "signer", name], timeout=5.0)
            if info.ok and not info.stdout.strip():
                unsigned.append(name)
        return unsigned

    def _evaluate_driverquery_csv(self, csv_text: str) -> None:
        import csv
        import io

        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            path = row.get("Path", "") or row.get("PATH", "")
            name = row.get("Module Name", "?") or row.get("MODULE NAME", "?")
            self._evaluate_paths([(name, path)], context="driver", require_path=False)

    # -- native: scheduled tasks ---------------------------------------------

    def _audit_scheduled_tasks_native(self) -> None:
        if is_windows():
            result = run_powershell(
                "Get-ScheduledTask | ForEach-Object { "
                "$a = $_.Actions | Select-Object -First 1; "
                "[PSCustomObject]@{Name=$_.TaskName; Path=$a.Execute} } | "
                "ConvertTo-Json -Compress"
            )
            rows = self._parse_json_rows(result.stdout)
            self._evaluate_paths(
                ((r.get("Name", "?"), r.get("Path") or "") for r in rows),
                context="scheduled task",
                require_path=False,
            )
        elif is_linux():
            for cron_source, cmd in (
                ("user crontab", ["crontab", "-l"]),
                ("system crontab", ["cat", "/etc/crontab"]),
            ):
                result = run_command(cmd)
                if result.ok:
                    self._evaluate_cron_lines(result.stdout, cron_source)

            cron_d = Path("/etc/cron.d")
            if cron_d.is_dir():
                for entry in cron_d.iterdir():
                    if entry.is_file():
                        try:
                            self._evaluate_cron_lines(entry.read_text(errors="ignore"), f"cron.d/{entry.name}")
                        except OSError:
                            continue

    def _evaluate_cron_lines(self, text: str, source: str) -> None:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # crontab fields: min hour dom mon dow [user] command...
            parts = line.split(None, 5 if source != "user crontab" else 4)
            command = parts[-1] if parts else ""
            self._evaluate_paths([(source, command)], context="cron entry", require_path=False)

    # -- shared classification logic -----------------------------------------

    def _evaluate_paths(
        self,
        items: Iterable[tuple[str, str]],
        *,
        context: str,
        require_path: bool = True,
    ) -> None:
        checked = 0
        for name, raw_path in items:
            if not raw_path:
                if require_path:
                    self.add_finding(
                        f"{context.capitalize()} with no resolvable path",
                        Severity.INFO,
                        f"'{name}' has no executable path recorded.",
                    )
                continue
            checked += 1
            exe_path = self._extract_executable(raw_path)
            classification = self._classify_path(exe_path)
            if classification is None:
                continue
            severity, reason = classification
            self.add_finding(
                f"Suspicious {context} location",
                severity,
                f"'{name}' ({context}) executes from {reason}: {exe_path}",
                remediation="Verify this binary is expected; if unrecognized, "
                "isolate and investigate the file and its origin.",
                item_name=name,
                path=exe_path,
                context=context,
            )
        if checked == 0 and require_path is False:
            return

    @staticmethod
    def _extract_executable(command_line: str) -> str:
        command_line = command_line.strip()
        if not command_line:
            return command_line
        match = re.match(r'"([^"]+)"', command_line)
        if match:
            return match.group(1)

        tokens = command_line.split()
        if len(tokens) <= 1:
            return command_line

        # On Linux/cron, the first whitespace-delimited token is reliably
        # the executable (paths with unescaped spaces are rare and not
        # something we can disambiguate from arguments anyway). Only try
        # to recover a multi-token path on Windows-shaped input, where
        # sources like Get-ScheduledTask's Action.Execute return a bare,
        # unquoted path that may itself contain spaces (typical under
        # "Program Files") -- naively taking the first token would
        # truncate "C:\Program Files\Foo\bar.exe --flag" to "C:\Program".
        looks_like_windows_path = "\\" in tokens[0] or re.match(r"^[A-Za-z]:", tokens[0])
        if not looks_like_windows_path:
            return tokens[0]

        # Grow the candidate token-by-token until it either resolves to a
        # real file on disk or ends in a recognized executable extension
        # (the extension check also covers orphaned tasks whose target
        # binary has since been uninstalled, where is_file() alone would fail).
        candidate = tokens[0]
        for token in tokens[1:]:
            if candidate.lower().endswith(_EXECUTABLE_EXTENSIONS) or Path(
                os.path.expandvars(candidate)
            ).is_file():
                break
            candidate += " " + token
        return candidate

    @staticmethod
    def _classify_path(path: str) -> Optional[tuple[Severity, str]]:
        # Startup/task sources routinely hand back unexpanded %windir%,
        # %SystemRoot%, %ProgramFiles% etc, and driverquery/services report
        # NT-namespace paths like "\??\C:\Windows\system32\drv.sys" -- left
        # unexpanded/unnormalized, nearly every built-in Windows driver and
        # scheduled task would misclassify as "non-standard" since it
        # wouldn't literal-match the standard-dir prefixes below.
        path = os.path.expandvars(path)
        if is_windows():
            path = PersistenceAuditor._normalize_windows_path(path)
        # A bare filename with no directory component (e.g. a scheduled
        # task whose Execute is just "powershell.exe", relying on PATH
        # resolution) can't be judged against the standard-dir prefixes
        # below without resolving it first -- otherwise every such entry,
        # including common built-in Windows tasks, reads as "non-standard".
        if "\\" not in path and "/" not in path:
            resolved = which(path)
            if resolved:
                path = resolved
        lower = path.lower()
        if is_windows():
            if any(marker in lower for marker in _WINDOWS_SUSPECT_MARKERS):
                return Severity.CRITICAL, "a temporary/public/unusual OEM directory"
            if not any(lower.startswith(d) for d in _WINDOWS_STANDARD_DIRS):
                return Severity.WARNING, "a non-standard install directory"
            return None
        if any(marker in lower for marker in _LINUX_SUSPECT_MARKERS):
            return Severity.CRITICAL, "a world-writable temp directory"
        if lower.startswith("/home/") or lower.startswith("/root/"):
            return Severity.WARNING, "a user home directory rather than a system path"
        if not any(lower.startswith(d) for d in _LINUX_STANDARD_DIRS):
            return Severity.WARNING, "a non-standard install directory"
        return None

    @staticmethod
    def _normalize_windows_path(path: str) -> str:
        for prefix in _NT_DEVICE_PATH_PREFIXES:
            if path.startswith(prefix):
                path = path[len(prefix):]
                break
        if path.lower().startswith("\\systemroot\\"):
            systemroot = os.environ.get("SystemRoot", r"C:\Windows")
            path = systemroot + path[len("\\SystemRoot"):]
        return path

    @staticmethod
    def _parse_json_rows(raw: str) -> list[dict]:
        raw = raw.strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [d for d in data if isinstance(d, dict)]
        return []
