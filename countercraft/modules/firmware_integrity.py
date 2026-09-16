"""
Module 2: Firmware Hash & Integrity Checker.

Ingests a dumped SPI BIOS/UEFI binary (e.g. `flashrom -r image.bin`, or a
vendor update payload), extracts component partitions/modules using
`UEFIExtract` (preferred, ships with UEFITool) or `binwalk` as a fallback,
then hashes each extracted file and compares against:

  1. A local baseline JSON (SHA-256 per relative path) captured on a
     known-good system -- flags anything ADDED, REMOVED, or CHANGED.
  2. A denylist of known-untrusted digests/key fingerprints.

This module does not attempt to parse PE/TE section internals itself --
that's exactly the job UEFIExtract already does well. Re-implementing a
UEFI firmware volume parser here would be a large, security-sensitive
undertaking better left to the maintained upstream tool.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from countercraft.core.base import BaseAuditor
from countercraft.core.models import Severity
from countercraft.core.utils import run_command, which


class FirmwareIntegrityChecker(BaseAuditor):
    name = "firmware_integrity"
    description = "Extracts and hashes UEFI firmware modules, diffing against a baseline."
    requires_root = False  # operates on a file the caller already dumped

    def __init__(
        self,
        firmware_image: Optional[Path] = None,
        baseline_path: Optional[Path] = None,
        untrusted_hashes_path: Optional[Path] = None,
    ) -> None:
        super().__init__()
        self.firmware_image = firmware_image
        self.baseline_path = baseline_path
        self.untrusted_hashes_path = untrusted_hashes_path

    def audit(self) -> None:
        if self.firmware_image is None:
            self.add_finding(
                "No firmware image supplied",
                Severity.INFO,
                "Run with --firmware-image <path to flashrom/vendor dump> "
                "to enable firmware integrity checks. This module cannot "
                "dump SPI flash itself -- use `flashrom -p <programmer> -r "
                "image.bin` (requires root) to produce one.",
            )
            return

        if not self.firmware_image.is_file():
            self.add_finding(
                "Firmware image not found",
                Severity.WARNING,
                f"{self.firmware_image} does not exist or is not a file.",
            )
            return

        extractor, tool_name = self._pick_extractor()
        if extractor is None:
            self.add_finding(
                "No extraction tool available",
                Severity.WARNING,
                "Neither UEFIExtract nor binwalk was found on PATH. Cannot "
                "decompose the firmware image into modules for hashing.",
                remediation="Install UEFITool (provides UEFIExtract) or binwalk.",
            )
            return

        with tempfile.TemporaryDirectory(prefix="countercraft_fw_") as tmp:
            out_dir = Path(tmp) / "extracted"
            ok = extractor(self.firmware_image, out_dir)
            if not ok:
                self.add_finding(
                    f"Extraction failed ({tool_name})",
                    Severity.WARNING,
                    f"{tool_name} did not produce output for {self.firmware_image}.",
                )
                return

            hashes = self._hash_tree(out_dir)
            self.add_finding(
                "Firmware image extracted and hashed",
                Severity.INFO,
                f"Extracted and hashed {len(hashes)} modules from "
                f"{self.firmware_image.name} using {tool_name}.",
            )
            self._check_untrusted(hashes)
            self._check_baseline(hashes)

    # -- extraction --------------------------------------------------------

    def _pick_extractor(self):
        uefiextract = which("UEFIExtract")
        if uefiextract:
            return (lambda img, out: self._run_uefiextract(uefiextract, img, out)), "UEFIExtract"
        binwalk = which("binwalk")
        if binwalk:
            return (lambda img, out: self._run_binwalk(binwalk, img, out)), "binwalk"
        return None, None

    @staticmethod
    def _run_uefiextract(binary: str, image: Path, out_dir: Path) -> bool:
        # UEFIExtract writes to "<image>.dump" next to the input by default;
        # run it inside a scratch cwd so we control the output location.
        out_dir.mkdir(parents=True, exist_ok=True)
        result = run_command([binary, str(image), "all"], timeout=180.0, shell=False)
        dump_dir = image.parent / f"{image.name}.dump"
        if dump_dir.is_dir():
            shutil.move(str(dump_dir), str(out_dir))
            return True
        return result.ok

    @staticmethod
    def _run_binwalk(binary: str, image: Path, out_dir: Path) -> bool:
        out_dir.mkdir(parents=True, exist_ok=True)
        result = run_command(
            [binary, "--extract", "--directory", str(out_dir), str(image)],
            timeout=180.0,
        )
        return result.ok and any(out_dir.iterdir())

    # -- hashing / comparison ----------------------------------------------

    @staticmethod
    def _hash_tree(root: Path) -> dict[str, str]:
        hashes: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
            hashes[str(path.relative_to(root))] = digest
        return hashes

    def _check_untrusted(self, hashes: dict[str, str]) -> None:
        if not self.untrusted_hashes_path or not self.untrusted_hashes_path.is_file():
            return
        try:
            untrusted: set[str] = set(json.loads(self.untrusted_hashes_path.read_text()))
        except (json.JSONDecodeError, OSError) as exc:
            self.add_finding(
                "Could not load untrusted-hash list",
                Severity.WARNING,
                f"Failed to parse {self.untrusted_hashes_path}: {exc}",
            )
            return

        for rel_path, digest in hashes.items():
            if digest in untrusted:
                self.add_finding(
                    "Module matches known-untrusted hash",
                    Severity.CRITICAL,
                    f"Extracted module '{rel_path}' (sha256={digest}) matches "
                    "an entry in the untrusted-hash denylist.",
                    remediation="Treat this firmware image as compromised; "
                    "do not flash it. Re-obtain firmware from the vendor.",
                    path=rel_path,
                    sha256=digest,
                )

    def _check_baseline(self, hashes: dict[str, str]) -> None:
        if not self.baseline_path:
            self.add_finding(
                "No baseline configured",
                Severity.INFO,
                "Run with --firmware-baseline <path> to enable drift "
                "detection against a known-good snapshot. Use "
                "--save-firmware-baseline to create one from this image.",
            )
            return
        if not self.baseline_path.is_file():
            self.add_finding(
                "Baseline file not found",
                Severity.WARNING,
                f"{self.baseline_path} does not exist yet.",
            )
            return

        try:
            baseline: dict[str, str] = json.loads(self.baseline_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            self.add_finding(
                "Could not load firmware baseline",
                Severity.WARNING,
                f"Failed to parse {self.baseline_path}: {exc}",
            )
            return

        added = hashes.keys() - baseline.keys()
        removed = baseline.keys() - hashes.keys()
        changed = {
            p for p in hashes.keys() & baseline.keys() if hashes[p] != baseline[p]
        }

        if not (added or removed or changed):
            self.add_finding(
                "Firmware matches baseline",
                Severity.INFO,
                f"All {len(hashes)} modules match the recorded baseline exactly.",
            )
            return

        for rel_path in sorted(changed):
            self.add_finding(
                "Firmware module hash changed",
                Severity.CRITICAL,
                f"Module '{rel_path}' hash differs from baseline "
                f"({baseline[rel_path]} -> {hashes[rel_path]}).",
                remediation="Confirm this change corresponds to an "
                "intentional, vendor-signed firmware update before trusting it.",
                path=rel_path,
                baseline_sha256=baseline[rel_path],
                current_sha256=hashes[rel_path],
            )
        for rel_path in sorted(added):
            self.add_finding(
                "New firmware module not in baseline",
                Severity.WARNING,
                f"Module '{rel_path}' was not present in the baseline snapshot.",
                path=rel_path,
                sha256=hashes[rel_path],
            )
        for rel_path in sorted(removed):
            self.add_finding(
                "Baseline module missing from current image",
                Severity.WARNING,
                f"Module '{rel_path}' was present in the baseline but is "
                "absent from this image.",
                path=rel_path,
                baseline_sha256=baseline[rel_path],
            )

    @staticmethod
    def save_baseline(firmware_image: Path, out_path: Path) -> int:
        """
        Utility used by `countercraft audit --save-firmware-baseline` --
        extracts and hashes an image, writing the result as the new trusted baseline.
        Not part of `audit()` since it's a write action, not a check.
        """
        checker = FirmwareIntegrityChecker(firmware_image=firmware_image)
        extractor, _ = checker._pick_extractor()
        if extractor is None:
            raise RuntimeError("No extraction tool (UEFIExtract/binwalk) available on PATH")
        with tempfile.TemporaryDirectory(prefix="countercraft_fw_baseline_") as tmp:
            out_dir = Path(tmp) / "extracted"
            if not extractor(firmware_image, out_dir):
                raise RuntimeError(f"Extraction failed for {firmware_image}")
            hashes = checker._hash_tree(out_dir)
        out_path.write_text(json.dumps(hashes, indent=2, sort_keys=True))
        return len(hashes)
