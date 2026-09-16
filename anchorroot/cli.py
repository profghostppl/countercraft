"""
Command-line interface for Anchorroot.

Installed as the `anchorroot` console script (see pyproject.toml's
[project.scripts]), pointing at `main()` here. `python -m anchorroot`
works identically.

Two subcommands:
  anchorroot audit [flags]           run auditors, optionally --diff a baseline
  anchorroot baseline save [path]    snapshot current state for later comparison

`audit` is the default: `anchorroot`, `anchorroot --all`,
`anchorroot --audit-uefi` all work without typing the subcommand name, by
inserting it automatically when the first argument isn't a known
subcommand. Within `audit`, module selection stays one boolean flag per
auditor (`--audit-uefi`, `--audit-tpm`, ...) plus `--all` (also the default
when no selection flag is given). Per-artifact baseline snapshot creation
(`--save-firmware-baseline`, `--save-tpm-baseline`) remains a one-shot
action that exits before the normal audit runs; the combined-state
baseline (`baseline save` / `audit --diff`) is a separate, broader
mechanism -- see `anchorroot.core.diff`.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from anchorroot.config import DEFAULT_REPORT_PATH
from anchorroot.core.diff import DEFAULT_BASELINE_PATH, SnapshotError, diff_snapshots, load_snapshot, save_snapshot
from anchorroot.core.models import AuditReport, ModuleResult, Severity
from anchorroot.core.reporter import print_summary, write_json_report
from anchorroot.core.utils import is_elevated, is_mock_mode, set_mock_mode
from anchorroot.modules import (
    CaAuditor,
    DmaAuditor,
    FirmwareIntegrityChecker,
    MeAuditor,
    NetworkAuditor,
    PersistenceAuditor,
    TpmAuditor,
    UefiPlatformAuditor,
)
from anchorroot.utils.logger import logger

_SEVERITY_ORDER = {"none": None, "info": Severity.INFO, "warning": Severity.WARNING, "critical": Severity.CRITICAL}
_SUBCOMMANDS = ("audit", "baseline")


def _add_mock_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mock",
        "--dry-run",
        dest="mock",
        action="store_true",
        help="Run entirely against synthetic data (anchorroot.mocks) -- no root, no "
        "TPM/CHIPSEC/ME hardware, none of the external tools actually installed "
        "required. Useful for demos, CI smoke tests, and developing without matching hardware.",
    )


def _build_audit_parser(parser: argparse.ArgumentParser) -> None:
    selection = parser.add_argument_group("module selection")
    selection.add_argument("--audit-uefi", action="store_true", help="Platform/UEFI/Secure Boot checks.")
    selection.add_argument("--audit-firmware", action="store_true", help="Firmware image hash/integrity checks.")
    selection.add_argument("--audit-network", action="store_true", help="Passive network telemetry capture.")
    selection.add_argument("--audit-persistence", action="store_true", help="Startup/kernel-module/task persistence audit.")
    selection.add_argument("--audit-tpm", action="store_true", help="TPM 2.0 PCR integrity check.")
    selection.add_argument("--audit-dma", action="store_true", help="IOMMU / Kernel DMA protection check.")
    selection.add_argument("--audit-me", action="store_true", help="Intel ME / AMD PSP / AMT out-of-band check.")
    selection.add_argument("--audit-ca", action="store_true", help="Root CA store and UEFI dbx check.")
    selection.add_argument("--all", action="store_true", help="Run every module (default if none of the above are given).")

    fw = parser.add_argument_group("firmware_integrity options")
    fw.add_argument("--firmware-image", type=Path, help="Path to a dumped SPI BIOS/UEFI image.")
    fw.add_argument("--firmware-baseline", type=Path, help="Baseline JSON to diff extracted module hashes against.")
    fw.add_argument("--save-firmware-baseline", type=Path, metavar="OUT_PATH",
                     help="Extract+hash --firmware-image and save as a new baseline, then exit.")

    net = parser.add_argument_group("network options")
    net.add_argument("--network-duration", type=float, default=30.0, help="Capture window in seconds (default: 30).")
    net.add_argument("--network-interface", help="Interface to sniff on (scapy backend only).")
    net.add_argument("--network-whitelist", type=Path, help="Path to a whitelist YAML (default: bundled sample).")

    tpm = parser.add_argument_group("tpm options")
    tpm.add_argument("--tpm-baseline", type=Path, help="Baseline JSON of PCR values to diff against.")
    tpm.add_argument("--save-tpm-baseline", type=Path, metavar="OUT_PATH",
                      help="Read current PCRs and save as a new baseline, then exit.")

    ca = parser.add_argument_group("ca options")
    ca.add_argument("--mozilla-ca-list", type=Path,
                     help="JSON array of lowercase SHA-256 CA fingerprints to cross-reference the CA store against.")
    ca.add_argument("--expected-dbx-hashes", type=Path,
                     help="JSON array of lowercase SHA-256 hashes expected to be present in dbx.")

    diff = parser.add_argument_group("state baseline & diff")
    diff.add_argument(
        "--diff",
        type=Path,
        nargs="?",
        const=DEFAULT_BASELINE_PATH,
        default=None,
        metavar="PATH",
        help=f"Compare this run's TPM PCRs / root CAs / kernel modules / EFI boot "
        f"variables against a saved baseline snapshot (default path if omitted: "
        f"{DEFAULT_BASELINE_PATH}). Create one first with 'anchorroot baseline save'.",
    )

    out = parser.add_argument_group("output")
    out.add_argument("--output", type=Path, default=DEFAULT_REPORT_PATH, help="JSON report output path.")
    out.add_argument("--no-table", action="store_true", help="Suppress the CLI summary table (JSON only).")
    out.add_argument(
        "--fail-on",
        choices=list(_SEVERITY_ORDER),
        default="none",
        help="Exit non-zero if any finding at or above this severity exists. 'none' always exits 0.",
    )
    _add_mock_flag(parser)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        # prog intentionally left unset: argparse falls back to
        # sys.argv[0]'s basename, so usage text reads "anchorroot ..."
        # (or "__main__.py ..." if invoked via `python -m anchorroot`).
        description="Anchorroot -- host-level defensive security audit.",
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    audit_parser = subparsers.add_parser("audit", help="Run audit modules and produce a report.")
    _build_audit_parser(audit_parser)

    baseline_parser = subparsers.add_parser("baseline", help="Save a state snapshot for later --diff comparison.")
    baseline_subparsers = baseline_parser.add_subparsers(dest="baseline_action")
    save_parser = baseline_subparsers.add_parser("save", help="Collect and save a baseline snapshot.")
    save_parser.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=DEFAULT_BASELINE_PATH,
        help=f"Where to save the snapshot (default: {DEFAULT_BASELINE_PATH}).",
    )
    _add_mock_flag(save_parser)

    return parser


def _normalize_argv(argv: list[str]) -> list[str]:
    """Insert the implicit 'audit' subcommand so old flag-only invocations keep working."""
    if not argv:
        return ["audit"]
    if argv[0] in _SUBCOMMANDS or argv[0] in ("-h", "--help"):
        return list(argv)
    return ["audit", *argv]


def _selected_modules(args: argparse.Namespace) -> list:
    any_selected = any(
        [
            args.audit_uefi,
            args.audit_firmware,
            args.audit_network,
            args.audit_persistence,
            args.audit_tpm,
            args.audit_dma,
            args.audit_me,
            args.audit_ca,
        ]
    )
    run_all = args.all or not any_selected

    modules = []
    if run_all or args.audit_uefi:
        modules.append(UefiPlatformAuditor())
    if run_all or args.audit_firmware:
        modules.append(
            FirmwareIntegrityChecker(
                firmware_image=args.firmware_image,
                baseline_path=args.firmware_baseline,
            )
        )
    if run_all or args.audit_network:
        modules.append(
            NetworkAuditor(
                duration_seconds=args.network_duration,
                interface=args.network_interface,
                whitelist_path=args.network_whitelist,
            )
        )
    if run_all or args.audit_persistence:
        modules.append(PersistenceAuditor())
    if run_all or args.audit_tpm:
        modules.append(TpmAuditor(baseline_path=args.tpm_baseline))
    if run_all or args.audit_dma:
        modules.append(DmaAuditor())
    if run_all or args.audit_me:
        modules.append(MeAuditor())
    if run_all or args.audit_ca:
        modules.append(
            CaAuditor(
                mozilla_ca_fingerprints_path=args.mozilla_ca_list,
                expected_dbx_hashes_path=args.expected_dbx_hashes,
            )
        )
    return modules


def _handle_per_artifact_baseline_actions(args: argparse.Namespace) -> bool:
    """Returns True if a one-shot per-artifact baseline action ran (caller should exit)."""
    if args.save_firmware_baseline:
        if not args.firmware_image:
            logger.error("--save-firmware-baseline requires --firmware-image")
            sys.exit(2)
        try:
            count = FirmwareIntegrityChecker.save_baseline(args.firmware_image, args.save_firmware_baseline)
        except RuntimeError as exc:
            logger.error("%s", exc)
            sys.exit(1)
        print(f"Saved {count} module hashes to {args.save_firmware_baseline}")
        return True

    if args.save_tpm_baseline:
        try:
            pcrs = TpmAuditor.read_current_pcrs()
        except RuntimeError as exc:
            logger.error("%s", exc)
            sys.exit(1)
        TpmAuditor.save_baseline(pcrs, args.save_tpm_baseline)
        print(f"Saved {len(pcrs)} PCR values to {args.save_tpm_baseline}")
        return True

    return False


def _cmd_audit(args: argparse.Namespace) -> int:
    if getattr(args, "mock", False):
        set_mock_mode(True)

    if _handle_per_artifact_baseline_actions(args):
        return 0

    # Fail fast on a bad --diff path before spending time running modules.
    baseline_snapshot = None
    if args.diff is not None:
        try:
            baseline_snapshot = load_snapshot(args.diff)
        except SnapshotError as exc:
            logger.error("%s", exc)
            return 2

    if is_mock_mode():
        logger.info("running in --mock mode -- all findings below are synthetic demo data.")
    elif not is_elevated():
        logger.warning(
            "not running elevated (root/Administrator) -- some checks "
            "(SPI/SMM register state, raw packet capture, full driver "
            "enumeration) will be skipped or degraded. See each module's findings for specifics."
        )

    modules = _selected_modules(args)
    report = AuditReport()
    for module in modules:
        logger.info("running: %s ...", module.name)
        report.results.append(module.run())

    if baseline_snapshot is not None:
        logger.info("running: baseline_diff ...")
        from anchorroot.core.diff import collect_snapshot

        current_snapshot = collect_snapshot()
        diff_findings = diff_snapshots(baseline_snapshot, current_snapshot)
        report.results.append(ModuleResult(module="baseline_diff", findings=diff_findings))

    write_json_report(report, args.output)
    if not args.no_table:
        print_summary(report)
    logger.info("JSON report written to %s", args.output)

    threshold = _SEVERITY_ORDER[args.fail_on]
    if threshold is not None and any(f.severity >= threshold for f in report.all_findings):
        return 1
    return 0


def _cmd_baseline(args: argparse.Namespace) -> int:
    if args.baseline_action != "save":
        logger.error("usage: anchorroot baseline save [path]")
        return 2

    if getattr(args, "mock", False):
        set_mock_mode(True)
        logger.info("running in --mock mode -- this baseline contains synthetic demo data.")

    snapshot = save_snapshot(args.path)
    print(f"Saved baseline snapshot to {args.path}")
    print(
        f"  TPM PCRs: {len(snapshot.tpm_pcrs)}   Root CAs: {len(snapshot.root_cas)}   "
        f"Kernel modules: {len(snapshot.kernel_modules)}   EFI boot variables: {len(snapshot.efi_boot_variables)}"
    )
    for category, count in (
        ("TPM PCRs", len(snapshot.tpm_pcrs)),
        ("root CAs", len(snapshot.root_cas)),
        ("kernel modules", len(snapshot.kernel_modules)),
        ("EFI boot variables", len(snapshot.efi_boot_variables)),
    ):
        if count == 0:
            logger.warning("%s snapshot is empty -- that category won't be diffable later.", category)
    return 0


def main(argv: list[str] | None = None) -> int:
    raw_argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    args = parser.parse_args(_normalize_argv(raw_argv))

    if args.subcommand == "baseline":
        return _cmd_baseline(args)
    return _cmd_audit(args)


if __name__ == "__main__":
    sys.exit(main())
