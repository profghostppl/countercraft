"""
Reporting & Scoring Engine.

Takes the list of ModuleResult objects produced by the audit run and turns
them into:
  1. A structured JSON report on disk (machine-readable, diffable, CI-friendly).
  2. A CLI summary table (rich if available, plain text fallback otherwise).
"""

from __future__ import annotations

import json
from pathlib import Path

from countercraft.core.models import AuditReport, Severity

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    _HAS_RICH = True
except ImportError:  # rich is a soft dependency -- degrade to plain text
    _HAS_RICH = False


_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.WARNING: "bold black on yellow",
    Severity.INFO: "cyan",
}


def write_json_report(report: AuditReport, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
    return path


def print_summary(report: AuditReport) -> None:
    """Render the human-facing CLI summary. Auto-selects rich vs plain text."""
    if _HAS_RICH:
        _print_summary_rich(report)
    else:
        _print_summary_plain(report)


def _print_summary_rich(report: AuditReport) -> None:
    console = Console()
    counts = report.counts()

    header = (
        f"Host: {report.hostname}    OS: {report.os_info}\n"
        f"Generated: {report.generated_at}\n"
        f"Risk Score: {report.risk_score()}    "
        f"[bold red]CRITICAL: {counts['CRITICAL']}[/bold red]  "
        f"[yellow]WARNING: {counts['WARNING']}[/yellow]  "
        f"[cyan]INFO: {counts['INFO']}[/cyan]"
    )
    console.print(Panel(header, title="CounterCraft - Audit Summary", expand=False))

    for result in report.results:
        if result.skipped:
            console.print(f"  [dim]- {result.module}: skipped ({result.skip_reason})[/dim]")
            continue
        if result.error:
            console.print(f"  [red]- {result.module}: ERROR ({result.error})[/red]")
            continue
        if not result.findings:
            console.print(f"  [green]- {result.module}: clean[/green]")
            continue

        table = Table(
            title=result.module,
            box=box.SIMPLE_HEAVY,
            show_lines=False,
            title_justify="left",
        )
        table.add_column("Severity", width=12)
        table.add_column("Finding")
        table.add_column("Detail", overflow="fold")

        for finding in sorted(result.findings, key=lambda f: -f.severity):
            style = _SEVERITY_STYLE[finding.severity]
            table.add_row(
                f"[{style}]{finding.severity.label}[/{style}]",
                finding.title,
                finding.description,
            )
        console.print(table)


def _print_summary_plain(report: AuditReport) -> None:
    counts = report.counts()
    print("=" * 78)
    print("CounterCraft - Audit Summary")
    print(f"Host: {report.hostname}    OS: {report.os_info}")
    print(f"Generated: {report.generated_at}")
    print(
        f"Risk Score: {report.risk_score()}   "
        f"CRITICAL={counts['CRITICAL']} WARNING={counts['WARNING']} INFO={counts['INFO']}"
    )
    print("=" * 78)

    for result in report.results:
        print(f"\n## {result.module}")
        if result.skipped:
            print(f"   skipped ({result.skip_reason})")
            continue
        if result.error:
            print(f"   ERROR: {result.error}")
            continue
        if not result.findings:
            print("   clean")
            continue
        for finding in sorted(result.findings, key=lambda f: -f.severity):
            print(f"   {finding.severity.label:<10} {finding.title}")
            print(f"              {finding.description}")
            if finding.remediation:
                print(f"              remediation: {finding.remediation}")
    print()
