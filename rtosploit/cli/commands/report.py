"""rtosploit report — generate SARIF and HTML engagement reports."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import click
from rich.console import Console

from rtosploit.reporting.models import (
    EngagementReport,
    Finding,
    finding_from_exploit_result,
    finding_from_fuzz_report,
)
from rtosploit.reporting.sarif import SARIFGenerator
from rtosploit.reporting.html import HTMLGenerator

console = Console()


def _try_parse_finding(data: dict) -> Finding | None:
    """Attempt to parse a JSON dict as a FuzzReport or ScanResult finding."""
    # FuzzReport has crash_type; ScanResult has module + status + technique
    if "crash_type" in data:
        return finding_from_fuzz_report(data)
    if "module" in data and "technique" in data:
        return finding_from_exploit_result(data)
    return None


@click.command("report")
@click.option(
    "--input-dir", "-i",
    required=True,
    type=click.Path(exists=True),
    help="Directory containing crash/exploit JSON files",
)
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["sarif", "html", "both"]),
    default="both",
    show_default=True,
    help="Output format",
)
@click.option(
    "--output", "-o",
    required=True,
    type=click.Path(),
    help="Output directory",
)
@click.option(
    "--firmware",
    type=str,
    default="unknown",
    show_default=True,
    help="Target firmware name",
)
@click.option(
    "--architecture",
    type=str,
    default="armv7m",
    show_default=True,
    help="Target architecture",
)
@click.pass_context
def report(ctx, input_dir: str, fmt: str, output: str, firmware: str, architecture: str) -> None:
    """Generate SARIF and/or HTML engagement reports from crash/exploit data.

    \b
    Example:
      rtosploit report -i ./fuzz-output/crashes -o ./reports
      rtosploit report -i ./results -f sarif -o ./reports --firmware fw.bin
    """
    input_path = Path(input_dir)
    output_path = Path(output)

    # Scan for JSON files
    json_files = sorted(input_path.glob("*.json"))
    if not json_files:
        console.print(f"[yellow]No JSON files found in {input_dir}[/yellow]")

    # Parse findings
    findings: list[Finding] = []
    skipped = 0
    for jf in json_files:
        try:
            with open(jf) as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[dim]Skipping {jf.name}: {exc}[/dim]")
            skipped += 1
            continue

        finding = _try_parse_finding(data)
        if finding is not None:
            findings.append(finding)
        else:
            console.print(f"[dim]Skipping {jf.name}: unrecognised format[/dim]")
            skipped += 1

    # Build report
    engagement_report = EngagementReport(
        engagement_id=f"rtosploit-{int(time.time())}",
        timestamp=int(time.time()),
        target_firmware=firmware,
        target_architecture=architecture,
        findings=findings,
    )

    # Create output directory
    os.makedirs(output_path, exist_ok=True)

    # Generate outputs
    files_written: list[str] = []

    if fmt in ("sarif", "both"):
        sarif_path = str(output_path / "report.sarif.json")
        SARIFGenerator().write(engagement_report, sarif_path)
        files_written.append(sarif_path)

    if fmt in ("html", "both"):
        html_path = str(output_path / "report.html")
        HTMLGenerator().write(engagement_report, html_path)
        files_written.append(html_path)

    # Output summary
    output_json = ctx.obj.get("output_json", False) if ctx.obj else False
    if output_json:
        click.echo(json.dumps({
            "findings": len(findings),
            "skipped": skipped,
            "files": files_written,
            "engagement_id": engagement_report.engagement_id,
        }, indent=2))
    else:
        console.print("\n[bold green]Report generated[/bold green]")
        console.print(f"  Findings:  [cyan]{len(findings)}[/cyan]")
        console.print(f"  Skipped:   [dim]{skipped}[/dim]")
        for fp in files_written:
            console.print(f"  Written:   [cyan]{fp}[/cyan]")
