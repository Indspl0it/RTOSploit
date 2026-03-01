"""rtosploit triage — classify crash exploitability and minimize inputs."""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from rtosploit.triage.classifier import Exploitability
from rtosploit.triage.pipeline import TriagePipeline, TriagedCrash

console = Console()

_EXPLOIT_STYLE = {
    Exploitability.EXPLOITABLE: "[bold red]EXPLOITABLE[/bold red]",
    Exploitability.PROBABLY_EXPLOITABLE: "[yellow]PROBABLY EXPLOITABLE[/yellow]",
    Exploitability.PROBABLY_NOT: "[green]PROBABLY NOT[/green]",
    Exploitability.UNKNOWN: "[dim]UNKNOWN[/dim]",
}


def _render_text(results: list[TriagedCrash]) -> None:
    """Print a Rich table summarising triage results."""
    table = Table(title="Crash Triage Results", show_lines=True)
    table.add_column("Crash ID", style="cyan", no_wrap=True)
    table.add_column("Exploitability")
    table.add_column("Crash Type", style="magenta")
    table.add_column("PC", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Reasons")

    for tc in results:
        tr = tc.triage_result
        exploit_str = _EXPLOIT_STYLE.get(
            tr.exploitability, str(tr.exploitability.value)
        )

        pc_val = tc.crash_data.get("pc", tc.crash_data.get("registers", {}).get("pc", 0))
        pc_str = f"0x{pc_val:08x}" if pc_val else "N/A"

        if tc.minimized_size is not None:
            size_str = f"{tc.original_size} -> {tc.minimized_size}"
        else:
            size_str = str(tc.original_size)

        reasons_str = "; ".join(tr.reasons) if tr.reasons else "-"

        table.add_row(
            tc.crash_id,
            exploit_str,
            tr.fault_type,
            pc_str,
            size_str,
            reasons_str,
        )

    console.print(table)

    # Summary counts
    counts: dict[str, int] = {}
    for tc in results:
        key = tc.triage_result.exploitability.value
        counts[key] = counts.get(key, 0) + 1

    console.print(f"\n[bold]Total crashes:[/bold] {len(results)}")
    for label, count in sorted(counts.items()):
        console.print(f"  {label}: {count}")


def _render_json(results: list[TriagedCrash]) -> str:
    """Serialise triage results to JSON."""
    out = []
    for tc in results:
        d = {
            "crash_id": tc.crash_id,
            "original_input": tc.original_input,
            "minimized_input": tc.minimized_input,
            "original_size": tc.original_size,
            "minimized_size": tc.minimized_size,
            "triage_result": {
                "exploitability": tc.triage_result.exploitability.value,
                "reasons": tc.triage_result.reasons,
                "cfsr_flags": tc.triage_result.cfsr_flags,
                "fault_type": tc.triage_result.fault_type,
                "write_target": tc.triage_result.write_target,
                "pc_control": tc.triage_result.pc_control,
                "sp_control": tc.triage_result.sp_control,
            },
            "crash_data": tc.crash_data,
        }
        out.append(d)
    return json.dumps(out, indent=2)


def _render_sarif(results: list[TriagedCrash], firmware: str) -> str:
    """Generate SARIF output from triage results."""
    from rtosploit.reporting.models import EngagementReport, finding_from_triaged_crash
    from rtosploit.reporting.sarif import SARIFGenerator

    findings = [finding_from_triaged_crash(tc) for tc in results]
    report = EngagementReport(
        engagement_id=f"rtosploit-triage-{int(time.time())}",
        timestamp=int(time.time()),
        target_firmware=firmware,
        findings=findings,
    )
    return SARIFGenerator().generate_json(report)


@click.command("triage")
@click.option(
    "--crash-dir", "-c",
    required=True,
    type=click.Path(exists=True),
    help="Directory containing crash JSON files",
)
@click.option(
    "--firmware", "-f",
    required=True,
    type=click.Path(exists=True),
    help="Path to target firmware binary",
)
@click.option(
    "--machine", "-m",
    default="mps2-an385",
    show_default=True,
    help="QEMU machine type",
)
@click.option(
    "--minimize/--no-minimize",
    default=True,
    show_default=True,
    help="Minimize crash inputs",
)
@click.option(
    "--format", "fmt",
    type=click.Choice(["text", "json", "sarif"]),
    default="text",
    show_default=True,
    help="Output format",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout",
)
@click.pass_context
def triage(ctx, crash_dir, firmware, machine, minimize, fmt, output):
    """Triage crash inputs: classify exploitability and minimize.

    \b
    Example:
      rtosploit triage -c ./fuzz-output/crashes -f ./firmware.elf
      rtosploit triage -c ./crashes -f ./fw.bin --format json -o results.json
      rtosploit triage -c ./crashes -f ./fw.bin --no-minimize --format sarif
    """
    pipeline = TriagePipeline(
        firmware_path=firmware,
        machine=machine,
        minimize=minimize,
    )

    output_json = ctx.obj.get("output_json", False)

    results = pipeline.run(crash_dir)

    # Determine effective format: --json flag overrides --format
    effective_fmt = "json" if output_json else fmt

    if not results:
        if effective_fmt == "json":
            click.echo(json.dumps({"crashes": [], "count": 0}))
            return
        if effective_fmt == "sarif":
            content = _render_sarif([], firmware)
            if output:
                os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
                with open(output, "w") as fh:
                    fh.write(content)
                console.print(f"[green]Written to {output}[/green]")
            else:
                click.echo(content)
            return
        console.print("[yellow]No crashes found to triage.[/yellow]")
        return

    if effective_fmt == "text":
        _render_text(results)
        # Text mode ignores --output (always prints to console)
        return

    if effective_fmt == "json":
        content = _render_json(results)
    elif effective_fmt == "sarif":
        content = _render_sarif(results, firmware)
    else:
        content = ""

    if output:
        os.makedirs(os.path.dirname(output) or ".", exist_ok=True)
        with open(output, "w") as fh:
            fh.write(content)
        console.print(f"[green]Written to {output}[/green]")
    else:
        click.echo(content)
