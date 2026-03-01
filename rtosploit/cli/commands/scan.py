"""rtosploit scan — full security scan pipeline (CI/CD mode)."""

from __future__ import annotations

import click
from rich.console import Console

from rtosploit.ci.pipeline import CIConfig, CIPipeline

console = Console()


@click.command()
@click.option(
    "--firmware", "-f",
    required=True,
    type=click.Path(exists=True),
    help="Path to firmware binary (ELF, HEX, SREC, or raw).",
)
@click.option(
    "--machine", "-m",
    default="mps2-an385",
    show_default=True,
    help="QEMU machine type.",
)
@click.option(
    "--fuzz-timeout",
    type=int,
    default=60,
    show_default=True,
    help="Fuzzing timeout in seconds.",
)
@click.option(
    "--format", "fmt",
    type=click.Choice(["sarif", "html", "both"]),
    default="both",
    show_default=True,
    help="Output report format.",
)
@click.option(
    "--output", "-o",
    default="scan-output",
    show_default=True,
    type=click.Path(),
    help="Output directory for reports.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low", "any"]),
    default="critical",
    show_default=True,
    help="Severity threshold that causes non-zero exit.",
)
@click.option("--skip-fuzz", is_flag=True, default=False, help="Skip the fuzzing step.")
@click.option("--skip-cve", is_flag=True, default=False, help="Skip CVE correlation.")
@click.option("--no-minimize", is_flag=True, default=False, help="Skip crash input minimization.")
@click.option(
    "--architecture",
    default="armv7m",
    show_default=True,
    help="Target architecture (armv7m, armv8m, riscv32).",
)
@click.pass_context
def scan(
    ctx: click.Context,
    firmware: str,
    machine: str,
    fuzz_timeout: int,
    fmt: str,
    output: str,
    fail_on: str,
    skip_fuzz: bool,
    skip_cve: bool,
    no_minimize: bool,
    architecture: str,
) -> None:
    """Run full security scan pipeline (CI/CD mode).

    \b
    Orchestrates: firmware load -> fingerprint -> CVE correlation ->
    fuzz -> triage -> report generation.

    \b
    Example:
      rtosploit scan -f firmware.elf -o ./results --fail-on high
      rtosploit scan -f firmware.bin --skip-fuzz --skip-cve --format sarif
    """
    # Map --format both -> ["sarif", "html"]
    if fmt == "both":
        formats = ["sarif", "html"]
    else:
        formats = [fmt]

    config = CIConfig(
        firmware_path=firmware,
        machine=machine,
        fuzz_timeout=fuzz_timeout,
        output_dir=output,
        formats=formats,
        fail_on=fail_on,
        skip_fuzz=skip_fuzz,
        skip_cve=skip_cve,
        minimize=not no_minimize,
        architecture=architecture,
    )

    pipeline = CIPipeline(config)
    exit_code = pipeline.run()

    # Print summary
    output_json = ctx.obj.get("output_json", False) if ctx.obj else False

    severity_counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
    }
    for f in pipeline.findings:
        sev = f.severity.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    if output_json:
        import json
        click.echo(json.dumps({
            "findings": len(pipeline.findings),
            "severity_counts": severity_counts,
            "output_dir": output,
            "output_files": pipeline.metadata.get("output_files", []),
            "elapsed_seconds": pipeline.metadata.get("elapsed_seconds"),
            "exit_code": exit_code,
        }, indent=2))
    else:
        total = len(pipeline.findings)
        elapsed = pipeline.metadata.get("elapsed_seconds", "?")
        console.print(f"\n[bold]Scan complete[/bold] ({elapsed}s)")
        console.print(f"  Total findings: [cyan]{total}[/cyan]")
        for sev, count in severity_counts.items():
            if count > 0:
                color = {"critical": "red", "high": "red", "medium": "yellow", "low": "blue", "info": "dim"}.get(sev, "white")
                console.print(f"    {sev:>10}: [{color}]{count}[/{color}]")
        output_files = pipeline.metadata.get("output_files", [])
        for fp in output_files:
            console.print(f"  Output: [cyan]{fp}[/cyan]")
        if exit_code == 0:
            console.print(f"  [bold green]PASS[/bold green] (fail-on={fail_on})")
        else:
            console.print(f"  [bold red]FAIL[/bold red] (fail-on={fail_on})")

    ctx.exit(exit_code)
