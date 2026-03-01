"""Reporting handler for interactive mode."""

from __future__ import annotations

import logging
from pathlib import Path

import questionary
from rich.console import Console

from rtosploit.interactive.session import InteractiveSession

logger = logging.getLogger(__name__)


def handle_reports(session: InteractiveSession, console: Console) -> None:
    """Generate SARIF/HTML reports."""
    fmt = questionary.checkbox(
        "Report format(s):",
        choices=[
            questionary.Choice("SARIF", value="sarif", checked=True),
            questionary.Choice("HTML", value="html", checked=True),
        ],
    ).ask()

    if not fmt:
        return

    output_dir = questionary.path(
        "Output directory:",
        default=str(session.output_dir),
        only_directories=True,
    ).ask()

    if not output_dir:
        return

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    console.print(f"[dim]Generating reports in {out}...[/dim]")

    # Gather findings from session
    findings = []
    if session.firmware and session.firmware.fingerprint:
        findings.append({"type": "fingerprint", "data": session.firmware.fingerprint})

    try:
        if "sarif" in fmt:
            from rtosploit.reporting.sarif import generate_sarif
            sarif_path = out / "report.sarif"
            generate_sarif(findings, str(sarif_path))
            console.print(f"[green]SARIF report: {sarif_path}[/green]")

        if "html" in fmt:
            from rtosploit.reporting.html import generate_html
            html_path = out / "report.html"
            generate_html(findings, str(html_path))
            console.print(f"[green]HTML report: {html_path}[/green]")

    except Exception as exc:
        console.print(f"[red]Report generation failed: {exc}[/red]")
