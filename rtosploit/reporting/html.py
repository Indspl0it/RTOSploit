"""HTML engagement report generator for RTOSploit."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from rtosploit.reporting.models import EngagementReport

TEMPLATE_DIR = Path(__file__).parent / "templates"


class HTMLGenerator:
    """Generate self-contained HTML reports from an EngagementReport."""

    def __init__(self) -> None:
        self._env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,
        )

    def generate(self, report: EngagementReport) -> str:
        """Produce a self-contained HTML string from an EngagementReport."""
        template = self._env.get_template("report.html.j2")

        # Pre-compute summary stats for the template
        severity_counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        category_counts: dict[str, int] = {}
        for f in report.findings:
            sev = f.severity.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            cat = f.category
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return template.render(
            report=report,
            severity_counts=severity_counts,
            category_counts=category_counts,
            total_findings=len(report.findings),
        )

    def write(self, report: EngagementReport, path: str) -> None:
        """Write HTML report to a file."""
        with open(path, "w") as fh:
            fh.write(self.generate(report))
