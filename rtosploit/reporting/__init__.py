"""RTOSploit reporting — SARIF + HTML engagement report generation."""

from rtosploit.reporting.models import (
    Finding,
    EngagementReport,
    finding_from_fuzz_report,
    finding_from_exploit_result,
    finding_from_triaged_crash,
    finding_from_cve,
)
from rtosploit.reporting.sarif import SARIFGenerator
from rtosploit.reporting.html import HTMLGenerator

__all__ = [
    "Finding",
    "EngagementReport",
    "finding_from_fuzz_report",
    "finding_from_exploit_result",
    "finding_from_triaged_crash",
    "finding_from_cve",
    "SARIFGenerator",
    "HTMLGenerator",
]
