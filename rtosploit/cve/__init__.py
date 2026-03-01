"""CVE correlation package for RTOSploit."""

from rtosploit.cve.database import CVEEntry, CVEDatabase
from rtosploit.cve.nvd_client import NVDClient
from rtosploit.cve.correlator import CorrelationResult, CVECorrelator

__all__ = [
    "CVEEntry",
    "CVEDatabase",
    "NVDClient",
    "CorrelationResult",
    "CVECorrelator",
]
