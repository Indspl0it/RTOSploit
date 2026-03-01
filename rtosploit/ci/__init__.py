"""CI/CD pipeline mode for RTOSploit — orchestrates scan, triage, and reporting."""

from rtosploit.ci.pipeline import CIConfig, CIPipeline

__all__ = [
    "CIConfig",
    "CIPipeline",
]
