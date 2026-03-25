"""Vulnerability scanner module framework."""

from rtosploit.scanners.base import ScannerModule, ScanOption, ScanResult
from rtosploit.scanners.registry import ScannerRegistry, get_registry
from rtosploit.scanners.runtime_bridge import ScanInjector, InjectionResult
from rtosploit.scanners.target import ScanTarget

__all__ = [
    "ScannerModule", "ScanOption", "ScanResult",
    "ScannerRegistry", "get_registry",
    "ScanInjector", "InjectionResult",
    "ScanTarget",
]
