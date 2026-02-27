"""VulnRange manifest parsing and range discovery."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class RangeTarget:
    rtos: str
    rtos_version: str
    arch: str
    machine: str  # QEMU machine name
    firmware: str  # relative path to .bin file


@dataclass
class RangeVulnerability:
    type: str         # "heap_corruption", "mpu_bypass", "network_overflow", etc.
    component: str    # which component/module
    root_cause: str   # brief root cause description
    affected_function: str
    trigger: str      # how to trigger


@dataclass
class RangeExploit:
    technique: str
    reliability: str
    payload: Optional[str]
    script: str       # path to exploit.py


@dataclass
class RangeManifest:
    id: str
    title: str
    cve: Optional[str]
    cvss: Optional[float]
    category: str
    difficulty: str   # "beginner", "intermediate", "advanced"
    target: RangeTarget
    vulnerability: RangeVulnerability
    exploit: RangeExploit
    prerequisites: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    description: str = ""
    hints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "cve": self.cve,
            "cvss": self.cvss,
            "category": self.category,
            "difficulty": self.difficulty,
            "description": self.description,
            "tags": self.tags,
        }


def load_manifest(range_dir: str | Path) -> RangeManifest:
    """Parse manifest.yaml from a range directory."""
    path = Path(range_dir) / "manifest.yaml"
    if not path.exists():
        raise FileNotFoundError(f"manifest.yaml not found in {range_dir}")

    with open(path) as f:
        data = yaml.safe_load(f)

    target_data = data.get("target", {})
    target = RangeTarget(
        rtos=target_data.get("rtos", "freertos"),
        rtos_version=target_data.get("rtos_version", "unknown"),
        arch=target_data.get("arch", "armv7m"),
        machine=target_data.get("machine", "mps2-an385"),
        firmware=target_data.get("firmware", "firmware.bin"),
    )

    vuln_data = data.get("vulnerability", {})
    vuln = RangeVulnerability(
        type=vuln_data.get("type", "unknown"),
        component=vuln_data.get("component", ""),
        root_cause=vuln_data.get("root_cause", ""),
        affected_function=vuln_data.get("affected_function", ""),
        trigger=vuln_data.get("trigger", ""),
    )

    exploit_data = data.get("exploit", {})
    exploit = RangeExploit(
        technique=exploit_data.get("technique", ""),
        reliability=exploit_data.get("reliability", "medium"),
        payload=exploit_data.get("payload"),
        script=exploit_data.get("script", "exploit.py"),
    )

    return RangeManifest(
        id=data.get("id", "unknown"),
        title=data.get("title", ""),
        cve=data.get("cve"),
        cvss=data.get("cvss"),
        category=data.get("category", ""),
        difficulty=data.get("difficulty", "intermediate"),
        target=target,
        vulnerability=vuln,
        exploit=exploit,
        prerequisites=data.get("prerequisites", []),
        tags=data.get("tags", []),
        description=data.get("description", ""),
        hints=data.get("hints", []),
    )


def list_ranges(vulnrange_dir: str | Path = "vulnrange") -> list[RangeManifest]:
    """Scan vulnrange/ directory for all available ranges."""
    base = Path(vulnrange_dir)
    ranges = []
    if not base.exists():
        return ranges
    for subdir in sorted(base.iterdir()):
        if subdir.is_dir() and (subdir / "manifest.yaml").exists():
            try:
                ranges.append(load_manifest(subdir))
            except Exception:
                pass
    return ranges
