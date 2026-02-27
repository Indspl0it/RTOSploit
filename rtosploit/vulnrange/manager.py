"""VulnRange manager — orchestrates CVE lab ranges."""

from __future__ import annotations

import logging
from pathlib import Path

from rtosploit.vulnrange.manifest import RangeManifest, load_manifest, list_ranges

logger = logging.getLogger(__name__)


class VulnRangeManager:
    """Manages the VulnRange CVE reproduction lab."""

    def __init__(self, vulnrange_dir: str | Path = "vulnrange"):
        self.vulnrange_dir = Path(vulnrange_dir)

    def list(self) -> list[RangeManifest]:
        """Return all available ranges."""
        return list_ranges(self.vulnrange_dir)

    def get(self, range_id: str) -> RangeManifest:
        """Get a specific range by ID."""
        range_dir = self.vulnrange_dir / range_id
        if not range_dir.exists():
            # Try case-insensitive match
            if self.vulnrange_dir.exists():
                for d in self.vulnrange_dir.iterdir():
                    if d.name.lower() == range_id.lower():
                        return load_manifest(d)
            raise FileNotFoundError(f"Range not found: {range_id}")
        return load_manifest(range_dir)

    def verify_firmware(self, manifest: RangeManifest) -> bool:
        """Check firmware binary exists and is not empty."""
        range_dir = self.vulnrange_dir / manifest.id
        firmware_path = range_dir / manifest.target.firmware
        return firmware_path.exists() and firmware_path.stat().st_size > 0

    def hint(self, range_id: str, level: int = 1) -> str:
        """Return a progressive hint for the range."""
        manifest = self.get(range_id)
        if not manifest.hints:
            return f"No hints available for {range_id}. Try: 'rtosploit range writeup {range_id}'"
        idx = min(level - 1, len(manifest.hints) - 1)
        return manifest.hints[idx]

    def get_writeup_path(self, range_id: str) -> Path:
        """Return path to writeup.md."""
        return self.vulnrange_dir / range_id / "writeup.md"

    def get_exploit_path(self, range_id: str) -> Path:
        """Return path to exploit.py."""
        manifest = self.get(range_id)
        return self.vulnrange_dir / range_id / manifest.exploit.script

    def get_qemu_config_path(self, range_id: str) -> Path:
        """Return path to qemu.yaml."""
        return self.vulnrange_dir / range_id / "qemu.yaml"

    def get_firmware_path(self, range_id: str) -> Path:
        """Return path to firmware binary."""
        manifest = self.get(range_id)
        return self.vulnrange_dir / range_id / manifest.target.firmware

    def get_range_info(self, range_id: str) -> dict:
        """Return structured info about a range for display."""
        manifest = self.get(range_id)
        return {
            "id": manifest.id,
            "title": manifest.title,
            "cve": manifest.cve,
            "cvss": manifest.cvss,
            "difficulty": manifest.difficulty,
            "category": manifest.category,
            "description": manifest.description,
            "rtos": manifest.target.rtos,
            "rtos_version": manifest.target.rtos_version,
            "machine": manifest.target.machine,
            "technique": manifest.exploit.technique,
            "reliability": manifest.exploit.reliability,
            "prerequisites": manifest.prerequisites,
            "tags": manifest.tags,
            "firmware_ready": self.verify_firmware(manifest),
        }
