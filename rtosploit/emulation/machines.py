"""Machine configuration loading and validation for QEMU targets."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from rtosploit.errors import InvalidConfigError, UnknownMachineError


# Valid QEMU ARM machine names known to rtosploit
_VALID_QEMU_MACHINES = {
    "mps2-an385",
    "mps2-an505",
    "mps2-an521",
    "stm32vldiscovery",
    "netduino2",
    "netduinoplus2",
    "olimex-stm32-h405",
    "microbit",
    "lm3s811evb",
    "lm3s6965evb",
    "stellaris",
    "versatilepb",
    "vexpress-a9",
    "realview-pbx-a9",
    "virt",
}


@dataclass
class PeripheralConfig:
    """Configuration for a single peripheral."""
    name: str
    base: int
    size: int
    irq: Optional[int] = None
    builtin: bool = False


@dataclass
class MachineConfig:
    """Configuration for a QEMU machine target."""
    name: str
    qemu_machine: str
    cpu: str
    architecture: str
    memory: dict[str, dict[str, Any]] = field(default_factory=dict)
    peripherals: dict[str, PeripheralConfig] = field(default_factory=dict)


def _get_configs_dir() -> Path:
    """Return the path to the configs/machines/ directory."""
    # Walk up from this file to find the project root (where configs/ lives)
    here = Path(__file__).resolve()
    # rtosploit/emulation/machines.py -> rtosploit/emulation -> rtosploit -> project root
    project_root = here.parent.parent.parent
    return project_root / "configs" / "machines"


def _parse_machine_yaml(data: dict[str, Any], source: str) -> MachineConfig:
    """Parse a machine YAML dict into a MachineConfig."""
    machine_section = data.get("machine") or data
    required = ["name", "qemu_machine", "cpu", "architecture"]
    for field_name in required:
        if field_name not in machine_section:
            raise InvalidConfigError(
                f"Machine config '{source}' missing required field: '{field_name}'"
            )

    name = machine_section["name"]
    qemu_machine = machine_section["qemu_machine"]
    cpu = machine_section["cpu"]
    architecture = machine_section["architecture"]

    memory = data.get("memory") or {}
    raw_peripherals = data.get("peripherals") or {}

    # Parse peripherals
    peripherals: dict[str, PeripheralConfig] = {}
    for pname, pdata in raw_peripherals.items():
        if not isinstance(pdata, dict):
            raise InvalidConfigError(
                f"Peripheral '{pname}' in '{source}' must be a mapping"
            )
        if "base" not in pdata:
            raise InvalidConfigError(
                f"Peripheral '{pname}' in '{source}' missing 'base' field"
            )
        if "size" not in pdata:
            raise InvalidConfigError(
                f"Peripheral '{pname}' in '{source}' missing 'size' field"
            )
        irq_val = pdata.get("irq")
        peripherals[pname] = PeripheralConfig(
            name=pname,
            base=int(pdata["base"]),
            size=int(pdata["size"]),
            irq=int(irq_val) if irq_val is not None else None,
            builtin=bool(pdata.get("builtin", False)),
        )

    config = MachineConfig(
        name=name,
        qemu_machine=qemu_machine,
        cpu=cpu,
        architecture=architecture,
        memory=memory,
        peripherals=peripherals,
    )

    _validate_machine_config(config, source)
    return config


def _validate_machine_config(config: MachineConfig, source: str) -> None:
    """Validate machine config for consistency."""
    # Validate QEMU machine name (warn but don't error for unknown names)
    if config.qemu_machine not in _VALID_QEMU_MACHINES:
        # Allow unknown machines — QEMU evolves
        pass

    # Check memory regions don't overlap
    regions: list[tuple[str, int, int]] = []
    for region_name, region_data in config.memory.items():
        if isinstance(region_data, dict) and "base" in region_data and "size" in region_data:
            base = int(region_data["base"])
            size = int(region_data["size"])
            regions.append((region_name, base, size))

    for i, (name_a, base_a, size_a) in enumerate(regions):
        for name_b, base_b, size_b in regions[i + 1:]:
            end_a = base_a + size_a
            end_b = base_b + size_b
            if base_a < end_b and base_b < end_a:
                raise InvalidConfigError(
                    f"Memory regions '{name_a}' (0x{base_a:08x}-0x{end_a:08x}) and "
                    f"'{name_b}' (0x{base_b:08x}-0x{end_b:08x}) overlap in '{source}'"
                )


def load_machine(name_or_path: str) -> MachineConfig:
    """Load a MachineConfig by name or path.

    If name_or_path looks like a file path (contains '/' or ends in .yaml/.yml),
    load it directly. Otherwise treat it as a machine name and look in configs/machines/.
    """
    is_path = (
        "/" in name_or_path
        or "\\" in name_or_path
        or name_or_path.endswith(".yaml")
        or name_or_path.endswith(".yml")
        or os.path.sep in name_or_path
    )

    if is_path:
        path = Path(name_or_path)
        if not path.exists():
            raise InvalidConfigError(f"Machine config file not found: {path}")
        source = str(path)
    else:
        configs_dir = _get_configs_dir()
        path = configs_dir / f"{name_or_path}.yaml"
        if not path.exists():
            # Try without extension in case user included it
            path2 = configs_dir / name_or_path
            if path2.exists():
                path = path2
            else:
                available = list_machines()
                names = [m[0] for m in available]
                raise UnknownMachineError(
                    f"Unknown machine '{name_or_path}'. "
                    f"Available machines: {names}"
                )
        source = name_or_path

    with path.open() as f:
        data = yaml.safe_load(f) or {}

    return _parse_machine_yaml(data, source)


def list_machines() -> list[tuple[str, str, str]]:
    """Scan configs/machines/ and return [(name, cpu, architecture)] for each machine."""
    configs_dir = _get_configs_dir()
    results: list[tuple[str, str, str]] = []

    if not configs_dir.exists():
        return results

    for yaml_file in sorted(configs_dir.glob("*.yaml")):
        try:
            with yaml_file.open() as f:
                data = yaml.safe_load(f) or {}
            machine_section = data.get("machine") or data
            name = machine_section.get("name", yaml_file.stem)
            cpu = machine_section.get("cpu", "unknown")
            arch = machine_section.get("architecture", "unknown")
            results.append((name, cpu, arch))
        except Exception:
            # Skip malformed configs
            continue

    return results
