"""RTOSploit configuration system.

Precedence (highest to lowest):
    1. CLI flags
    2. Environment variables (RTOSPLOIT_*)
    3. Project config (.rtosploit.yaml in cwd)
    4. User config (~/.config/rtosploit/config.yaml)
    5. Built-in defaults
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class QEMUConfig:
    binary: str = "qemu-system-arm"
    timeout: int = 30


@dataclass
class GDBConfig:
    port: int = 1234


@dataclass
class OutputConfig:
    format: str = "text"  # "text" or "json"
    color: bool = True


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: str | None = None


@dataclass
class SVDConfig:
    cache_dir: str = str(Path.home() / ".cache" / "rtosploit" / "svd")


@dataclass
class FuzzerConfig:
    default_config: str = "default"


@dataclass
class RTOSploitConfig:
    qemu: QEMUConfig = field(default_factory=QEMUConfig)
    gdb: GDBConfig = field(default_factory=GDBConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    svd: SVDConfig = field(default_factory=SVDConfig)
    fuzzer: FuzzerConfig = field(default_factory=FuzzerConfig)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge override into base."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _config_from_dict(data: dict[str, Any]) -> RTOSploitConfig:
    cfg = RTOSploitConfig()
    if "qemu" in data:
        q = data["qemu"]
        if "binary" in q:
            cfg.qemu.binary = q["binary"]
        if "timeout" in q:
            cfg.qemu.timeout = int(q["timeout"])
    if "gdb" in data:
        g = data["gdb"]
        if "port" in g:
            cfg.gdb.port = int(g["port"])
    if "output" in data:
        o = data["output"]
        if "format" in o:
            cfg.output.format = o["format"]
        if "color" in o:
            cfg.output.color = bool(o["color"])
    if "logging" in data:
        lo = data["logging"]
        if "level" in lo:
            cfg.logging.level = lo["level"]
        if "file" in lo:
            cfg.logging.file = lo["file"]
    if "svd" in data:
        s = data["svd"]
        if "cache_dir" in s:
            cfg.svd.cache_dir = s["cache_dir"]
    if "fuzzer" in data:
        f = data["fuzzer"]
        if "default_config" in f:
            cfg.fuzzer.default_config = f["default_config"]
    return cfg


def _load_yaml_file(path: Path) -> dict[str, Any]:
    if path.exists():
        with path.open() as f:
            return yaml.safe_load(f) or {}
    return {}


def load_config(config_path: str | None = None) -> RTOSploitConfig:
    """Load configuration from all sources in precedence order."""
    merged: dict[str, Any] = {}

    # 5. Built-in defaults (via dataclass defaults — nothing to load)

    # 4. User config
    user_config = Path.home() / ".config" / "rtosploit" / "config.yaml"
    merged = _deep_merge(merged, _load_yaml_file(user_config))

    # 3. Project config
    project_config = Path.cwd() / ".rtosploit.yaml"
    merged = _deep_merge(merged, _load_yaml_file(project_config))

    # 3b. Explicit config path (from CLI --config flag)
    if config_path:
        merged = _deep_merge(merged, _load_yaml_file(Path(config_path)))

    # 2. Environment variables
    env_map = {
        "RTOSPLOIT_QEMU_BINARY": ["qemu", "binary"],
        "RTOSPLOIT_QEMU_TIMEOUT": ["qemu", "timeout"],
        "RTOSPLOIT_GDB_PORT": ["gdb", "port"],
        "RTOSPLOIT_OUTPUT_FORMAT": ["output", "format"],
        "RTOSPLOIT_OUTPUT_COLOR": ["output", "color"],
        "RTOSPLOIT_LOGGING_LEVEL": ["logging", "level"],
        "RTOSPLOIT_LOGGING_FILE": ["logging", "file"],
        "RTOSPLOIT_SVD_CACHE_DIR": ["svd", "cache_dir"],
        "RTOSPLOIT_FUZZER_DEFAULT_CONFIG": ["fuzzer", "default_config"],
    }
    for env_key, path_parts in env_map.items():
        value = os.environ.get(env_key)
        if value is not None:
            section = path_parts[0]
            key = path_parts[1]
            if section not in merged:
                merged[section] = {}
            merged[section][key] = value

    return _config_from_dict(merged)
