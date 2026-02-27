"""Firmware string extraction and analysis."""

from __future__ import annotations

import re
from typing import Optional

from rtosploit.utils.binary import FirmwareImage


def extract_strings(
    firmware: FirmwareImage,
    min_length: int = 4,
) -> list[tuple[int, str]]:
    """
    Scan firmware.data for null-terminated printable ASCII sequences.

    Returns a list of (address, string) tuples where address is
    firmware.base_address + byte_offset.
    """
    results: list[tuple[int, str]] = []
    data = firmware.data
    base = firmware.base_address

    current: list[str] = []
    start_offset: int = 0

    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7E:
            if not current:
                start_offset = i
            current.append(chr(b))
        else:
            if len(current) >= min_length:
                # Accept whether terminated by NUL (b==0) or any other byte
                results.append((base + start_offset, "".join(current)))
            current = []

    # Flush any remaining run at end of data
    if len(current) >= min_length:
        results.append((base + start_offset, "".join(current)))

    return results


def categorize_string(s: str) -> str:
    """
    Classify a string into a semantic category.

    Categories (in priority order):
      url, path, version, error, debug, format_string, config, function, other
    """
    sl = s.lower()

    if sl.startswith("http://") or sl.startswith("https://"):
        return "url"

    if s.startswith("/") or ("/" in s and not s.startswith("%")):
        return "path"

    # Version: digits.digits pattern (e.g. "1.2.3", "v10.4.0")
    if re.search(r"\d+\.\d+", s):
        return "version"

    if any(w in sl for w in ("error", "fail", "assert", "abort", "panic")):
        return "error"

    if any(w in sl for w in ("debug", "trace", "log", "verbose", "warn")):
        return "debug"

    # Format string: % followed by a format specifier character
    if re.search(r"%[sdioxXucpneEfgG%]", s):
        return "format_string"

    if s.startswith("CONFIG_") or s.startswith("config_"):
        return "config"

    # Heuristic for C function names: snake_case or camelCase identifiers
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{3,}", s):
        return "function"

    return "other"


def find_format_string_vulnerabilities(
    firmware: FirmwareImage,
) -> list[tuple[int, str]]:
    """
    Return (address, string) pairs for strings containing potentially
    dangerous format specifiers: %s, %n, %x, %d.
    """
    dangerous_re = re.compile(r"%[snxd]")
    results: list[tuple[int, str]] = []

    for addr, s in extract_strings(firmware):
        if dangerous_re.search(s):
            results.append((addr, s))

    return results


def extract_rtos_strings(
    firmware: FirmwareImage,
    rtos_type: str,
) -> list[tuple[int, str]]:
    """
    Return strings that are relevant to the identified RTOS.

    FreeRTOS: short task/queue/semaphore names (<=16 chars, no spaces,
              alphanumeric + underscore).
    Zephyr:   CONFIG_-prefixed configuration strings.
    Others:   all extracted strings.
    """
    all_strings = extract_strings(firmware)

    if rtos_type == "freertos":
        filtered = []
        name_re = re.compile(r"^[A-Za-z0-9_]{1,16}$")
        for addr, s in all_strings:
            if name_re.fullmatch(s):
                filtered.append((addr, s))
        return filtered

    if rtos_type == "zephyr":
        return [(addr, s) for addr, s in all_strings if s.startswith("CONFIG_")]

    # Default: return everything
    return all_strings
