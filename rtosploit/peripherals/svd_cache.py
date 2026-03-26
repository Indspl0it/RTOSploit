"""SVD file download and cache manager.

Downloads SVD files from the CMSIS-SVD GitHub repository and caches them
locally for offline use. Maps MCU family shortnames to specific SVD files.
"""

from __future__ import annotations

import logging
import os
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from rtosploit.peripherals.svd_model import SVDDevice

logger = logging.getLogger(__name__)

# Base URLs for CMSIS-SVD data repository, tried in order (first success wins).
# The upstream repo has moved/restructured several times; fallbacks prevent 404s.
_SVD_BASE_URLS = [
    "https://raw.githubusercontent.com/cmsis-svd/cmsis-svd-data/main/data/",
    "https://raw.githubusercontent.com/cmsis-svd/cmsis-svd-data/main/",
    "https://raw.githubusercontent.com/posborne/cmsis-svd/master/data/",
]

# MCU family shortname -> (vendor_folder, svd_filename)
_MCU_SVD_MAP: dict[str, tuple[str, str]] = {
    "nrf52": ("Nordic", "nRF52840.svd"),
    "nrf52832": ("Nordic", "nRF52832.svd"),
    "stm32": ("STMicro", "STM32F407.svd"),
    "stm32f1": ("STMicro", "STM32F103xx.svd"),
    "stm32f4": ("STMicro", "STM32F407.svd"),
    "stm32l4": ("STMicro", "STM32L4x6.svd"),
    "lpc": ("NXP", "LPC176x5x_v0.2.svd"),
    "sam": ("Atmel", "ATSAMD21G18A.svd"),
    "rp2040": ("RaspberryPi", "RP2040.svd"),
    "esp32": ("Espressif", "ESP32.svd"),
}

# Default cache directory — respects $XDG_CACHE_HOME
_DEFAULT_CACHE_DIR = (
    Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    / "rtosploit"
    / "svd"
)


class SVDCache:
    """Downloads and caches SVD files for MCU families."""

    def __init__(self, cache_dir: Optional[Path] = None) -> None:
        self._cache_dir = cache_dir or _DEFAULT_CACHE_DIR

    @property
    def cache_dir(self) -> Path:
        """Return the cache directory path."""
        return self._cache_dir

    def get_svd(self, mcu_family: str) -> Optional[Path]:
        """Get SVD file path, downloading if needed.

        Args:
            mcu_family: MCU family shortname (e.g. "nrf52", "stm32f4").

        Returns:
            Path to cached SVD file, or None if download fails and no cache.
        """
        key = mcu_family.lower()
        mapping = _MCU_SVD_MAP.get(key)
        if mapping is None:
            logger.warning("Unknown MCU family: %s", mcu_family)
            return None

        vendor, filename = mapping
        cached_path = self._cache_dir / vendor / filename

        # Cache hit — return immediately
        if cached_path.exists():
            return cached_path

        # Download — try each base URL in order until one succeeds
        cached_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = cached_path.with_suffix(".tmp")

        for base_url in _SVD_BASE_URLS:
            url = f"{base_url}{vendor}/{filename}"
            logger.info("Trying SVD URL: %s", url)

            try:
                urllib.request.urlretrieve(url, str(tmp_path))
                tmp_path.rename(cached_path)
                logger.info("Downloaded SVD from %s", url)
                return cached_path
            except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
                logger.debug("URL failed: %s — %s", url, e)
                # Clean up partial download before trying next URL
                if tmp_path.exists():
                    tmp_path.unlink()

        logger.error(
            "Failed to download SVD %s/%s from all URLs", vendor, filename
        )
        return None

    def get_svd_device(self, mcu_family: str) -> Optional[SVDDevice]:
        """Get parsed SVDDevice, downloading SVD if needed.

        Args:
            mcu_family: MCU family shortname.

        Returns:
            Parsed SVDDevice, or None if SVD file unavailable.
        """
        path = self.get_svd(mcu_family)
        if path is None:
            return None

        from rtosploit.peripherals.svd_parser import SVDParseError, parse_svd

        try:
            return parse_svd(path)
        except (SVDParseError, ValueError, KeyError, AttributeError, ET.ParseError) as e:
            logger.error("Failed to parse SVD %s: %s", path, e)
            return None

    @staticmethod
    def known_families() -> list[str]:
        """Return list of known MCU family shortnames."""
        return sorted(_MCU_SVD_MAP.keys())

    @staticmethod
    def get_mapping(mcu_family: str) -> Optional[tuple[str, str]]:
        """Return (vendor, filename) for an MCU family, or None."""
        return _MCU_SVD_MAP.get(mcu_family.lower())
