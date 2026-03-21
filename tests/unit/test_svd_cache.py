"""Unit tests for rtosploit.peripherals.svd_cache."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch
import urllib.error


from rtosploit.peripherals.svd_cache import SVDCache


# ---------------------------------------------------------------------------
# MCU family mapping
# ---------------------------------------------------------------------------

class TestMCUMapping:
    def test_known_families_not_empty(self):
        families = SVDCache.known_families()
        assert len(families) > 0

    def test_nrf52_mapping(self):
        mapping = SVDCache.get_mapping("nrf52")
        assert mapping == ("Nordic", "nRF52840.svd")

    def test_stm32f4_mapping(self):
        mapping = SVDCache.get_mapping("stm32f4")
        assert mapping == ("STMicro", "STM32F407.svd")

    def test_rp2040_mapping(self):
        mapping = SVDCache.get_mapping("rp2040")
        assert mapping == ("RaspberryPi", "RP2040.svd")

    def test_esp32_mapping(self):
        mapping = SVDCache.get_mapping("esp32")
        assert mapping == ("Espressif", "ESP32.svd")

    def test_unknown_family_returns_none(self):
        assert SVDCache.get_mapping("unknownchip") is None

    def test_case_insensitive(self):
        assert SVDCache.get_mapping("NRF52") == SVDCache.get_mapping("nrf52")

    def test_all_expected_families_present(self):
        expected = [
            "nrf52", "nrf52832", "stm32", "stm32f1", "stm32f4",
            "stm32l4", "lpc", "sam", "rp2040", "esp32",
        ]
        for fam in expected:
            assert SVDCache.get_mapping(fam) is not None, f"Missing family: {fam}"


# ---------------------------------------------------------------------------
# Cache directory
# ---------------------------------------------------------------------------

class TestCacheDirectory:
    def test_default_cache_dir(self):
        cache = SVDCache()
        assert "rtosploit" in str(cache.cache_dir)
        assert "svd" in str(cache.cache_dir)

    def test_custom_cache_dir(self, tmp_path):
        cache = SVDCache(cache_dir=tmp_path / "my_cache")
        assert cache.cache_dir == tmp_path / "my_cache"


# ---------------------------------------------------------------------------
# Cache hit (file already exists)
# ---------------------------------------------------------------------------

class TestCacheHit:
    def test_returns_cached_file(self, tmp_path):
        """When SVD file exists in cache, return path without downloading."""
        cache = SVDCache(cache_dir=tmp_path)
        # Create the expected cache structure
        svd_dir = tmp_path / "Nordic"
        svd_dir.mkdir()
        svd_file = svd_dir / "nRF52840.svd"
        svd_file.write_text("<device><name>test</name></device>")

        result = cache.get_svd("nrf52")
        assert result == svd_file
        assert result.exists()


# ---------------------------------------------------------------------------
# Cache miss (download needed)
# ---------------------------------------------------------------------------

class TestCacheMiss:
    def test_unknown_family_returns_none(self, tmp_path):
        cache = SVDCache(cache_dir=tmp_path)
        result = cache.get_svd("unknownchip")
        assert result is None

    @patch("rtosploit.peripherals.svd_cache.urllib.request.urlretrieve")
    def test_download_success(self, mock_retrieve, tmp_path):
        """Successful download creates cached file."""
        cache = SVDCache(cache_dir=tmp_path)

        def fake_download(url, dest):
            Path(dest).parent.mkdir(parents=True, exist_ok=True)
            Path(dest).write_text("<device><name>nRF52840</name></device>")

        mock_retrieve.side_effect = fake_download

        result = cache.get_svd("nrf52")
        assert result is not None
        assert result.exists()
        assert "Nordic" in str(result)
        assert "nRF52840.svd" in str(result)
        mock_retrieve.assert_called_once()

    @patch("rtosploit.peripherals.svd_cache.urllib.request.urlretrieve")
    def test_download_failure_returns_none(self, mock_retrieve, tmp_path):
        """Failed download returns None."""
        cache = SVDCache(cache_dir=tmp_path)
        mock_retrieve.side_effect = urllib.error.HTTPError(
            "http://example.com", 404, "Not Found", {}, None
        )
        result = cache.get_svd("nrf52")
        assert result is None

    @patch("rtosploit.peripherals.svd_cache.urllib.request.urlretrieve")
    def test_download_uses_atomic_rename(self, mock_retrieve, tmp_path):
        """Download writes to .tmp then renames for atomicity."""
        cache = SVDCache(cache_dir=tmp_path)
        calls = []

        def fake_download(url, dest):
            calls.append(dest)
            Path(dest).parent.mkdir(parents=True, exist_ok=True)
            Path(dest).write_text("<device/>")

        mock_retrieve.side_effect = fake_download

        cache.get_svd("nrf52")
        # Should have downloaded to .tmp file
        assert len(calls) == 1
        assert calls[0].endswith(".tmp")


# ---------------------------------------------------------------------------
# get_svd_device (parsing integration)
# ---------------------------------------------------------------------------

class TestGetSVDDevice:
    def test_cached_svd_parses(self, tmp_path):
        """get_svd_device parses a cached SVD file."""
        cache = SVDCache(cache_dir=tmp_path)
        svd_dir = tmp_path / "Nordic"
        svd_dir.mkdir()
        svd_file = svd_dir / "nRF52840.svd"
        svd_file.write_text("""\
<?xml version="1.0" encoding="utf-8"?>
<device>
  <name>nRF52840</name>
  <peripherals>
    <peripheral>
      <name>UART0</name>
      <baseAddress>0x40002000</baseAddress>
    </peripheral>
  </peripherals>
</device>
""")
        device = cache.get_svd_device("nrf52")
        assert device is not None
        assert device.name == "nRF52840"
        assert len(device.peripherals) == 1

    def test_missing_svd_returns_none(self, tmp_path):
        cache = SVDCache(cache_dir=tmp_path)
        assert cache.get_svd_device("unknownchip") is None

    def test_corrupt_svd_returns_none(self, tmp_path):
        """Corrupt SVD file returns None instead of raising."""
        cache = SVDCache(cache_dir=tmp_path)
        svd_dir = tmp_path / "Nordic"
        svd_dir.mkdir()
        svd_file = svd_dir / "nRF52840.svd"
        svd_file.write_text("NOT VALID XML {{{{")

        device = cache.get_svd_device("nrf52")
        assert device is None
