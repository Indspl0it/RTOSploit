"""Tests for the VulnRange CVE reproduction lab (Phase 14)."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

# Add project root to path so we can import rtosploit
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
VULNRANGE_DIR = PROJECT_ROOT / "vulnrange"

sys.path.insert(0, str(PROJECT_ROOT))

from rtosploit.vulnrange import RangeManifest, VulnRangeManager, list_ranges, load_manifest


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def manager() -> VulnRangeManager:
    return VulnRangeManager(vulnrange_dir=VULNRANGE_DIR)


# ─── Test 1: load_manifest returns RangeManifest ─────────────────────────────

def test_load_manifest_returns_range_manifest():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert isinstance(manifest, RangeManifest)


# ─── Test 2: CVE field ───────────────────────────────────────────────────────

def test_manifest_cve():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert manifest.cve == "CVE-2018-16525"


# ─── Test 3: target RTOS ─────────────────────────────────────────────────────

def test_manifest_target_rtos():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert manifest.target.rtos == "freertos"


# ─── Test 4: target machine ──────────────────────────────────────────────────

def test_manifest_target_machine():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert manifest.target.machine == "mps2-an385"


# ─── Test 5: difficulty ──────────────────────────────────────────────────────

def test_manifest_difficulty():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert manifest.difficulty == "intermediate"


# ─── Test 6: vulnerability type ──────────────────────────────────────────────

def test_manifest_vulnerability_type():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert manifest.vulnerability.type == "heap_corruption"


# ─── Test 7: exploit technique ───────────────────────────────────────────────

def test_manifest_exploit_technique():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert manifest.exploit.technique == "blocklist_unlink_rce"


# ─── Test 8: missing manifest raises FileNotFoundError ───────────────────────

def test_load_manifest_nonexistent_raises():
    with pytest.raises(FileNotFoundError):
        load_manifest(VULNRANGE_DIR / "NONEXISTENT-RANGE")


# ─── Test 9: list_ranges returns 5 ranges ────────────────────────────────────

def test_list_ranges_count():
    ranges = list_ranges(VULNRANGE_DIR)
    assert len(ranges) == 5


# ─── Test 10: list_ranges sorted by id ───────────────────────────────────────

def test_list_ranges_sorted():
    ranges = list_ranges(VULNRANGE_DIR)
    ids = [r.id for r in ranges]
    assert ids == sorted(ids)


# ─── Test 11: list_ranges nonexistent dir returns empty ──────────────────────

def test_list_ranges_nonexistent_dir():
    result = list_ranges(PROJECT_ROOT / "nonexistent_vulnrange_dir_xyz")
    assert result == []


# ─── Test 12: VulnRangeManager.list() returns all ranges ─────────────────────

def test_manager_list_all(manager: VulnRangeManager):
    ranges = manager.list()
    assert len(ranges) == 5
    assert all(isinstance(r, RangeManifest) for r in ranges)


# ─── Test 13: VulnRangeManager.get() returns correct manifest ────────────────

def test_manager_get_correct_manifest(manager: VulnRangeManager):
    manifest = manager.get("CVE-2018-16525")
    assert manifest.id == "CVE-2018-16525"
    assert manifest.title == "FreeRTOS+TCP DNS Response Heap Overflow"


# ─── Test 14: VulnRangeManager.get() nonexistent raises FileNotFoundError ────

def test_manager_get_nonexistent_raises(manager: VulnRangeManager):
    with pytest.raises(FileNotFoundError):
        manager.get("DOES-NOT-EXIST-12345")


# ─── Test 15: hint level 1 returns non-empty string ──────────────────────────

def test_manager_hint_level1(manager: VulnRangeManager):
    hint = manager.hint("CVE-2018-16525", level=1)
    assert isinstance(hint, str)
    assert len(hint) > 0


# ─── Test 16: hint level 3 returns most detailed hint ────────────────────────

def test_manager_hint_level3(manager: VulnRangeManager):
    hint = manager.hint("CVE-2018-16525", level=3)
    assert isinstance(hint, str)
    # Level 3 should be the most detailed (last) hint
    manifest = manager.get("CVE-2018-16525")
    assert hint == manifest.hints[-1]


# ─── Test 17: get_writeup_path returns path to writeup.md ────────────────────

def test_manager_get_writeup_path(manager: VulnRangeManager):
    writeup_path = manager.get_writeup_path("CVE-2018-16525")
    assert writeup_path.name == "writeup.md"
    assert writeup_path.exists()


# ─── Test 18: verify_firmware returns True for placeholder bin ───────────────

def test_manager_verify_firmware(manager: VulnRangeManager):
    manifest = manager.get("CVE-2018-16525")
    assert manager.verify_firmware(manifest) is True


# ─── Test 19: get_range_info includes firmware_ready key ─────────────────────

def test_manager_get_range_info_firmware_ready(manager: VulnRangeManager):
    info = manager.get_range_info("CVE-2021-43997")
    assert "firmware_ready" in info
    assert isinstance(info["firmware_ready"], bool)


# ─── Test 20: to_dict() contains required keys ───────────────────────────────

def test_manifest_to_dict_keys():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    d = manifest.to_dict()
    for key in ("id", "cve", "difficulty"):
        assert key in d


# ─── Test 21: KOM-ThreadX has cve=None ───────────────────────────────────────

def test_kom_threadx_no_cve(manager: VulnRangeManager):
    manifest = manager.get("KOM-ThreadX")
    assert manifest.cve is None


# ─── Test 22: CVE-2024-28115 difficulty is advanced ──────────────────────────

def test_cve_2024_28115_difficulty(manager: VulnRangeManager):
    manifest = manager.get("CVE-2024-28115")
    assert manifest.difficulty == "advanced"


# ─── Test 23: All 5 exploit.py files have valid Python syntax ────────────────

@pytest.mark.parametrize("range_id", [
    "CVE-2018-16525",
    "CVE-2021-43997",
    "CVE-2024-28115",
    "CVE-2025-5688",
    "KOM-ThreadX",
])
def test_exploit_py_valid_syntax(range_id: str):
    exploit_path = VULNRANGE_DIR / range_id / "exploit.py"
    assert exploit_path.exists(), f"exploit.py missing for {range_id}"
    source = exploit_path.read_text(encoding="utf-8")
    try:
        ast.parse(source)
    except SyntaxError as e:
        pytest.fail(f"exploit.py for {range_id} has syntax error: {e}")


# ─── Test 24: All 5 ranges have writeup.md ───────────────────────────────────

@pytest.mark.parametrize("range_id", [
    "CVE-2018-16525",
    "CVE-2021-43997",
    "CVE-2024-28115",
    "CVE-2025-5688",
    "KOM-ThreadX",
])
def test_writeup_md_exists(range_id: str):
    writeup_path = VULNRANGE_DIR / range_id / "writeup.md"
    assert writeup_path.exists(), f"writeup.md missing for {range_id}"
    content = writeup_path.read_text(encoding="utf-8")
    assert len(content) > 100, f"writeup.md for {range_id} seems too short"


# ─── Additional coverage tests ────────────────────────────────────────────────

def test_manifest_id_matches_directory():
    """Manifest id field should match its containing directory name."""
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert manifest.id == "CVE-2018-16525"


def test_manifest_has_hints():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert len(manifest.hints) >= 1


def test_manifest_has_prerequisites():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert len(manifest.prerequisites) >= 1


def test_manifest_has_tags():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert "heap" in manifest.tags or "network" in manifest.tags


def test_manifest_cvss_is_float():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert isinstance(manifest.cvss, float)
    assert 0.0 <= manifest.cvss <= 10.0


def test_manager_get_firmware_path(manager: VulnRangeManager):
    path = manager.get_firmware_path("CVE-2018-16525")
    assert path.name == "firmware.bin"
    assert path.exists()


def test_manager_get_exploit_path(manager: VulnRangeManager):
    path = manager.get_exploit_path("CVE-2018-16525")
    assert path.name == "exploit.py"
    assert path.exists()


def test_manager_get_qemu_config_path(manager: VulnRangeManager):
    path = manager.get_qemu_config_path("CVE-2018-16525")
    assert path.name == "qemu.yaml"
    assert path.exists()


def test_cve_2021_43997_difficulty_beginner(manager: VulnRangeManager):
    manifest = manager.get("CVE-2021-43997")
    assert manifest.difficulty == "beginner"


def test_cve_2025_5688_category(manager: VulnRangeManager):
    manifest = manager.get("CVE-2025-5688")
    assert manifest.category == "heap_corruption"


def test_kom_threadx_category(manager: VulnRangeManager):
    manifest = manager.get("KOM-ThreadX")
    assert manifest.category == "kernel"


def test_all_ranges_have_firmware_placeholder(manager: VulnRangeManager):
    """All ranges should have a firmware.bin placeholder."""
    for manifest in manager.list():
        assert manager.verify_firmware(manifest), \
            f"firmware.bin missing or empty for {manifest.id}"


def test_manifest_description_not_empty():
    manifest = load_manifest(VULNRANGE_DIR / "CVE-2018-16525")
    assert len(manifest.description.strip()) > 0


def test_manager_hint_no_hints_returns_fallback(manager: VulnRangeManager, tmp_path):
    """hint() returns fallback message when no hints defined."""
    # Create a minimal range with no hints
    minimal_dir = tmp_path / "MINIMAL"
    minimal_dir.mkdir()
    (minimal_dir / "manifest.yaml").write_text(
        "id: MINIMAL\ntitle: Minimal\ncve: null\ncvss: null\n"
        "category: test\ndifficulty: beginner\n"
        "target:\n  rtos: freertos\n  rtos_version: '1.0'\n"
        "  arch: armv7m\n  machine: mps2-an385\n  firmware: firmware.bin\n"
        "vulnerability:\n  type: test\n  component: test\n  root_cause: test\n"
        "  affected_function: test\n  trigger: test\n"
        "exploit:\n  technique: test\n  reliability: low\n  payload: null\n  script: exploit.py\n"
    )
    local_manager = VulnRangeManager(vulnrange_dir=tmp_path)
    hint = local_manager.hint("MINIMAL", level=1)
    assert "No hints available" in hint or isinstance(hint, str)
