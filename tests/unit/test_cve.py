"""Tests for the CVE correlation package."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path


from rtosploit.cve.database import CVEEntry, CVEDatabase
from rtosploit.cve.correlator import CVECorrelator, CorrelationResult


# ---------------------------------------------------------------------------
# CVEEntry
# ---------------------------------------------------------------------------

class TestCVEEntry:
    def test_creation_defaults(self):
        entry = CVEEntry(cve_id="CVE-2021-43997", description="test")
        assert entry.cve_id == "CVE-2021-43997"
        assert entry.severity == "medium"
        assert entry.has_exploit is False
        assert entry.affected_versions == []
        assert entry.references == []

    def test_to_dict_roundtrip(self):
        entry = CVEEntry(
            cve_id="CVE-2021-43997",
            description="heap_4 unlink vuln",
            cvss_score=9.8,
            severity="critical",
            affected_product="freertos",
            affected_versions=["<=10.4.6"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-43997"],
            published_date="2021-11-17",
            has_exploit=True,
        )
        d = entry.to_dict()
        restored = CVEEntry.from_dict(d)
        assert restored.cve_id == entry.cve_id
        assert restored.cvss_score == entry.cvss_score
        assert restored.has_exploit is True
        assert restored.affected_versions == ["<=10.4.6"]


# ---------------------------------------------------------------------------
# CVEDatabase
# ---------------------------------------------------------------------------

class TestCVEDatabase:
    def test_loads_bundled_db(self):
        db = CVEDatabase()
        db.load()
        assert len(db.entries) > 0
        # Bundled DB should have FreeRTOS, Zephyr, and ThreadX entries
        products = {e.affected_product for e in db.entries}
        assert "freertos" in products
        assert "zephyr" in products
        assert "threadx" in products

    def test_lookup_by_product(self):
        db = CVEDatabase()
        db.load()
        freertos_cves = db.lookup("freertos")
        assert len(freertos_cves) > 0
        assert all(e.affected_product == "freertos" for e in freertos_cves)

    def test_lookup_by_product_and_version(self):
        db = CVEDatabase()
        db.load()
        # Version 10.0.0 should match entries with constraint "<=10.0.1"
        results = db.lookup("freertos", "10.0.0")
        assert len(results) > 0
        # Version 99.0.0 should still match entries with high constraints
        results_high = db.lookup("freertos", "99.0.0")
        # Some entries have "<=10.0.1" so version 99 should NOT match those
        ids_low = {r.cve_id for r in db.lookup("freertos", "10.0.0")}
        ids_high = {r.cve_id for r in results_high}
        # The 10.0.0 set should have entries that 99.0.0 does not
        assert ids_low - ids_high  # some entries excluded for v99

    def test_search_by_term(self):
        db = CVEDatabase()
        db.load()
        results = db.search("heap")
        assert len(results) > 0
        # All results should mention heap somewhere
        for r in results:
            searchable = f"{r.cve_id} {r.description} {r.affected_product}".lower()
            assert "heap" in searchable

    def test_search_by_cve_id(self):
        db = CVEDatabase()
        db.load()
        results = db.search("CVE-2021-43997")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2021-43997"

    def test_version_matches(self):
        vm = CVEDatabase._version_matches
        assert vm("10.0.0", "<=10.0.1") is True
        assert vm("10.0.1", "<=10.0.1") is True
        assert vm("10.0.2", "<=10.0.1") is False
        assert vm("10.4.3", ">=10.0.0") is True
        assert vm("9.9.9", ">=10.0.0") is False
        assert vm("10.0.0", "<10.0.1") is True
        assert vm("10.0.1", "<10.0.1") is False
        assert vm("10.0.1", ">10.0.0") is True
        assert vm("10.0.0", ">10.0.0") is False
        assert vm("10.0.1", "==10.0.1") is True
        assert vm("10.0.1", "10.0.1") is True  # bare = ==
        assert vm("10.0.2", "10.0.1") is False

    def test_update_from_nvd_idempotent(self):
        """update_from_nvd should not add duplicates."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump([], f)
            tmp_path = f.name
        try:
            db = CVEDatabase(db_path=tmp_path)
            db.load()
            entry = CVEEntry(cve_id="CVE-TEST-0001", description="test")
            db.update_from_nvd([entry])
            assert len(db.entries) == 1
            # Adding again should be idempotent
            db.update_from_nvd([entry])
            assert len(db.entries) == 1
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_save_and_reload(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump([], f)
            tmp_path = f.name
        try:
            db = CVEDatabase(db_path=tmp_path)
            db.load()
            db.update_from_nvd([
                CVEEntry(cve_id="CVE-TEST-0001", description="first"),
                CVEEntry(cve_id="CVE-TEST-0002", description="second"),
            ])
            db.save()

            db2 = CVEDatabase(db_path=tmp_path)
            db2.load()
            assert len(db2.entries) == 2
        finally:
            Path(tmp_path).unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# CVECorrelator
# ---------------------------------------------------------------------------

class TestCVECorrelator:
    def _make_correlator(self) -> CVECorrelator:
        db = CVEDatabase()
        db.load()
        return CVECorrelator(db)

    def test_correlate_known_product(self):
        correlator = self._make_correlator()
        result = correlator.correlate("freertos")
        assert isinstance(result, CorrelationResult)
        assert result.rtos == "freertos"
        assert result.total_cves > 0
        assert len(result.matching_cves) == result.total_cves

    def test_correlate_returns_exploitable_subset(self):
        correlator = self._make_correlator()
        result = correlator.correlate("freertos", "10.0.0")
        assert len(result.exploitable_cves) > 0
        for cve in result.exploitable_cves:
            assert cve.has_exploit is True
        # Exploitable should be a subset of matching
        exploitable_ids = {c.cve_id for c in result.exploitable_cves}
        matching_ids = {c.cve_id for c in result.matching_cves}
        assert exploitable_ids.issubset(matching_ids)

    def test_highest_severity_computation(self):
        correlator = self._make_correlator()
        result = correlator.correlate("freertos", "10.0.0")
        # FreeRTOS 10.0.0 has critical CVEs
        assert result.highest_severity == "critical"

    def test_correlate_unknown_product(self):
        correlator = self._make_correlator()
        result = correlator.correlate("nonexistent_rtos")
        assert result.total_cves == 0
        assert result.highest_severity == "info"

    def test_correlate_from_fingerprint(self):
        correlator = self._make_correlator()
        fp_data = {"rtos": "freertos", "version": "10.0.0"}
        result = correlator.correlate_from_fingerprint(fp_data)
        assert result.rtos == "freertos"
        assert result.total_cves > 0

    def test_correlate_from_fingerprint_rtos_type_key(self):
        """Supports 'rtos_type' key used by RTOSFingerprint."""
        correlator = self._make_correlator()
        fp_data = {"rtos_type": "zephyr", "version": "2.2.0"}
        result = correlator.correlate_from_fingerprint(fp_data)
        assert result.rtos == "zephyr"
        assert result.total_cves > 0


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

class TestCVECLI:
    def test_cve_help(self):
        from click.testing import CliRunner
        from rtosploit.cli.commands.cve import cve

        runner = CliRunner()
        result = runner.invoke(cve, ["--help"])
        assert result.exit_code == 0
        assert "CVE correlation" in result.output

    def test_scan_help(self):
        from click.testing import CliRunner
        from rtosploit.cli.commands.cve import cve

        runner = CliRunner()
        result = runner.invoke(cve, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--firmware" in result.output

    def test_search_help(self):
        from click.testing import CliRunner
        from rtosploit.cli.commands.cve import cve

        runner = CliRunner()
        result = runner.invoke(cve, ["search", "--help"])
        assert result.exit_code == 0
        assert "TERM" in result.output

    def test_update_help(self):
        from click.testing import CliRunner
        from rtosploit.cli.commands.cve import cve

        runner = CliRunner()
        result = runner.invoke(cve, ["update", "--help"])
        assert result.exit_code == 0
        assert "--api-key" in result.output
