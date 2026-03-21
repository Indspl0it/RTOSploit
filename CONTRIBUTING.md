# Contributing to RTOSploit

## Development Setup

```bash
git clone https://github.com/Indspl0it/RTOSploit
cd rtosploit
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
# Unit tests (no QEMU required)
pytest tests/unit/ -v

# Integration tests (requires QEMU)
pytest tests/integration/ -v

# Full suite
pytest tests/ -v --tb=short

# Specific test modules
pytest tests/unit/test_reporting.py -v    # Reporting
pytest tests/unit/test_triage.py -v       # Crash triage
pytest tests/unit/test_cve.py -v          # CVE correlation
pytest tests/unit/test_coverage_viz.py -v # Coverage viz
pytest tests/unit/test_ci_pipeline.py -v  # CI pipeline

# Rust tests
cargo test --workspace
```

## Code Style

- Python: follow PEP 8, use type hints, `from __future__ import annotations`
- Rust: use `cargo fmt` and `cargo clippy`
- Keep imports sorted (stdlib, third-party, local)

## Adding Exploit Modules

1. Create `rtosploit/exploits/<rtos>/mymodule.py`
2. Extend `ExploitModule` ABC — implement `check()`, `exploit()`, `cleanup()`, `requirements()`
3. Add tests to `tests/unit/test_<rtos>_exploits.py`
4. If the module has a CVE, add it to `rtosploit/cve/bundled_cves.json`
5. Submit PR

See [Writing Exploits](docs/writing-exploits.md) for the full API reference.

## Adding VulnRange Labs

1. Create `vulnrange/<CVE-ID>/` with `manifest.yaml`, `exploit.py`, `firmware.bin`
2. Optionally add `writeup.md`
3. Test with `rtosploit vulnrange verify <CVE-ID>`

See [Writing VulnRange Labs](docs/writing-vulnranges.md) for the manifest format.

## Adding CVEs to the Database

Edit `rtosploit/cve/bundled_cves.json` and add entries following the existing format:

```json
{
  "cve_id": "CVE-2024-XXXXX",
  "description": "Description of the vulnerability",
  "cvss_score": 7.5,
  "severity": "high",
  "affected_product": "freertos",
  "affected_versions": ["<=10.6.0", ">=10.4.0"],
  "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-XXXXX"],
  "published_date": "2024-01-15",
  "has_exploit": false
}
```

Set `has_exploit: true` if there's a corresponding exploit module in `rtosploit/exploits/`.

## Project Structure

See [Architecture](docs/architecture.md) for the full package layout and component descriptions.

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0-only.
