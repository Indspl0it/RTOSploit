"""Tests verifying docs and packaging configuration."""
import pytest
from pathlib import Path


class TestDocs:
    def test_readme_exists(self):
        assert Path("README.md").exists()

    def test_readme_not_empty(self):
        content = Path("README.md").read_text()
        assert len(content) > 100

    def test_readme_has_install_section(self):
        content = Path("README.md").read_text()
        assert "install" in content.lower()

    def test_readme_has_usage_section(self):
        content = Path("README.md").read_text()
        assert "usage" in content.lower() or "quick" in content.lower()

    def test_changelog_exists(self):
        assert Path("CHANGELOG.md").exists()

    def test_contributing_exists(self):
        assert Path("CONTRIBUTING.md").exists()

    def test_docs_installation_exists(self):
        assert Path("docs/installation.md").exists()

    def test_docs_quickstart_exists(self):
        assert Path("docs/quickstart.md").exists()

    def test_docs_writing_exploits_exists(self):
        assert Path("docs/writing-exploits.md").exists()

    def test_docs_architecture_exists(self):
        assert Path("docs/architecture.md").exists()

    def test_dockerfile_exists(self):
        assert Path("Dockerfile").exists()


class TestPackaging:
    def test_pyproject_toml_exists(self):
        assert Path("pyproject.toml").exists()

    def test_pyproject_has_name(self):
        content = Path("pyproject.toml").read_text()
        assert "rtosploit" in content.lower()

    def test_pyproject_has_version(self):
        content = Path("pyproject.toml").read_text()
        assert "version" in content

    def test_pyproject_has_cli_entry_point(self):
        content = Path("pyproject.toml").read_text()
        assert "rtosploit" in content and "cli" in content

    def test_package_version_importable(self):
        import rtosploit
        assert hasattr(rtosploit, "__version__")
        assert rtosploit.__version__ == "0.1.0"

    def test_package_exports_key_modules(self):
        import rtosploit.exploits.registry
        import rtosploit.emulation.machines
        import rtosploit.analysis.fingerprint

    def test_cargo_toml_exists(self):
        assert Path("Cargo.toml").exists()

    def test_cargo_workspace_members(self):
        content = Path("Cargo.toml").read_text()
        assert "rtosploit-fuzzer" in content
        assert "rtosploit-svd" in content
        assert "rtosploit-payloads" in content

    def test_license_file_exists(self):
        assert Path("LICENSE").exists()

    def test_gitignore_exists(self):
        assert Path(".gitignore").exists()
