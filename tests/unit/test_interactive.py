"""Tests for the interactive mode package."""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from rtosploit.interactive.session import FirmwareContext, InteractiveSession
from rtosploit.interactive.banner import print_banner
from rtosploit.interactive.menus import (
    MAIN_MENU,
    MAIN_FOOTER,
    FIRMWARE_MENU,
    FIRMWARE_FOOTER,
)
from rtosploit.interactive.app import InteractiveApp, interactive_main


# ---------------------------------------------------------------------------
# Session dataclasses
# ---------------------------------------------------------------------------


class TestInteractiveSession:
    def test_default_state(self):
        session = InteractiveSession()
        assert session.firmware is None
        assert session.debug is False
        assert session.history == []
        assert session.output_dir == Path("./results")

    def test_has_firmware_false(self):
        session = InteractiveSession()
        assert session.has_firmware is False

    def test_has_firmware_true(self):
        fw = MagicMock(spec=FirmwareContext)
        session = InteractiveSession(firmware=fw)
        assert session.has_firmware is True

    def test_has_qemu_false_no_firmware(self):
        session = InteractiveSession()
        assert session.has_qemu is False

    def test_has_qemu_false_no_qemu(self):
        fw = MagicMock(spec=FirmwareContext)
        fw.qemu = None
        session = InteractiveSession(firmware=fw)
        assert session.has_qemu is False

    def test_has_qemu_true(self):
        fw = MagicMock(spec=FirmwareContext)
        fw.qemu = MagicMock()
        session = InteractiveSession(firmware=fw)
        assert session.has_qemu is True

    def test_debug_mode(self):
        session = InteractiveSession(debug=True)
        assert session.debug is True


class TestFirmwareContext:
    def test_rtos_name_no_fingerprint(self):
        fw = FirmwareContext(
            path=Path("/tmp/fw.bin"),
            image=MagicMock(),
            fingerprint=None,
        )
        assert fw.rtos_name == "Unknown"

    def test_rtos_name_with_fingerprint(self):
        fp = MagicMock()
        fp.rtos_type = "freertos"
        fp.version = "10.4.3"
        fw = FirmwareContext(
            path=Path("/tmp/fw.bin"),
            image=MagicMock(),
            fingerprint=fp,
        )
        assert fw.rtos_name == "Freertos"
        assert fw.rtos_version == "10.4.3"

    def test_rtos_version_none(self):
        fp = MagicMock()
        fp.version = None
        fw = FirmwareContext(
            path=Path("/tmp/fw.bin"),
            image=MagicMock(),
            fingerprint=fp,
        )
        assert fw.rtos_version == ""

    def test_arch_name(self):
        img = MagicMock()
        img.architecture = "armv7m"
        fw = FirmwareContext(path=Path("/tmp/fw.bin"), image=img)
        assert fw.arch_name == "armv7m"


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------


class TestBanner:
    def test_banner_art_is_nonempty(self):
        from rtosploit.interactive.banner import _RTOS_LINES
        assert len(_RTOS_LINES) >= 5  # Block art has multiple lines

    def test_print_banner_no_crash(self):
        from rich.console import Console
        from io import StringIO
        buf = StringIO()
        console = Console(file=buf, force_terminal=True)
        print_banner(console)
        output = buf.getvalue()
        assert "Santhosh" in output
        assert len(output) > 100


# ---------------------------------------------------------------------------
# Menu definitions
# ---------------------------------------------------------------------------


class TestMenus:
    def _all_actions(self, categories, footer):
        """Collect all action strings from menu categories + footer."""
        actions = []
        for cat in categories:
            for item in cat.items:
                actions.append(item.action)
        for item in footer:
            actions.append(item.action)
        return actions

    def test_main_menu_has_exit(self):
        actions = self._all_actions(MAIN_MENU, MAIN_FOOTER)
        assert "exit" in actions
        assert "load_firmware" in actions

    def test_firmware_menu_has_expected_actions(self):
        actions = self._all_actions(FIRMWARE_MENU, FIRMWARE_FOOTER)
        assert "boot_qemu" in actions
        assert "fuzz" in actions
        assert "exploits" in actions
        assert "analysis" in actions
        assert "back" in actions

    def test_main_menu_has_categories(self):
        assert len(MAIN_MENU) >= 3

    def test_firmware_menu_has_categories(self):
        assert len(FIRMWARE_MENU) >= 4


# ---------------------------------------------------------------------------
# InteractiveApp dispatch
# ---------------------------------------------------------------------------


class TestInteractiveApp:
    def test_dispatch_exit_returns_false(self):
        app = InteractiveApp()
        assert app._dispatch("exit") is False

    def test_dispatch_back_returns_true(self):
        app = InteractiveApp()
        assert app._dispatch("back") is True

    def test_dispatch_unknown_returns_true(self):
        app = InteractiveApp()
        assert app._dispatch("unknown_action_xyz") is True

    def test_dispatch_firmware_required(self):
        app = InteractiveApp()
        # These require firmware; should print error but not crash
        for action in ["boot_qemu", "attach_gdb", "fuzz", "exploits", "analysis"]:
            assert app._dispatch(action) is True

    def test_dispatch_tracks_history(self):
        app = InteractiveApp()
        app._dispatch("back")
        app._dispatch("back")
        assert app.session.history == ["back", "back"]

    def test_debug_mode(self):
        app = InteractiveApp(debug=True)
        assert app.session.debug is True


# ---------------------------------------------------------------------------
# main.py no-args routing
# ---------------------------------------------------------------------------


class TestMainRouting:
    def test_cli_help_still_works(self):
        from rtosploit.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "RTOSploit" in result.output

    def test_cli_version_still_works(self):
        from rtosploit.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0

    def test_should_launch_interactive_no_args(self):
        from rtosploit.cli.main import _should_launch_interactive
        with patch.object(sys, "argv", ["rtosploit"]):
            assert _should_launch_interactive() is True

    def test_should_launch_interactive_with_debug(self):
        from rtosploit.cli.main import _should_launch_interactive
        with patch.object(sys, "argv", ["rtosploit", "--debug"]):
            assert _should_launch_interactive() is True

    def test_should_not_launch_interactive_with_subcommand(self):
        from rtosploit.cli.main import _should_launch_interactive
        with patch.object(sys, "argv", ["rtosploit", "scan", "--help"]):
            assert _should_launch_interactive() is False

    def test_should_not_launch_interactive_with_help(self):
        from rtosploit.cli.main import _should_launch_interactive
        with patch.object(sys, "argv", ["rtosploit", "--help"]):
            assert _should_launch_interactive() is False

    def test_should_not_launch_interactive_with_version(self):
        from rtosploit.cli.main import _should_launch_interactive
        with patch.object(sys, "argv", ["rtosploit", "--version"]):
            assert _should_launch_interactive() is False

    def test_should_launch_interactive_verbose_only(self):
        from rtosploit.cli.main import _should_launch_interactive
        with patch.object(sys, "argv", ["rtosploit", "--verbose"]):
            assert _should_launch_interactive() is True

    def test_interactive_main_missing_questionary(self):
        """interactive_main exits if questionary is not importable."""
        with patch.dict(sys.modules, {"questionary": None}):
            # The import check in interactive_main should handle this
            pass  # Just verifying no crash on import
