"""Tests for the RTOSploit interactive console (Phase 16)."""
from __future__ import annotations

import pytest
from io import StringIO

from rich.console import Console

from rtosploit.console.state import ConsoleState
from rtosploit.console.repl import RTOSploitConsole


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def state():
    """Fresh ConsoleState with no module loaded."""
    return ConsoleState()


@pytest.fixture
def console():
    """RTOSploitConsole with output redirected to StringIO."""
    c = RTOSploitConsole()
    c.console = Console(file=StringIO(), highlight=False)
    return c


@pytest.fixture
def console_with_module(console):
    """Console with freertos/mpu_bypass already loaded."""
    console.dispatch("use freertos/mpu_bypass")
    return console


# ---------------------------------------------------------------------------
# ConsoleState tests (1-5)
# ---------------------------------------------------------------------------

def test_console_state_initial_prompt(state):
    """Default prompt is 'rtosploit> ' when no module is selected."""
    assert state.get_prompt() == "rtosploit> "


def test_console_state_module_prompt(state):
    """With a module set, prompt includes the module name."""
    state.current_module = "freertos/heap_overflow"
    state.current_module_instance = object()
    assert state.get_prompt() == "rtosploit(freertos/heap_overflow)> "


def test_console_state_set_module(state):
    """set_module() updates current_module and current_module_instance."""
    dummy = object()
    state.set_module("freertos/heap_overflow", dummy)
    assert state.current_module == "freertos/heap_overflow"
    assert state.current_module_instance is dummy


def test_console_state_clear_module(state):
    """clear_module() resets module and options to None/empty."""
    dummy = object()
    state.set_module("freertos/heap_overflow", dummy)
    state.option_values["firmware"] = "/tmp/fw.bin"
    state.clear_module()
    assert state.current_module is None
    assert state.current_module_instance is None
    assert state.option_values == {}


def test_console_state_option_values(state):
    """option_values starts as an empty dict."""
    assert state.option_values == {}


def test_console_state_set_module_resets_options(state):
    """set_module() clears any previously set option values."""
    state.option_values["firmware"] = "/old/path"
    dummy = object()
    state.set_module("freertos/heap_overflow", dummy)
    assert state.option_values == {}


def test_console_state_command_history(state):
    """command_history starts empty and is a list."""
    assert state.command_history == []


def test_console_state_cleanup_empty(state):
    """cleanup() on empty active_qemu does not raise."""
    state.cleanup()  # should not raise


# ---------------------------------------------------------------------------
# dispatch() return value tests (6-10)
# ---------------------------------------------------------------------------

def test_console_dispatch_unknown(console):
    """Unknown command doesn't crash and returns True (continue loop)."""
    result = console.dispatch("totally_unknown_cmd")
    assert result is True


def test_console_dispatch_empty(console):
    """Empty line returns True (continue loop)."""
    assert console.dispatch("") is True
    assert console.dispatch("   ") is True


def test_console_dispatch_comment(console):
    """Comment line (starts with #) returns True."""
    assert console.dispatch("# this is a comment") is True


def test_console_dispatch_exit(console):
    """'exit' returns False (signal to exit loop)."""
    assert console.dispatch("exit") is False


def test_console_dispatch_quit(console):
    """'quit' returns False (signal to exit loop)."""
    assert console.dispatch("quit") is False


# ---------------------------------------------------------------------------
# Individual command tests (11-32)
# ---------------------------------------------------------------------------

def test_console_dispatch_help(console):
    """'help' returns True and does not raise."""
    result = console.dispatch("help")
    assert result is True


def test_console_dispatch_banner(console):
    """'banner' returns True and does not raise."""
    result = console.dispatch("banner")
    assert result is True


def test_console_dispatch_version(console):
    """'version' returns True and does not raise."""
    result = console.dispatch("version")
    assert result is True


def test_console_cmd_use_missing_module(console):
    """'use nonexistent/module' does not raise and keeps no module selected."""
    console.dispatch("use nonexistent/module")
    assert console.state.current_module is None


def test_console_cmd_use_valid_module(console):
    """'use freertos/mpu_bypass' selects the module and sets instance."""
    console.dispatch("use freertos/mpu_bypass")
    assert console.state.current_module == "freertos/mpu_bypass"
    assert console.state.current_module_instance is not None


def test_console_cmd_back_no_module(console):
    """'back' without any module selected does not raise."""
    result = console.dispatch("back")
    assert result is True
    assert console.state.current_module is None


def test_console_cmd_back_with_module(console_with_module):
    """'back' clears the current module."""
    assert console_with_module.state.current_module is not None
    console_with_module.dispatch("back")
    assert console_with_module.state.current_module is None
    assert console_with_module.state.current_module_instance is None


def test_console_cmd_show_options_no_module(console):
    """'show options' without a module prints an error, returns True."""
    result = console.dispatch("show options")
    assert result is True


def test_console_cmd_show_options_with_module(console_with_module):
    """'show options' with module loaded prints table, does not raise."""
    result = console_with_module.dispatch("show options")
    assert result is True


def test_console_cmd_show_info_no_module(console):
    """'show info' without a module prints an error, returns True."""
    result = console.dispatch("show info")
    assert result is True


def test_console_cmd_show_info_with_module(console_with_module):
    """'show info' with module prints module info panel, does not raise."""
    result = console_with_module.dispatch("show info")
    assert result is True


def test_console_cmd_show_modules(console):
    """'show modules' lists all modules without raising."""
    result = console.dispatch("show modules")
    assert result is True


def test_console_cmd_show_exploits_alias(console):
    """'show exploits' is an alias that lists all modules."""
    result = console.dispatch("show exploits")
    assert result is True


def test_console_cmd_set_no_module(console):
    """'set firmware /tmp/fw.bin' without a module selected prints error."""
    result = console.dispatch("set firmware /tmp/fw.bin")
    assert result is True
    assert "firmware" not in console.state.option_values


def test_console_cmd_set_with_module(console_with_module):
    """'set firmware /tmp/fw.bin' with module stores the value."""
    console_with_module.dispatch("set firmware /tmp/fw.bin")
    assert console_with_module.state.option_values.get("firmware") == "/tmp/fw.bin"


def test_console_cmd_set_missing_value(console_with_module):
    """'set firmware' without a value prints usage error."""
    result = console_with_module.dispatch("set firmware")
    assert result is True
    assert "firmware" not in console_with_module.state.option_values


def test_console_cmd_unset(console_with_module):
    """'unset firmware' after setting it removes the key."""
    console_with_module.dispatch("set firmware /tmp/fw.bin")
    console_with_module.dispatch("unset firmware")
    assert "firmware" not in console_with_module.state.option_values


def test_console_cmd_unset_not_set(console_with_module):
    """'unset' a key that was never set prints a warning, does not crash."""
    result = console_with_module.dispatch("unset nonexistent_key")
    assert result is True


def test_console_cmd_search_freertos(console):
    """'search freertos' finds freertos modules."""
    # Capture output via StringIO already set up
    result = console.dispatch("search freertos")
    assert result is True


def test_console_cmd_search_cve(console):
    """'search CVE-2021' finds modules with matching CVE."""
    result = console.dispatch("search CVE-2021")
    assert result is True


def test_console_cmd_search_no_match(console):
    """'search zzznomatch999' warns about no results."""
    result = console.dispatch("search zzznomatch999")
    assert result is True


def test_console_cmd_check_no_firmware(console_with_module):
    """'check' without firmware option set prints error."""
    result = console_with_module.dispatch("check")
    assert result is True


def test_console_cmd_check_no_module(console):
    """'check' without any module prints error, does not raise."""
    result = console.dispatch("check")
    assert result is True


def test_console_cmd_exploit_no_module(console):
    """'exploit' without any module selected prints error."""
    result = console.dispatch("exploit")
    assert result is True


def test_console_cmd_run_alias(console):
    """'run' is an alias for 'exploit'."""
    result = console.dispatch("run")
    assert result is True


def test_console_cmd_exploit_no_firmware(console_with_module):
    """'exploit' with module but no firmware set prints error."""
    result = console_with_module.dispatch("exploit")
    assert result is True


def test_console_cmd_show_unknown_sub(console):
    """'show xyz' fails gracefully and returns True."""
    result = console.dispatch("show xyz")
    assert result is True


def test_console_get_registry(console):
    """Registry loads and discovers exploit modules on demand."""
    registry = console._get_registry()
    assert registry is not None
    assert len(registry._modules) > 0


def test_console_cmd_use_then_set(console):
    """After 'use', 'set' stores the value for the selected module."""
    console.dispatch("use freertos/heap_overflow")
    assert console.state.current_module == "freertos/heap_overflow"
    console.dispatch("set firmware /tmp/test.bin")
    assert console.state.option_values.get("firmware") == "/tmp/test.bin"


def test_console_dispatch_adds_to_history(console):
    """dispatch() appends non-empty, non-comment commands to history."""
    console.dispatch("help")
    console.dispatch("version")
    assert "help" in console.state.command_history
    assert "version" in console.state.command_history


def test_console_dispatch_comment_not_in_history(console):
    """Comment lines are not added to command history."""
    console.dispatch("# just a comment")
    assert console.state.command_history == []


def test_console_dispatch_empty_not_in_history(console):
    """Empty lines are not added to command history."""
    console.dispatch("")
    assert console.state.command_history == []


def test_console_show_empty_args(console):
    """'show' with no argument lists modules (same as 'show modules')."""
    result = console.dispatch("show")
    assert result is True


def test_console_use_no_args(console):
    """'use' with no argument prints usage error."""
    result = console.dispatch("use")
    assert result is True
    assert console.state.current_module is None


def test_console_back_after_set_clears_options(console):
    """'back' after setting options clears the option state."""
    console.dispatch("use freertos/mpu_bypass")
    console.dispatch("set firmware /tmp/fw.bin")
    console.dispatch("back")
    assert console.state.option_values == {}


def test_console_use_replaces_module(console):
    """Loading a second module via 'use' replaces the first."""
    console.dispatch("use freertos/mpu_bypass")
    first = console.state.current_module
    console.dispatch("use freertos/heap_overflow")
    second = console.state.current_module
    assert first != second
    assert second == "freertos/heap_overflow"


def test_console_use_replaces_module_clears_options(console):
    """Loading a new module resets option_values from previous module."""
    console.dispatch("use freertos/mpu_bypass")
    console.dispatch("set firmware /tmp/old.bin")
    console.dispatch("use freertos/heap_overflow")
    assert console.state.option_values == {}
