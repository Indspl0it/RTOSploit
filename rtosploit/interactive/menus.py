"""Rich-based menu rendering for interactive mode."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from rich.console import Console


@dataclass
class MenuItem:
    """A selectable menu item."""
    key: str
    label: str
    description: str
    action: str


@dataclass
class MenuCategory:
    """A category grouping menu items."""
    name: str
    items: list[MenuItem]


# ---------------------------------------------------------------------------
# Main Menu (no firmware loaded)
# ---------------------------------------------------------------------------

MAIN_MENU: list[MenuCategory] = [
    MenuCategory("FIRMWARE", [
        MenuItem("1", "Load Firmware", "Load and fingerprint a firmware binary", "load_firmware"),
    ]),
    MenuCategory("SECURITY TESTING", [
        MenuItem("2", "Quick Scan", "Full CI pipeline scan on any firmware", "quick_scan"),
        MenuItem("3", "Scanner Console", "Metasploit-style interactive REPL", "console"),
    ]),
    MenuCategory("INTELLIGENCE", [
        MenuItem("4", "Search CVE Database", "Search by CVE ID, keyword, or RTOS", "cve_search"),
        MenuItem("5", "VulnRange Labs", "Practice CVE exploitation with guided challenges", "vulnrange"),
    ]),
    MenuCategory("TOOLS", [
        MenuItem("6", "SVD Operations", "Parse, generate stubs, download SVD files", "svd"),
        MenuItem("7", "Generate Payload", "Create shellcode or ROP chains", "payload"),
    ]),
]

MAIN_FOOTER: list[MenuItem] = [
    MenuItem("s", "Settings", "", "settings"),
    MenuItem("q", "Exit", "", "exit"),
]

# ---------------------------------------------------------------------------
# Firmware Menu (firmware loaded)
# ---------------------------------------------------------------------------

FIRMWARE_MENU: list[MenuCategory] = [
    MenuCategory("EMULATION", [
        MenuItem("1", "Boot in QEMU", "Start firmware emulation", "boot_qemu"),
        MenuItem("2", "Attach GDB", "Connect debugger to running instance", "attach_gdb"),
        MenuItem("3", "Rehost Firmware", "Run with HAL peripheral intercepts", "rehost"),
    ]),
    MenuCategory("SECURITY TESTING", [
        MenuItem("4", "Fuzz Firmware", "Grey-box fuzzing with live dashboard", "fuzz"),
        MenuItem("5", "Run Vulnerability Scanners", "Browse and execute vulnerability scanners", "exploits"),
        MenuItem("6", "Full Security Scan", "Fingerprint + CVE + fuzz + triage + report", "full_scan"),
    ]),
    MenuCategory("ANALYSIS", [
        MenuItem("7", "Static Analysis", "RTOS fingerprint, heap, MPU, strings", "analysis"),
        MenuItem("8", "CVE Correlation", "Match firmware against known CVEs", "cve_correlate"),
        MenuItem("9", "Triage Crashes", "Classify exploitability, minimize inputs", "triage"),
    ]),
    MenuCategory("OUTPUT", [
        MenuItem("10", "View Coverage", "Visualize fuzzing coverage", "coverage"),
        MenuItem("11", "Generate Reports", "SARIF and/or HTML reports", "reports"),
        MenuItem("12", "Generate Payload", "Shellcode or ROP chains for this target", "payload"),
    ]),
]

FIRMWARE_FOOTER: list[MenuItem] = [
    MenuItem("l", "Load Different Firmware", "", "load_firmware"),
    MenuItem("b", "Back to Main Menu", "", "back"),
]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _render_menu(
    categories: list[MenuCategory],
    footer: list[MenuItem],
    console: Console,
) -> dict[str, str]:
    """Render a categorized menu and return key-to-action mapping."""
    key_map: dict[str, str] = {}

    for cat in categories:
        console.print(f"\n  [bold cyan]{cat.name}[/bold cyan]")
        console.print()
        for item in cat.items:
            key_map[item.key] = item.action
            desc = f"[dim]{item.description}[/dim]" if item.description else ""
            console.print(
                f"    [bold white]{item.key:>2}[/bold white]  {item.label:<26} {desc}"
            )

    # Footer items separated by a blank line
    console.print()
    for item in footer:
        key_map[item.key] = item.action
        console.print(f"    [dim] {item.key}[/dim]  [dim]{item.label}[/dim]")

    console.print()
    return key_map


def _prompt_selection(key_map: dict[str, str], console: Console) -> str | None:
    """Prompt for a selection key and return the corresponding action."""
    try:
        choice = console.input("  [bold]>[/bold] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return None

    if not choice:
        return None

    action = key_map.get(choice)
    if action is None:
        console.print("  [yellow]Invalid selection.[/yellow]")
        return _prompt_selection(key_map, console)

    return action


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def prompt_main_menu(console: Console) -> str | None:
    """Render main menu and return selected action."""
    key_map = _render_menu(MAIN_MENU, MAIN_FOOTER, console)
    return _prompt_selection(key_map, console)


def prompt_firmware_menu(
    console: Console,
    firmware: Optional[Any] = None,
) -> str | None:
    """Render firmware menu and return selected action."""
    if firmware:
        name = firmware.path.name
        rtos = f"{firmware.rtos_name} {firmware.rtos_version}".strip()
        arch = firmware.arch_name
        machine = firmware.machine or "unknown"
        console.print(
            f"\n  [bold cyan]Loaded:[/bold cyan] {name} "
            f"[dim]|[/dim] {rtos} "
            f"[dim]|[/dim] {arch} "
            f"[dim]|[/dim] {machine}",
        )

    key_map = _render_menu(FIRMWARE_MENU, FIRMWARE_FOOTER, console)
    return _prompt_selection(key_map, console)
