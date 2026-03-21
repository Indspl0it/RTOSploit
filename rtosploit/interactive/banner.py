"""ASCII banner and version display for interactive mode."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from rtosploit import __version__


# Block-style filled ASCII art — each letter is 7 lines tall
# Inspired by ANSI Shadow / Blocky fonts used by security tools
# Split into RTOS (red/magenta gradient) and ploit (cyan/blue)

_RTOS_LINES = [
    " ██████╗ ████████╗ ██████╗ ███████╗",
    " ██╔══██╗╚══██╔══╝██╔═══██╗██╔════╝",
    " ██████╔╝   ██║   ██║   ██║███████╗",
    " ██╔══██╗   ██║   ██║   ██║╚════██║",
    " ██║  ██║   ██║   ╚██████╔╝███████║",
    " ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚══════╝",
]

_PLOIT_LINES = [
    " ██████╗ ██╗      ██████╗ ██╗████████╗",
    " ██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝",
    " ██████╔╝██║     ██║   ██║██║   ██║   ",
    " ██╔═══╝ ██║     ██║   ██║██║   ██║   ",
    " ██║     ███████╗╚██████╔╝██║   ██║   ",
    " ╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ",
]

SUPPORTED_RTOS = "FreeRTOS  ThreadX  Zephyr  ESP-IDF  RTEMS"
SUPPORTED_ARCH = "ARM Cortex-M  RISC-V  Xtensa  MIPS  AArch64"

# Color styles — gradient-like effect using different shades per line
_RTOS_STYLES = [
    "bold bright_red",
    "bold red",
    "bold bright_magenta",
    "bold magenta",
    "bold red",
    "bold bright_red",
]

_PLOIT_STYLES = [
    "bold bright_cyan",
    "bold cyan",
    "bold bright_blue",
    "bold blue",
    "bold cyan",
    "bold bright_cyan",
]

_S_STYLE = "bold bright_green"


def _colorize_banner() -> Text:
    """Build the banner with filled block letters and color gradient."""
    text = Text()
    for i in range(len(_RTOS_LINES)):
        rtos_style = _RTOS_STYLES[i % len(_RTOS_STYLES)]
        ploit_style = _PLOIT_STYLES[i % len(_PLOIT_STYLES)]
        text.append(_RTOS_LINES[i], style=rtos_style)
        text.append(_PLOIT_LINES[i], style=ploit_style)
        if i < len(_RTOS_LINES) - 1:
            text.append("\n")
    return text


def print_banner(console: Console | None = None) -> None:
    """Print the RTOSploit banner with version info."""
    if console is None:
        console = Console()

    banner_text = _colorize_banner()

    banner_text.append("\n\n")
    banner_text.append(
        "  RTOS Exploitation & Bare-Metal Fuzzing Framework\n",
        style="bold white",
    )
    banner_text.append(f"  v{__version__}", style="bold yellow")
    banner_text.append("  |  ", style="dim white")
    banner_text.append("by Santhosh Ballikonda", style="bold white")
    banner_text.append("\n\n")
    banner_text.append("  RTOS  ", style="bold green")
    banner_text.append(SUPPORTED_RTOS, style="white")
    banner_text.append("\n  Arch  ", style="bold green")
    banner_text.append(SUPPORTED_ARCH, style="white")

    panel = Panel(
        banner_text,
        border_style="bright_red",
        expand=False,
        padding=(1, 1),
    )
    console.print(panel)


def version_banner(console: Console | None = None) -> None:
    """Print a compact banner for --version output."""
    if console is None:
        console = Console()

    banner_text = _colorize_banner()
    banner_text.append("\n\n")
    banner_text.append(
        "  RTOS Exploitation & Bare-Metal Fuzzing Framework\n",
        style="bold white",
    )
    banner_text.append(f"  v{__version__}", style="bold yellow")
    banner_text.append("  |  ", style="dim white")
    banner_text.append("by Santhosh Ballikonda\n", style="bold white")

    console.print(banner_text)
