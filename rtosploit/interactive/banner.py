"""ASCII banner and version display for interactive mode."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from rtosploit import __version__


# Figlet "slant" style — wide block letters
BANNER_ART = r"""
    ____  __________  ____        __      _ __
   / __ \/_  __/ __ \/ __/____   / /___  (_) /_
  / /_/ / / / / / / /\ \/ __ \ / / __ \/ / __/
 / _, _/ / / / /_/ /___/ /_/ // / /_/ / / /_
/_/ |_| /_/  \____//____/ .___//_/\____/_/\__/
                        /_/
""".strip("\n")

SUPPORTED_RTOS = "FreeRTOS  Zephyr  ThreadX  RT-Thread  NuttX  RIOT  embOS  uC/OS"
SUPPORTED_ARCH = "ARM Cortex-M  RISC-V RV32  ARMv8-M"

# Color scheme: red/orange gradient for "RTOS", cyan/blue for "ploit"
# The split point in each line is roughly column 30 where "S" ends and "ploit" begins
_RTOS_STYLE = "bold red"
_PLOIT_STYLE = "bold cyan"
_SPLIT_COLS = [30, 30, 30, 30, 30, 24]  # per-line split points


def _colorize_banner() -> Text:
    """Build the banner with a two-tone color split: red RTOS, cyan ploit."""
    lines = BANNER_ART.split("\n")
    text = Text()
    for i, line in enumerate(lines):
        split = _SPLIT_COLS[i] if i < len(_SPLIT_COLS) else 30
        left = line[:split]
        right = line[split:]
        text.append(left, style=_RTOS_STYLE)
        text.append(right, style=_PLOIT_STYLE)
        if i < len(lines) - 1:
            text.append("\n")
    return text


def print_banner(console: Console | None = None) -> None:
    """Print the RTOSploit banner with version info."""
    if console is None:
        console = Console()

    banner_text = _colorize_banner()

    banner_text.append("\n\n")
    banner_text.append(
        "    RTOS Exploitation & Bare-Metal Fuzzing Framework\n",
        style="bold white",
    )
    banner_text.append(f"    v{__version__}", style="bold yellow")
    banner_text.append("  |  ", style="dim")
    banner_text.append("by Santhosh Ballikonda", style="dim white")
    banner_text.append("\n\n")
    banner_text.append("    RTOS  ", style="dim")
    banner_text.append(SUPPORTED_RTOS, style="dim white")
    banner_text.append("\n    Arch  ", style="dim")
    banner_text.append(SUPPORTED_ARCH, style="dim white")

    panel = Panel(
        banner_text,
        title="[bold red]RTOSploit[/bold red]",
        border_style="red",
        expand=False,
        padding=(1, 2),
    )
    console.print(panel)


def version_banner(console: Console | None = None) -> None:
    """Print a compact banner for --version output."""
    if console is None:
        console = Console()

    banner_text = _colorize_banner()
    banner_text.append("\n\n")
    banner_text.append(
        "    RTOS Exploitation & Bare-Metal Fuzzing Framework\n",
        style="bold white",
    )
    banner_text.append(f"    v{__version__}", style="bold yellow")
    banner_text.append("  |  ", style="dim")
    banner_text.append("by Santhosh Ballikonda\n", style="dim white")

    console.print(banner_text)
