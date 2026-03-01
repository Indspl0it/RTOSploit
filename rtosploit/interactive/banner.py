"""ASCII banner and version display for interactive mode."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from rtosploit import __version__


BANNER_ART = r"""
 ____  _____ ___  ____        _       _ _
|  _ \|_   _/ _ \/ ___| _ __ | | ___ (_) |_
| |_) | | || | | \___ \| '_ \| |/ _ \| | __|
|  _ <  | || |_| |___) | |_) | | (_) | | |_
|_| \_\ |_| \___/|____/| .__/|_|\___/|_|\__|
                        |_|
""".strip()

SUPPORTED_RTOS = "FreeRTOS  Zephyr  ThreadX  RT-Thread  NuttX  RIOT  embOS  uC/OS"
SUPPORTED_ARCH = "ARM Cortex-M  RISC-V RV32  ARMv8-M"


def print_banner(console: Console | None = None) -> None:
    """Print the RTOSploit banner with version info."""
    if console is None:
        console = Console()

    # Build colored banner text
    lines = BANNER_ART.split("\n")
    banner_text = Text()
    colors = ["bold red", "bold yellow", "bold green", "bold cyan", "bold blue"]
    for i, line in enumerate(lines):
        color = colors[i % len(colors)]
        banner_text.append(line, style=color)
        if i < len(lines) - 1:
            banner_text.append("\n")

    banner_text.append("\n\n")
    banner_text.append("  RTOS Firmware Security Testing Framework\n", style="bold white")
    banner_text.append(f"\n  RTOS   ", style="dim")
    banner_text.append(SUPPORTED_RTOS, style="dim white")
    banner_text.append(f"\n  Arch   ", style="dim")
    banner_text.append(SUPPORTED_ARCH, style="dim white")

    panel = Panel(
        banner_text,
        title=f"[bold]RTOSploit[/bold]  v{__version__}",
        border_style="cyan",
        expand=False,
        padding=(1, 3),
    )
    console.print(panel)
