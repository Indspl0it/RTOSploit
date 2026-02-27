"""CLI entry point for RTOSploit."""

from __future__ import annotations

import sys
import click
from rich.console import Console

from .. import __version__

console = Console()
err_console = Console(stderr=True)


@click.group()
@click.version_option(version=__version__, prog_name="rtosploit")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable verbose (DEBUG) output.")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress info, show only warnings/errors.")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output results as JSON.")
@click.option("--config", type=click.Path(exists=False), default=None, help="Path to .rtosploit.yaml config file.")
@click.pass_context
def cli(
    ctx: click.Context,
    verbose: bool,
    quiet: bool,
    output_json: bool,
    config: str | None,
) -> None:
    """RTOSploit — RTOS Exploitation & Bare-Metal Fuzzing Framework.

    \b
    Supports: FreeRTOS, ThreadX, Zephyr
    Targets:  ARM Cortex-M (M3/M4/M7/M33), RISC-V (RV32I)
    Mode:     Software-only (QEMU-based, no hardware required)
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    ctx.obj["output_json"] = output_json
    ctx.obj["config"] = config

    import logging
    if verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    elif quiet:
        logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


# Register all subcommands
from rtosploit.cli.commands.emulate import emulate
from rtosploit.cli.commands.fuzz import fuzz
from rtosploit.cli.commands.exploit import exploit
from rtosploit.cli.commands.payload import payload
from rtosploit.cli.commands.analyze import analyze
from rtosploit.cli.commands.svd import svd
from rtosploit.cli.commands.vulnrange import vulnrange

cli.add_command(emulate)
cli.add_command(fuzz)
cli.add_command(exploit)
cli.add_command(payload)
cli.add_command(analyze)
cli.add_command(svd)
cli.add_command(vulnrange)
