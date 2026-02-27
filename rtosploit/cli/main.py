"""CLI entry point for RTOSploit."""

from __future__ import annotations

import sys
import traceback

import click
from rich.console import Console
from rich.panel import Panel

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
from rtosploit.cli.commands.console_cmd import console_cmd

cli.add_command(emulate)
cli.add_command(fuzz)
cli.add_command(exploit)
cli.add_command(payload)
cli.add_command(analyze)
cli.add_command(svd)
cli.add_command(vulnrange)
cli.add_command(console_cmd)


def main() -> None:
    """Entry point wrapper with global exception handling."""
    try:
        cli(standalone_mode=False)
    except KeyboardInterrupt:
        err_console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(130)
    except click.Abort:
        err_console.print("\n[yellow]Aborted[/yellow]")
        sys.exit(1)
    except click.exceptions.Exit as exc:
        sys.exit(exc.exit_code)
    except click.ClickException as exc:
        exc.show()
        sys.exit(exc.exit_code)
    except Exception as exc:
        # Determine if --verbose was passed (check sys.argv before Click parses)
        verbose = "--verbose" in sys.argv or "-v" in sys.argv

        error_body = f"[bold red]{type(exc).__name__}[/bold red]: {exc}"
        if verbose:
            tb = traceback.format_exception(type(exc), exc, exc.__traceback__)
            error_body += "\n\n[dim]" + "".join(tb).rstrip() + "[/dim]"

        err_console.print(
            Panel(
                error_body,
                title="[bold red]Error[/bold red]",
                border_style="red",
                expand=False,
            )
        )
        sys.exit(1)
