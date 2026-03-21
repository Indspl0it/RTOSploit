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


def _show_version(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    """Custom --version callback that prints the ASCII banner."""
    if not value or ctx.resilient_parsing:
        return
    from rtosploit.interactive.banner import version_banner
    version_banner(console)
    ctx.exit()


@click.group()
@click.option(
    "--version", is_flag=True, is_eager=True, expose_value=False,
    callback=_show_version, help="Show version banner and exit.",
)
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable verbose (DEBUG) output.")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress info, show only warnings/errors.")
@click.option("--json", "output_json", is_flag=True, default=False, help="Output results as JSON.")
@click.option("--config", type=click.Path(exists=False), default=None, help="Path to .rtosploit.yaml config file.")
@click.option("--debug", is_flag=True, default=False, hidden=True, help="Enable debug mode (interactive).")
@click.pass_context
def cli(
    ctx: click.Context,
    verbose: bool,
    quiet: bool,
    output_json: bool,
    config: str | None,
    debug: bool,
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
from rtosploit.cli.commands.report import report
from rtosploit.cli.commands.triage import triage
from rtosploit.cli.commands.coverage import coverage
from rtosploit.cli.commands.cve import cve
from rtosploit.cli.commands.scan import scan
from rtosploit.cli.commands.rehost import rehost

cli.add_command(emulate)
cli.add_command(fuzz)
cli.add_command(exploit)
cli.add_command(payload)
cli.add_command(analyze)
cli.add_command(svd)
cli.add_command(vulnrange)
cli.add_command(console_cmd)
cli.add_command(report)
cli.add_command(triage)
cli.add_command(coverage)
cli.add_command(cve)
cli.add_command(scan)
cli.add_command(rehost)


def _should_launch_interactive() -> bool:
    """Check if we should launch interactive mode (no subcommand given)."""
    # Strip global flags to see if a subcommand is present
    args = sys.argv[1:]
    known_flags = {
        "--verbose", "-v", "--quiet", "-q", "--json", "--config", "--version", "--help",
        "--debug",
    }
    remaining = []
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if arg == "--config":
            skip_next = True  # --config takes a value
            continue
        if arg in known_flags:
            continue
        remaining.append(arg)

    return len(remaining) == 0 and "--help" not in args and "--version" not in args


def main() -> None:
    """Entry point wrapper with global exception handling.

    Launches interactive mode when invoked with no subcommand,
    or delegates to Click CLI for subcommands.
    """
    if _should_launch_interactive():
        debug = "--debug" in sys.argv or "--verbose" in sys.argv or "-v" in sys.argv
        from rtosploit.interactive.app import interactive_main
        interactive_main(debug=debug)
        return

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
