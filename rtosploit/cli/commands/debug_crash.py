"""rtosploit debug crash — replay crash inputs under GDB for post-mortem debugging."""
from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rtosploit.config import RTOSploitConfig
from rtosploit.emulation.qemu import QEMUInstance

console = Console()
err_console = Console(stderr=True)

# Known CFSR bit definitions for Cortex-M
_CFSR_BITS = {
    0: "IACCVIOL (instruction access violation)",
    1: "DACCVIOL (data access violation)",
    3: "MUNSTKERR (MemManage unstacking error)",
    4: "MSTKERR (MemManage stacking error)",
    7: "MMARVALID (MMFAR valid)",
    8: "IBUSERR (instruction bus error)",
    9: "PRECISERR (precise data bus error)",
    10: "IMPRECISERR (imprecise data bus error)",
    11: "UNSTKERR (BusFault unstacking error)",
    12: "STKERR (BusFault stacking error)",
    13: "LSPERR (lazy FP stacking bus error)",
    15: "BFARVALID (BFAR valid)",
    16: "UNDEFINSTR (undefined instruction)",
    17: "INVSTATE (invalid state)",
    18: "INVPC (invalid PC load)",
    19: "NOCP (no coprocessor)",
    24: "UNALIGNED (unaligned access)",
    25: "DIVBYZERO (divide by zero)",
}


def _decode_cfsr(cfsr: int) -> list[str]:
    """Decode CFSR register bits into human-readable strings."""
    flags = []
    for bit, name in _CFSR_BITS.items():
        if cfsr & (1 << bit):
            flags.append(name)
    return flags


def _load_crash_data(crash_path: str) -> tuple[dict, bytes]:
    """Load crash JSON and its associated input binary.

    Args:
        crash_path: Path to a crash JSON file or a directory containing crash files.

    Returns:
        Tuple of (crash_data dict, input_bytes).

    Raises:
        click.ClickException: If files are missing or invalid.
    """
    path = Path(crash_path)

    if path.is_dir():
        # Find all crash JSON files in the directory
        crash_files = sorted(path.glob("crash-*.json"), key=lambda p: p.stat().st_mtime)
        if not crash_files:
            raise click.ClickException(f"No crash JSON files found in {crash_path}")
        # Use the most recent
        json_path = crash_files[-1]
        err_console.print(
            f"[dim]Found {len(crash_files)} crash file(s), using most recent: {json_path.name}[/dim]"
        )
    elif path.is_file():
        json_path = path
    else:
        raise click.ClickException(f"Path does not exist: {crash_path}")

    # Load JSON
    try:
        with open(json_path) as f:
            crash_data = json.load(f)
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"Invalid JSON in {json_path}: {exc}")

    # Validate required fields
    required_fields = ["crash_id", "fault_type", "registers"]
    for field in required_fields:
        if field not in crash_data:
            raise click.ClickException(f"Missing required field '{field}' in crash JSON")

    # Load input binary
    input_file = crash_data.get("input_file")
    if input_file:
        bin_path = json_path.parent / input_file
    else:
        # Fallback: try <crash_id>.bin in same directory
        bin_path = json_path.parent / f"{crash_data['crash_id']}.bin"

    if not bin_path.exists():
        raise click.ClickException(f"Crash input binary not found: {bin_path}")

    input_bytes = bin_path.read_bytes()
    return crash_data, input_bytes


def _print_crash_context(crash_data: dict) -> None:
    """Print formatted crash context using rich."""
    # Header panel
    console.print(Panel(
        f"[bold]{crash_data['crash_id']}[/bold]\n"
        f"Fault type: [red]{crash_data.get('fault_type', 'unknown')}[/red]",
        title="[bold red]Crash Report[/bold red]",
        border_style="red",
        expand=False,
    ))

    # Registers table
    regs = crash_data.get("registers", {})
    if regs:
        table = Table(title="Registers", show_header=True, header_style="bold cyan")
        table.add_column("Register", style="bold")
        table.add_column("Value", style="green")
        for name, value in regs.items():
            table.add_row(name, f"0x{value:08x}" if isinstance(value, int) else str(value))
        console.print(table)

    # CFSR decoding
    cfsr = crash_data.get("cfsr")
    if cfsr is not None:
        flags = _decode_cfsr(cfsr)
        console.print(f"\n[bold]CFSR:[/bold] 0x{cfsr:08x}")
        if flags:
            for flag in flags:
                console.print(f"  [yellow]{flag}[/yellow]")
        else:
            console.print("  [dim](no recognized bits set)[/dim]")

    # Fault address
    fault_addr = crash_data.get("fault_address")
    if fault_addr is not None:
        console.print(f"\n[bold]Fault address:[/bold] 0x{fault_addr:08x}")

    # Backtrace
    backtrace = crash_data.get("backtrace", [])
    if backtrace:
        console.print("\n[bold]Backtrace:[/bold]")
        for i, addr in enumerate(backtrace):
            console.print(f"  #{i}: 0x{addr:08x}" if isinstance(addr, int) else f"  #{i}: {addr}")

    # Vector table offset
    vtor = crash_data.get("vtor")
    if vtor:
        console.print(f"\n[bold]VTOR:[/bold] 0x{vtor:08x}")

    # Stack dump
    stack_ptr = crash_data.get("stack_pointer", 0)
    stack_hex = crash_data.get("stack_dump", "")
    if stack_hex and stack_ptr:
        console.print(f"\n[bold]Stack (SP=0x{stack_ptr:08x}):[/bold]")
        raw = bytes.fromhex(stack_hex)
        for off in range(0, min(len(raw), 64), 4):
            word = int.from_bytes(raw[off:off+4], "little") if off + 4 <= len(raw) else 0
            console.print(f"  0x{stack_ptr + off:08x}: 0x{word:08x}")

    # Fault memory context
    fault_hex = crash_data.get("fault_context", "")
    fault_base = crash_data.get("fault_context_base", 0)
    if fault_hex and fault_base:
        console.print(f"\n[bold]Memory at fault (0x{fault_base:08x}):[/bold]")
        raw = bytes.fromhex(fault_hex)
        for off in range(0, min(len(raw), 64), 4):
            word = int.from_bytes(raw[off:off+4], "little") if off + 4 <= len(raw) else 0
            console.print(f"  0x{fault_base + off:08x}: 0x{word:08x}")

    # Input info
    input_size = crash_data.get("input_size")
    if input_size is not None:
        console.print(f"\n[bold]Input size:[/bold] {input_size} bytes")


@click.group("debug")
def debug():
    """Debug commands for post-mortem crash analysis."""
    pass


@debug.command("crash")
@click.argument("crash_path", type=click.Path(exists=True))
@click.option("--firmware", "-f", required=False, default=None, type=click.Path(exists=True),
              help="Path to firmware binary (.bin/.elf/.hex). Falls back to crash JSON firmware_path.")
@click.option("--machine", "-m", required=False, default=None, type=str,
              help="QEMU machine name (e.g. mps2-an385). Falls back to crash JSON machine_name.")
@click.option("--inject-addr", type=str, default=None,
              help="Memory address to inject crash input (hex). Falls back to crash JSON inject_addr.")
@click.pass_context
def crash(ctx, crash_path, firmware, machine, inject_addr):
    """Replay a crash input under GDB for post-mortem debugging.

    \b
    CRASH_PATH can be a crash JSON file or a directory containing crash files.
    When a directory is given, the most recent crash file is used.

    \b
    Example:
      rtosploit debug crash crashes/crash-w0-000001.json -f fw.elf -m mps2-an385
      rtosploit debug crash crashes/ -f fw.elf -m mps2-an385
      rtosploit debug crash crash.json -f fw.elf -m mps2-an385 --inject-addr 0x20020000
    """
    output_json = ctx.obj.get("output_json", False)

    # Load crash data
    crash_data, input_bytes = _load_crash_data(crash_path)

    # Resolve firmware from CLI or crash JSON
    if firmware is None:
        firmware = crash_data.get("firmware_path", "")
    if not firmware:
        raise click.ClickException(
            "No --firmware provided and crash JSON has no firmware_path. "
            "Pass --firmware explicitly."
        )
    if not Path(firmware).exists():
        raise click.ClickException(f"Firmware file not found: {firmware}")

    # Resolve machine from CLI or crash JSON
    if machine is None:
        machine = crash_data.get("machine_name", "")
    if not machine:
        raise click.ClickException(
            "No --machine provided and crash JSON has no machine_name. "
            "Pass --machine explicitly."
        )

    # Resolve inject address from CLI or crash JSON
    if inject_addr is None:
        inject_address = crash_data.get("inject_addr", 0x20010000)
        if isinstance(inject_address, str):
            inject_address = int(inject_address, 16)
    else:
        try:
            inject_address = int(inject_addr, 16)
        except ValueError:
            raise click.ClickException(f"Invalid hex address: {inject_addr}")

    if output_json:
        result = {
            "crash_id": crash_data.get("crash_id"),
            "fault_type": crash_data.get("fault_type"),
            "fault_address": crash_data.get("fault_address"),
            "registers": crash_data.get("registers"),
            "input_size": len(input_bytes),
            "inject_addr": hex(inject_address),
            "firmware": firmware,
            "machine": machine,
            "status": "loaded",
        }
        click.echo(json.dumps(result, indent=2))
        return

    # Print crash context
    _print_crash_context(crash_data)

    console.print("\n[bold green]Debug Session[/bold green]")
    console.print(f"  Firmware:     [cyan]{firmware}[/cyan]")
    console.print(f"  Machine:      [cyan]{machine}[/cyan]")
    console.print(f"  Inject addr:  [cyan]0x{inject_address:08x}[/cyan]")
    console.print(f"  Input size:   [cyan]{len(input_bytes)} bytes[/cyan]")

    err_console.print("\n[dim]Starting QEMU with GDB server (paused)...[/dim]")

    try:
        config = RTOSploitConfig()
        instance = QEMUInstance(config)
        instance.start(
            firmware_path=firmware,
            machine_name=machine,
            gdb=True,
            paused=True,
        )

        pid = instance._process.pid if instance._process else "?"
        console.print(f"\n[green]QEMU running[/green] (PID: {pid})")

        gdb_client = instance.gdb
        if gdb_client is None:
            from rtosploit.errors import OperationError
            raise OperationError("GDB client not initialized — QEMU may have failed to start")

        # Inject crash input into target memory
        err_console.print(f"[dim]Injecting {len(input_bytes)} bytes at 0x{inject_address:08x}...[/dim]")
        gdb_client.write_memory(inject_address, input_bytes)

        # Set breakpoint at fault address if available
        fault_addr = crash_data.get("fault_address")
        if fault_addr is not None:
            err_console.print(f"[dim]Setting breakpoint at 0x{fault_addr:08x}...[/dim]")
            gdb_client.set_breakpoint(fault_addr)

        # Attempt live backtrace if crash JSON had none
        backtrace = crash_data.get("backtrace", [])
        if not backtrace and instance.gdb is not None:
            err_console.print("[dim]Live backtrace available after execution reaches fault address[/dim]")

        console.print(
            Panel(
                "[bold]GDB server ready on localhost:1234[/bold]\n\n"
                "Attach with:\n"
                "  [cyan]gdb-multiarch -ex 'target remote localhost:1234'[/cyan]\n\n"
                "Press [bold]Ctrl+C[/bold] to stop.",
                title="[bold green]Debug Session Active[/bold green]",
                border_style="green",
                expand=False,
            )
        )

        try:
            # Wait for QEMU process to exit or Ctrl+C
            if instance._process:
                instance._process.wait()
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping debug session...[/yellow]")
        finally:
            instance.stop()

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
    except Exception as exc:
        console.print(f"[red]Debug session error: {exc}[/red]")
        if ctx.obj.get("verbose"):
            import traceback
            traceback.print_exc()
        raise SystemExit(1)
