"""rtosploit rehost — run firmware with peripheral model intercepts."""

import click
from rich.console import Console

console = Console()


@click.command("rehost")
@click.option("--firmware", "-f", required=True, type=click.Path(exists=True), help="Firmware binary (ELF or raw)")
@click.option("--machine", "-m", type=str, default="auto", help="QEMU machine name (default: auto-detect)")
@click.option("--peripheral-config", "-p", type=click.Path(exists=True), default=None, help="YAML peripheral config file")
@click.option("--auto/--no-auto", "auto_mode", default=None, help="Auto-detect peripherals (default: auto when no config)")
@click.option("--save-config", type=click.Path(), default=None, help="Save auto-generated config to PATH")
@click.option("--svd", type=click.Path(exists=True), default=None, help="Override SVD file path")
@click.option("--engine", type=click.Choice(["qemu", "unicorn"]), default="qemu", help="Emulation engine (default: qemu)")
@click.option("--timeout", "-t", type=int, default=0, help="Timeout in seconds (0=unlimited)")
@click.pass_context
def rehost(ctx, firmware, machine, peripheral_config, auto_mode, save_config, svd, engine, timeout):
    """Rehost firmware with HAL function intercepts.

    \b
    Example:
      rtosploit rehost --firmware fw.elf
      rtosploit rehost --firmware fw.elf --machine stm32f4 \\
          --peripheral-config configs/peripherals/stm32f4_hal.yaml
      rtosploit rehost -f fw.elf -m mps2-an385 -p my_config.yaml -t 60
      rtosploit rehost -f fw.elf --auto --save-config my_config.yaml
      rtosploit rehost -f fw.elf --svd STM32F407.svd --engine unicorn
    """
    import json

    # Resolve auto_mode: explicit flag wins, otherwise auto when no config given
    if auto_mode is None:
        auto_mode = peripheral_config is None

    output_json = ctx.obj.get("output_json", False)

    if output_json:
        _rehost_json(ctx, firmware, machine, peripheral_config, auto_mode, save_config, svd, engine, timeout)
        return

    _rehost_rich(ctx, firmware, machine, peripheral_config, auto_mode, save_config, svd, engine, timeout)


def _rehost_json(ctx, firmware, machine, peripheral_config, auto_mode, save_config, svd, engine, timeout):
    """JSON output path for rehost command."""
    import json
    from rtosploit.config import RTOSploitConfig
    from rtosploit.emulation.qemu import QEMUInstance
    from rtosploit.peripherals.rehost import RehostingEngine, build_unimplemented_device_args

    config = RTOSploitConfig()
    engine_obj = RehostingEngine(
        firmware_path=firmware,
        machine_name=machine,
        peripheral_config=peripheral_config,
        config=config,
        auto_mode=auto_mode,
    )

    qemu = QEMUInstance(config)
    extra_args = build_unimplemented_device_args()

    try:
        effective_machine = engine_obj.machine_name
        qemu.start(
            firmware, effective_machine,
            gdb=True, paused=True,
            extra_qemu_args=extra_args,
        )
        dispatcher = engine_obj.setup(qemu)
        effective_machine = engine_obj.machine_name  # may have been resolved by auto_setup

        result = {
            "firmware": firmware,
            "machine": effective_machine,
            "peripheral_config": peripheral_config,
            "auto_mode": auto_mode,
            "engine": engine,
            "status": "ready",
            "intercepts": len(dispatcher.registered_addresses),
        }

        if auto_mode:
            result["auto_summary"] = engine_obj.get_auto_summary()

        if save_config:
            _save_auto_config(engine_obj, save_config)
            result["saved_config"] = save_config

        if timeout > 0:
            engine_obj.run_interactive(qemu, timeout=timeout)
            result["status"] = "completed"
            result["stats"] = dispatcher.stats

        click.echo(json.dumps(result, indent=2, default=str))
    finally:
        qemu.stop()


def _rehost_rich(ctx, firmware, machine, peripheral_config, auto_mode, save_config, svd, engine, timeout):
    """Rich console output path for rehost command."""
    from rtosploit.config import RTOSploitConfig
    from rtosploit.emulation.qemu import QEMUInstance
    from rtosploit.peripherals.rehost import RehostingEngine, build_unimplemented_device_args

    console.print("[bold green]RTOSploit Firmware Rehosting[/bold green]")
    console.print(f"  Firmware:     [cyan]{firmware}[/cyan]")
    if auto_mode:
        console.print(f"  Mode:         [cyan]auto-detect[/cyan]")
        if machine != "auto":
            console.print(f"  Machine:      [cyan]{machine}[/cyan] (override)")
    else:
        console.print(f"  Machine:      [cyan]{machine}[/cyan]")
        console.print(f"  Periph config:[cyan]{peripheral_config}[/cyan]")
    console.print(f"  Engine:       [cyan]{engine}[/cyan]")
    if svd:
        console.print(f"  SVD override: [cyan]{svd}[/cyan]")
    if timeout:
        console.print(f"  Timeout:      [cyan]{timeout}s[/cyan]")
    console.print()

    config = RTOSploitConfig()
    engine_obj = RehostingEngine(
        firmware_path=firmware,
        machine_name=machine,
        peripheral_config=peripheral_config,
        config=config,
        auto_mode=auto_mode,
    )

    qemu = QEMUInstance(config)
    extra_args = build_unimplemented_device_args()

    try:
        console.print("[dim]Starting QEMU...[/dim]")
        effective_machine = engine_obj.machine_name
        qemu.start(
            firmware, effective_machine,
            gdb=True, paused=True,
            extra_qemu_args=extra_args,
        )

        console.print("[dim]Setting up peripheral intercepts...[/dim]")
        dispatcher = engine_obj.setup(qemu)
        # auto_setup may have resolved machine name
        effective_machine = engine_obj.machine_name

        if auto_mode and effective_machine != machine:
            console.print(f"  [dim]Resolved machine:[/dim] [cyan]{effective_machine}[/cyan]")

        console.print(
            f"[green]Ready:[/green] {len(dispatcher.registered_addresses)} intercepts registered"
        )

        # Save auto-generated config if requested
        if save_config:
            _save_auto_config(engine_obj, save_config)
            console.print(f"[green]Saved config:[/green] [cyan]{save_config}[/cyan]")

        console.print("[dim]Running firmware... (Ctrl+C to stop)[/dim]\n")

        engine_obj.run_interactive(qemu, timeout=timeout)

        # Print stats
        stats = dispatcher.stats
        if stats:
            console.print("\n[bold]Intercept Statistics:[/bold]")
            for addr, count in sorted(stats.items()):
                console.print(f"  0x{addr:08x}: {count} hits")

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user[/yellow]")
    except FileNotFoundError as e:
        console.print(f"\n[red]File not found:[/red] {e}")
        console.print("[dim]Check that QEMU is installed and firmware path is correct.[/dim]")
    except ValueError as e:
        console.print(f"\n[red]Configuration error:[/red] {e}")
        console.print("[dim]Try --auto mode or provide a valid --peripheral-config.[/dim]")
    except RuntimeError as e:
        console.print(f"\n[red]Runtime error:[/red] {e}")
        console.print("[dim]Ensure QEMU supports the target machine. Try: qemu-system-arm -machine help[/dim]")
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        raise
    finally:
        qemu.stop()

    console.print("[green]Rehosting complete.[/green]")


def _save_auto_config(engine_obj, save_path: str) -> None:
    """Serialize and save auto-generated peripheral config to disk."""
    from pathlib import Path
    from rtosploit.peripherals.auto_config import serialize_config

    summary = engine_obj.get_auto_summary()
    dispatcher = engine_obj.dispatcher
    if dispatcher is None:
        return

    # The engine stores the peripheral config internally via setup;
    # reconstruct from models and dispatcher state
    from rtosploit.peripherals.config import PeripheralConfig, PeripheralModelSpec, InterceptSpec

    models = [
        PeripheralModelSpec(name=name, model_class=type(model).__module__ + "." + type(model).__qualname__,
                            base_addr=0, size=0)
        for name, model in engine_obj.models.items()
    ]
    intercepts: list[InterceptSpec] = []
    symbols: dict[int, str] = {}

    config = PeripheralConfig(models=models, intercepts=intercepts, symbols=symbols)
    yaml_text = serialize_config(config)
    Path(save_path).write_text(yaml_text)
