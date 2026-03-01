"""rtosploit rehost — run firmware with peripheral model intercepts."""

import click
from rich.console import Console

console = Console()


@click.command("rehost")
@click.option("--firmware", "-f", required=True, type=click.Path(exists=True), help="Firmware binary (ELF or raw)")
@click.option("--machine", "-m", required=True, type=str, help="QEMU machine name")
@click.option("--peripheral-config", "-p", required=True, type=click.Path(exists=True), help="YAML peripheral config file")
@click.option("--timeout", "-t", type=int, default=0, help="Timeout in seconds (0=unlimited)")
@click.pass_context
def rehost(ctx, firmware, machine, peripheral_config, timeout):
    """Rehost firmware with HAL function intercepts.

    \b
    Example:
      rtosploit rehost --firmware fw.elf --machine stm32f4 \\
          --peripheral-config configs/peripherals/stm32f4_hal.yaml
      rtosploit rehost -f fw.elf -m mps2-an385 -p my_config.yaml -t 60
    """
    import json

    output_json = ctx.obj.get("output_json", False)

    if output_json:
        from rtosploit.config import RTOSploitConfig
        from rtosploit.emulation.qemu import QEMUInstance
        from rtosploit.peripherals.rehost import RehostingEngine, build_unimplemented_device_args

        config = RTOSploitConfig()
        engine = RehostingEngine(
            firmware_path=firmware,
            machine_name=machine,
            peripheral_config=peripheral_config,
            config=config,
        )

        qemu = QEMUInstance(config)
        extra_args = build_unimplemented_device_args()

        try:
            qemu.start(
                firmware, machine,
                gdb=True, paused=True,
                extra_qemu_args=extra_args,
            )
            dispatcher = engine.setup(qemu)

            result = {
                "firmware": firmware,
                "machine": machine,
                "peripheral_config": peripheral_config,
                "status": "ready",
                "intercepts": len(dispatcher.registered_addresses),
            }

            if timeout > 0:
                engine.run_interactive(qemu, timeout=timeout)
                result["status"] = "completed"
                result["stats"] = dispatcher.stats

            click.echo(json.dumps(result, indent=2, default=str))
        finally:
            qemu.stop()
        return

    console.print("[bold green]RTOSploit Firmware Rehosting[/bold green]")
    console.print(f"  Firmware:     [cyan]{firmware}[/cyan]")
    console.print(f"  Machine:      [cyan]{machine}[/cyan]")
    console.print(f"  Periph config:[cyan]{peripheral_config}[/cyan]")
    if timeout:
        console.print(f"  Timeout:      [cyan]{timeout}s[/cyan]")
    console.print()

    from rtosploit.config import RTOSploitConfig
    from rtosploit.emulation.qemu import QEMUInstance
    from rtosploit.peripherals.rehost import RehostingEngine, build_unimplemented_device_args

    config = RTOSploitConfig()
    engine = RehostingEngine(
        firmware_path=firmware,
        machine_name=machine,
        peripheral_config=peripheral_config,
        config=config,
    )

    qemu = QEMUInstance(config)
    extra_args = build_unimplemented_device_args()

    try:
        console.print("[dim]Starting QEMU...[/dim]")
        qemu.start(
            firmware, machine,
            gdb=True, paused=True,
            extra_qemu_args=extra_args,
        )

        console.print("[dim]Setting up peripheral intercepts...[/dim]")
        dispatcher = engine.setup(qemu)

        console.print(
            f"[green]Ready:[/green] {len(dispatcher.registered_addresses)} intercepts registered"
        )
        console.print("[dim]Running firmware... (Ctrl+C to stop)[/dim]\n")

        engine.run_interactive(qemu, timeout=timeout)

        # Print stats
        stats = dispatcher.stats
        if stats:
            console.print("\n[bold]Intercept Statistics:[/bold]")
            for addr, count in sorted(stats.items()):
                console.print(f"  0x{addr:08x}: {count} hits")

    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped by user[/yellow]")
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        raise
    finally:
        qemu.stop()

    console.print("[green]Rehosting complete.[/green]")
