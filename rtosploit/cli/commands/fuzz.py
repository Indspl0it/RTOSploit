"""rtosploit fuzz — start QEMU-based firmware fuzzer."""
import os
import threading

import click
from rich.console import Console

from rtosploit.interactive.dashboard import (
    run_dashboard as _run_dashboard,
)

console = Console()


@click.command("fuzz")
@click.option("--firmware", "-f", required=True, type=click.Path(exists=True), help="Firmware binary")
@click.option("--machine", "-m", required=False, type=str, default=None, help="QEMU machine name (required unless --auto)")
@click.option("--rtos", type=click.Choice(["freertos", "threadx", "zephyr", "auto"]), default="auto", show_default=True, help="Target RTOS")
@click.option("--output", "-o", type=click.Path(), default="fuzz-output", show_default=True, help="Output directory for crashes and corpus")
@click.option("--seeds", "-s", type=click.Path(exists=True), default=None, help="Seed corpus directory")
@click.option("--timeout", "-t", type=int, default=0, help="Fuzzing timeout in seconds (0=unlimited)")
@click.option("--jobs", "-j", type=int, default=1, show_default=True, help="Parallel fuzzer instances")
@click.option("--exec-timeout", type=float, default=0.05, show_default=True, help="Per-execution timeout in seconds")
@click.option("--persistent", is_flag=True, default=False, help="Use persistent mode (system_reset instead of loadvm)")
@click.option("--inject-addr", type=str, default=None, help="SRAM address for input injection (hex, default: 0x20010000)")
@click.option("--inject-len-addr", type=str, default=None, help="Address to write input length (hex)")
@click.option("--corpus-dir", type=click.Path(), default=None, help="Corpus directory (default: {output}/corpus)")
@click.option("--seed", type=click.Path(exists=True), default=None, help="Initial seed file or directory")
@click.option("--coverage-addr", type=str, default=None, help="Address of coverage bitmap in target memory (hex)")
@click.option("--peripheral-config", type=click.Path(exists=True), default=None, help="YAML peripheral config for HAL intercepts")
@click.option("--auto", "auto_mode", is_flag=True, default=False, help="Fully automatic fuzzing: fingerprint firmware and discover input points")
@click.option("--engine", type=click.Choice(["qemu", "unicorn"]), default="qemu", show_default=True, help="Emulation engine backend")
@click.pass_context
def fuzz(ctx, firmware, machine, rtos, output, seeds, timeout, jobs,
         exec_timeout, persistent,
         inject_addr, inject_len_addr, corpus_dir, seed, coverage_addr,
         peripheral_config, auto_mode, engine):
    """Start fuzzing a firmware image with QEMU-based grey-box fuzzing.

    \b
    Example:
      rtosploit fuzz --firmware fw.bin --machine mps2-an385 --output ./output
      rtosploit fuzz --firmware fw.bin --machine mps2-an385 --timeout 3600 --jobs 8
      rtosploit fuzz --firmware fw.bin --auto --timeout 300
    """
    output_json = ctx.obj.get("output_json", False)

    # Auto mode: fingerprint firmware and discover input points
    injector = None
    if auto_mode:
        from rtosploit.utils.binary import load_firmware
        from rtosploit.analysis.fingerprint import fingerprint_firmware
        from rtosploit.fuzzing.input_injector import InputInjector

        fw_image = load_firmware(firmware)
        fp = fingerprint_firmware(fw_image)

        if not output_json:
            console.print("\n[bold cyan]Auto-rehost fingerprint:[/bold cyan]")
            console.print(f"  RTOS:        [cyan]{fp.rtos_type}[/cyan] (confidence {fp.confidence:.0%})")
            console.print(f"  MCU family:  [cyan]{fp.mcu_family}[/cyan]")
            console.print(f"  Architecture:[cyan]{fp.architecture}[/cyan]")
            if fp.input_interfaces:
                console.print(f"  Interfaces:  [cyan]{', '.join(fp.input_interfaces)}[/cyan]")

        injector = InputInjector.discover(fw_image)

        if not output_json:
            if injector.input_count > 0:
                console.print(f"\n[bold green]Discovered {injector.input_count} fuzzable input points:[/bold green]")
                for inp in injector.inputs:
                    console.print(f"  [cyan]{inp.symbol}[/cyan] @ 0x{inp.address:08X} ({inp.peripheral_type}, priority={inp.priority})")
            else:
                console.print("\n[yellow]No fuzzable input points discovered. Falling back to fixed inject address.[/yellow]")

        # Infer machine from MCU family if not provided
        if machine is None:
            _MCU_TO_MACHINE = {
                "stm32": "mps2-an385",
                "nrf52": "microbit",
                "esp32": "esp32",
                "lpc": "lpc4088",
                "sam": "sam3x8e",
            }
            machine = _MCU_TO_MACHINE.get(fp.mcu_family)
            if machine is None:
                raise click.UsageError(
                    f"Could not infer QEMU machine for MCU family '{fp.mcu_family}'. "
                    "Please specify --machine explicitly."
                )
            if not output_json:
                console.print(f"  Machine:     [cyan]{machine}[/cyan] (auto-detected from {fp.mcu_family})")

    if machine is None and not auto_mode:
        raise click.UsageError("--machine is required unless --auto is used.")

    # Parse hex addresses
    inject_addr_int = int(inject_addr, 16) if inject_addr else 0x20010000
    inject_len_addr_int = int(inject_len_addr, 16) if inject_len_addr else None
    coverage_addr_int = int(coverage_addr, 16) if coverage_addr else None

    # Set corpus_dir default
    if corpus_dir is None:
        corpus_dir = f"{output}/corpus"

    # Create output directories
    os.makedirs(output, exist_ok=True)
    os.makedirs(f"{output}/crashes", exist_ok=True)
    os.makedirs(corpus_dir, exist_ok=True)

    # Unicorn engine path
    if engine == "unicorn":
        from rtosploit.fuzzing.unicorn_worker import UnicornFuzzEngine

        if not output_json:
            console.print("  Engine:      [cyan]unicorn (PIP + FERMCov)[/cyan]")
            console.print("\n[dim]Starting Unicorn fuzzer... (Ctrl+C to stop)[/dim]")

        unicorn_engine = UnicornFuzzEngine(
            firmware_path=firmware,
            jobs=jobs,
            output_dir=output,
            timeout=timeout,
        )

        if output_json:
            import json

            final = unicorn_engine.run()
            result = {
                "firmware": firmware,
                "engine": "unicorn",
                "rtos": rtos,
                "output": output,
                "status": "completed",
                "jobs": jobs,
                "crashes": final.crashes,
                "unique_crashes": final.unique_crashes,
                "executions": final.executions,
                "corpus_size": final.corpus_size,
                "elapsed": round(final.elapsed, 1),
                "exec_per_sec": round(final.exec_per_sec, 1),
            }
            click.echo(json.dumps(result, indent=2))
        else:
            engine_stats = {}

            def on_unicorn_stats(stats):
                engine_stats.update(stats)

            unicorn_engine.run(on_stats=on_unicorn_stats)
            console.print(f"\n[green]Unicorn fuzzer stopped.[/green] Output: [cyan]{output}[/cyan]")
        return

    if output_json:
        import json

        if timeout > 0:
            from rtosploit.fuzzing import FuzzEngine

            engine = FuzzEngine(
                firmware_path=firmware,
                machine_name=machine,
                inject_addr=inject_addr_int,
                inject_size=256,
                inject_len_addr=inject_len_addr_int,
                coverage_addr=coverage_addr_int,
                exec_timeout=exec_timeout,
                jobs=jobs,
                persistent_mode=persistent,
                auto_rehost=auto_mode,
                injector=injector,
            )

            final = engine.run(
                timeout=timeout,
                corpus_dir=corpus_dir,
                crash_dir=f"{output}/crashes",
            )

            result = {
                "firmware": firmware,
                "machine": machine,
                "rtos": rtos,
                "output": output,
                "peripheral_config": peripheral_config,
                "auto_mode": auto_mode,
                "status": "completed",
                "jobs": jobs,
                "exec_timeout": exec_timeout,
                "crashes": final.crashes,
                "executions": final.executions,
                "coverage": final.coverage,
                "corpus_size": final.corpus_size,
                "elapsed": round(final.elapsed, 1),
                "exec_per_sec": round(final.exec_per_sec, 1),
            }
            if injector:
                result["injector"] = injector.to_dict()
        else:
            result = {
                "firmware": firmware,
                "machine": machine,
                "rtos": rtos,
                "output": output,
                "peripheral_config": peripheral_config,
                "status": "started",
                "crashes": 0,
                "executions": 0,
                "coverage": 0.0,
                "corpus_size": 0,
                "elapsed": 0.0,
            }
        click.echo(json.dumps(result, indent=2))
        return

    console.print("[bold green]RTOSploit Fuzzer[/bold green]")
    console.print(f"  Firmware:    [cyan]{firmware}[/cyan]")
    console.print(f"  Machine:     [cyan]{machine}[/cyan]")
    console.print(f"  RTOS:        [cyan]{rtos}[/cyan]")
    console.print(f"  Output:      [cyan]{output}[/cyan]")
    console.print(f"  Jobs:        [cyan]{jobs}[/cyan]")
    console.print(f"  Exec timeout:[cyan]{exec_timeout}s[/cyan]")
    if auto_mode:
        console.print("  Mode:        [cyan]auto-rehost[/cyan]")
    if persistent:
        console.print("  Mode:        [cyan]persistent (system_reset)[/cyan]")
    if timeout:
        console.print(f"  Timeout:     [cyan]{timeout}s[/cyan]")

    console.print("\n[dim]Starting fuzzer... (Ctrl+C to stop)[/dim]")

    from rtosploit.fuzzing import FuzzEngine

    engine = FuzzEngine(
        firmware_path=firmware,
        machine_name=machine,
        inject_addr=inject_addr_int,
        inject_size=256,
        inject_len_addr=inject_len_addr_int,
        coverage_addr=coverage_addr_int,
        exec_timeout=exec_timeout,
        jobs=jobs,
        persistent_mode=persistent,
        auto_rehost=auto_mode,
        injector=injector,
    )

    engine_stats = {}
    if peripheral_config:
        engine_stats["peripheral_config"] = peripheral_config

    def stats_provider():
        return engine_stats

    def on_engine_stats(stats):
        engine_stats.update(stats)

    # Run engine in background thread
    engine_thread = threading.Thread(
        target=engine.run,
        kwargs={
            "timeout": timeout,
            "corpus_dir": corpus_dir,
            "crash_dir": f"{output}/crashes",
            "on_stats": on_engine_stats,
        },
        daemon=True,
    )
    engine_thread.start()

    _run_dashboard(
        output, timeout=timeout,
        console=console, stats_provider=stats_provider,
    )

    engine_thread.join(timeout=5)

    console.print(f"\n[green]Fuzzer stopped.[/green] Output directory: [cyan]{output}[/cyan]")
