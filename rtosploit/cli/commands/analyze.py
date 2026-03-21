"""rtosploit analyze — static firmware analysis."""
import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.command("analyze")
@click.option("--firmware", "-f", required=True, type=click.Path(exists=True), help="Firmware binary to analyze")
@click.option("--detect-rtos", is_flag=True, default=False, help="Detect RTOS type")
@click.option("--detect-heap", is_flag=True, default=False, help="Detect heap allocator")
@click.option("--detect-mpu", is_flag=True, default=False, help="Detect MPU configuration")
@click.option("--strings", is_flag=True, default=False, help="Extract and classify strings")
@click.option("--detect-peripherals", "detect_periphs", is_flag=True, default=False, help="Detect peripheral usage")
@click.option("--rehost-check", is_flag=True, default=False, help="Check rehosting readiness")
@click.option("--all", "run_all", is_flag=True, default=False, help="Run all analyses")
@click.pass_context
def analyze(ctx, firmware, detect_rtos, detect_heap, detect_mpu, strings, detect_periphs, rehost_check, run_all):
    """Run static analysis on a firmware binary.

    \b
    Example:
      rtosploit analyze --firmware fw.bin --all
      rtosploit analyze --firmware fw.bin --detect-rtos --detect-mpu
      rtosploit analyze --firmware fw.bin --rehost-check
    """
    if run_all:
        detect_rtos = detect_heap = detect_mpu = strings = detect_periphs = rehost_check = True

    if not any([detect_rtos, detect_heap, detect_mpu, strings, detect_periphs, rehost_check]):
        detect_rtos = detect_heap = detect_mpu = strings = detect_periphs = True

    output_json = ctx.obj.get("output_json", False)
    results = {"firmware": firmware}

    from rtosploit.utils.binary import load_firmware
    fw_image = load_firmware(firmware)
    firmware_bytes = fw_image.data

    if detect_rtos:
        try:
            from rtosploit.analysis.fingerprint import fingerprint_firmware
            rtos_result = fingerprint_firmware(fw_image)
            results["rtos"] = {
                "detected": rtos_result.rtos_type,
                "version": rtos_result.version,
                "confidence": rtos_result.confidence,
                "architecture": rtos_result.architecture,
                "mcu_family": rtos_result.mcu_family,
                "symbol_count": rtos_result.symbol_count,
                "input_interfaces": rtos_result.input_interfaces,
                "memory_map": rtos_result.memory_map,
                "vector_table": {k: f"0x{v:08x}" for k, v in rtos_result.vector_table.items()},
            }
        except Exception as e:
            results["rtos"] = {"error": str(e)}

    if detect_heap:
        try:
            from rtosploit.analysis.heap_detect import detect_heap as detect_heap_fn
            from rtosploit.analysis.fingerprint import fingerprint_firmware, RTOSFingerprint
            # Need a fingerprint for detect_heap
            try:
                fp = fingerprint_firmware(fw_image)
            except Exception:
                fp = RTOSFingerprint(rtos_type="unknown", version=None, confidence=0.0)
            heap_result = detect_heap_fn(fw_image, fp)
            results["heap"] = {
                "type": heap_result.allocator_type,
                "base": hex(heap_result.heap_base) if heap_result.heap_base else None,
            }
        except Exception as e:
            results["heap"] = {"error": str(e)}

    if detect_mpu:
        try:
            from rtosploit.analysis.mpu_check import check_mpu
            mpu_result = check_mpu(fw_image)
            results["mpu"] = {
                "present": mpu_result.mpu_present,
                "regions": mpu_result.regions_configured,
                "vulnerabilities": mpu_result.vulnerabilities,
                "vulnerable": len(mpu_result.vulnerabilities) > 0,
            }
        except Exception as e:
            results["mpu"] = {"error": str(e)}

    if strings:
        try:
            from rtosploit.analysis.strings import extract_strings
            strs = extract_strings(fw_image)
            results["strings"] = {
                "count": len(strs),
                "sample": [s for _, s in strs[:10]],
            }
        except Exception as e:
            results["strings"] = {"error": str(e)}

    if detect_periphs:
        try:
            from rtosploit.analysis.detection import detect_peripherals as run_detection
            det_result = run_detection(fw_image)
            results["peripherals"] = det_result.to_dict()
        except Exception as e:
            results["peripherals"] = {"error": str(e)}

    if rehost_check:
        try:
            from rtosploit.analysis.fingerprint import fingerprint_firmware
            from rtosploit.peripherals.auto_config import AutoConfigGenerator, resolve_qemu_machine

            fp = fingerprint_firmware(fw_image)
            generator = AutoConfigGenerator()
            _pconfig, summary = generator.generate(fw_image, fingerprint=fp)

            # Compute readiness score (0-100%)
            score = 0
            # MCU detected (not falling back to unknown): +25
            if summary.get("mcu_family", "unknown") != "unknown":
                score += 25
            # SVD available: +25
            if summary.get("svd_available", False):
                score += 25
            # HAL matches found: +25
            if summary.get("hal_matches", 0) > 0:
                score += 25
            # RTOS detected: +15
            if summary.get("rtos_type", "unknown") != "unknown":
                score += 15
            # Has intercepts: +10
            if summary.get("intercept_count", 0) > 0:
                score += 10
            score = min(score, 100)

            qemu_machine = summary.get("qemu_machine", "unknown")
            # Check if machine was resolved from MCU or fell back to architecture default
            mcu = summary.get("mcu_family", "unknown")
            resolved_machine = resolve_qemu_machine(mcu, summary.get("architecture", "armv7m"))
            machine_resolved = mcu != "unknown"

            results["rehost_check"] = {
                "qemu_machine": qemu_machine,
                "machine_resolved": machine_resolved,
                "svd_available": summary.get("svd_available", False),
                "hal_hooks": summary.get("intercept_count", 0),
                "hal_matches": summary.get("hal_matches", 0),
                "model_count": summary.get("model_count", 0),
                "readiness_score": score,
                "mcu_family": mcu,
                "rtos_type": summary.get("rtos_type", "unknown"),
                "architecture": summary.get("architecture", "unknown"),
            }
        except Exception as e:
            results["rehost_check"] = {"error": str(e)}

    if output_json:
        import json
        click.echo(json.dumps(results, indent=2))
        return

    from rich.panel import Panel
    console.print(Panel(
        f"[bold]Firmware Analysis:[/bold] [cyan]{firmware}[/cyan] ({len(firmware_bytes)} bytes)",
        border_style="cyan",
    ))

    if "rtos" in results:
        r = results["rtos"]
        if "error" not in r:
            rtos_str = r["detected"] or "unknown"
            ver_str = f" v{r['version']}" if r.get("version") else ""
            conf_str = f" ({r['confidence']:.0%})" if r.get("confidence") else ""
            console.print(f"  RTOS:   [green]{rtos_str}{ver_str}{conf_str}[/green]")
            arch = r.get("architecture", "unknown")
            mcu = r.get("mcu_family", "unknown")
            sym_count = r.get("symbol_count", 0)
            console.print(f"  Arch:   [cyan]{arch}[/cyan]")
            console.print(f"  MCU:    [cyan]{mcu}[/cyan]")
            if sym_count:
                console.print(f"  Symbols: [cyan]{sym_count}[/cyan]")
            ifaces = r.get("input_interfaces", [])
            if ifaces:
                console.print(f"  Interfaces: [cyan]{', '.join(ifaces)}[/cyan]")
        else:
            console.print(f"  RTOS:   [yellow]detection error: {r['error']}[/yellow]")

    if "heap" in results:
        r = results["heap"]
        if "error" not in r:
            heap_str = r["type"] or "unknown"
            console.print(f"  Heap:   [green]{heap_str}[/green]")
        else:
            console.print("  Heap:   [yellow]detection error[/yellow]")

    if "mpu" in results:
        r = results["mpu"]
        if "error" not in r:
            present_status = "[green]present[/green]" if r.get("present") else "[red]not detected[/red]"
            vuln_str = " [red](VULNERABLE)[/red]" if r.get("vulnerable") else ""
            console.print(f"  MPU:    {present_status} ({r.get('regions', 0)} regions){vuln_str}")
        else:
            console.print("  MPU:    [yellow]detection error[/yellow]")

    if "strings" in results:
        r = results["strings"]
        if "error" not in r:
            console.print(f"  Strings: [green]{r['count']} found[/green]")
        else:
            console.print("  Strings: [yellow]extraction error[/yellow]")

    if "peripherals" in results:
        r = results["peripherals"]
        if "error" not in r:
            periph_data = r.get("peripherals", {})
            if periph_data:
                table = Table(title="Detected Peripherals")
                table.add_column("Peripheral", style="cyan")
                table.add_column("Type", style="green")
                table.add_column("Confidence", justify="right")
                table.add_column("Level", style="bold")
                table.add_column("Evidence", justify="right")
                for name, info in periph_data.items():
                    level = info.get("confidence_level", "?")
                    level_style = {"high": "[green]", "medium": "[yellow]", "low": "[red]"}.get(level, "")
                    table.add_row(
                        name,
                        info.get("type", "?"),
                        f"{info.get('confidence', 0):.2f}",
                        f"{level_style}{level}[/]" if level_style else level,
                        str(info.get("evidence_count", 0)),
                    )
                console.print(table)
            else:
                console.print("  Peripherals: [yellow]none detected[/yellow]")
        else:
            console.print(f"  Peripherals: [yellow]detection error: {r['error']}[/yellow]")

    if "rehost_check" in results:
        r = results["rehost_check"]
        if "error" not in r:
            score = r["readiness_score"]
            if score >= 75:
                score_style = "green"
            elif score >= 40:
                score_style = "yellow"
            else:
                score_style = "red"

            machine_str = r["qemu_machine"]
            if r["machine_resolved"]:
                machine_str += " [green](resolved)[/green]"
            else:
                machine_str += " [yellow](fallback)[/yellow]"

            svd_str = "[green]yes[/green]" if r["svd_available"] else "[red]no[/red]"

            from rich.table import Table as RichTable
            rh_table = RichTable(show_header=False, box=None, padding=(0, 2))
            rh_table.add_column("Key", style="bold cyan")
            rh_table.add_column("Value")
            rh_table.add_row("QEMU machine", machine_str)
            rh_table.add_row("SVD available", svd_str)
            rh_table.add_row("HAL hooks", str(r["hal_hooks"]))
            rh_table.add_row("HAL matches", str(r["hal_matches"]))
            rh_table.add_row("Models", str(r["model_count"]))
            rh_table.add_row("Readiness", f"[{score_style}]{score}%[/{score_style}]")

            from rich.panel import Panel as RichPanel
            console.print(RichPanel(
                rh_table,
                title="[bold]Rehosting Readiness[/bold]",
                border_style=score_style,
            ))
        else:
            console.print(f"  Rehost check: [yellow]error: {r['error']}[/yellow]")
