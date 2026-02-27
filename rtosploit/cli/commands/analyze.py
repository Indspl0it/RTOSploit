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
@click.option("--all", "run_all", is_flag=True, default=False, help="Run all analyses")
@click.pass_context
def analyze(ctx, firmware, detect_rtos, detect_heap, detect_mpu, strings, run_all):
    """Run static analysis on a firmware binary.

    \b
    Example:
      rtosploit analyze --firmware fw.bin --all
      rtosploit analyze --firmware fw.bin --detect-rtos --detect-mpu
    """
    if run_all:
        detect_rtos = detect_heap = detect_mpu = strings = True

    if not any([detect_rtos, detect_heap, detect_mpu, strings]):
        detect_rtos = detect_heap = detect_mpu = strings = True

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
