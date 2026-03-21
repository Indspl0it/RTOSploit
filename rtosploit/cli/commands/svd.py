"""rtosploit svd — SVD file operations."""
import os
import click
from rich.console import Console
from rich.table import Table

console = Console()

# Vendor prefix mapping for CMSIS-SVD GitHub repository
_VENDOR_PREFIXES = {
    "STM32": "STMicro",
    "STM":   "STMicro",
    "NRF":   "Nordic",
    "ATSAMD": "Atmel",
    "ATSAM":  "Atmel",
    "AT":     "Atmel",
    "LPC":    "NXP",
    "MK":     "Freescale",
    "EFM32":  "SiliconLabs",
    "EFR32":  "SiliconLabs",
    "TM4C":   "TexasInstruments",
    "LM3S":   "TexasInstruments",
    "LM4F":   "TexasInstruments",
    "MSP432": "TexasInstruments",
    "CC":     "TexasInstruments",
    "XMC":    "Infineon",
    "CY":     "Cypress",
    "RP":     "RaspberryPi",
    "GD32":   "GigaDevice",
    "ESP32":  "Espressif",
    "MAX":    "Maxim",
}

_SVD_BASE_URL = "https://raw.githubusercontent.com/cmsis-svd/cmsis-svd-data/main/"


def _guess_vendor(device: str) -> str | None:
    """Guess the vendor folder name from a device/chip prefix."""
    upper = device.upper()
    # Try longest prefix first for correct matching (e.g. STM32 before STM)
    for prefix in sorted(_VENDOR_PREFIXES, key=len, reverse=True):
        if upper.startswith(prefix):
            return _VENDOR_PREFIXES[prefix]
    return None


@click.group("svd")
def svd():
    """SVD (System View Description) file operations."""
    pass


@svd.command("parse")
@click.argument("svd_file", type=click.Path(exists=True))
@click.pass_context
def svd_parse(ctx, svd_file):
    """Parse an SVD file and display peripheral summary."""
    output_json = ctx.obj.get("output_json", False)

    peripherals = []
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(svd_file)
        root = tree.getroot()
        for periph in root.findall(".//peripheral"):
            name_el = periph.find("name")
            base_el = periph.find("baseAddress")
            desc_el = periph.find("description")
            regs = periph.findall(".//register")
            peripherals.append({
                "name": name_el.text if name_el is not None else "?",
                "base_address": int(base_el.text, 16) if base_el is not None else 0,
                "register_count": len(regs),
                "description": (desc_el.text or "").strip() if desc_el is not None else "",
            })
    except Exception as e:
        console.print(f"[yellow]SVD parse note: {e}[/yellow]")

    if output_json:
        import json
        click.echo(json.dumps({
            "svd_file": svd_file,
            "peripheral_count": len(peripherals),
            "peripherals": peripherals,
        }))
        return

    table = Table(title=f"SVD: {svd_file}", show_header=True, header_style="bold cyan")
    table.add_column("Peripheral", style="cyan")
    table.add_column("Base Address", style="yellow")
    table.add_column("Registers", style="green")
    table.add_column("Description", style="dim")

    for p in peripherals:
        table.add_row(
            p.get("name", "?"),
            f"0x{p.get('base_address', 0):08x}",
            str(p.get("register_count", 0)),
            (p.get("description", "") or "")[:50],
        )

    console.print(table)
    console.print(f"[dim]{len(peripherals)} peripherals found.[/dim]")


def _parse_svd_peripherals(svd_file):
    """Parse an SVD file and return a list of peripheral dicts with registers and fields."""
    import xml.etree.ElementTree as ET

    tree = ET.parse(svd_file)
    root = tree.getroot()
    peripherals = []

    for periph in root.findall(".//peripheral"):
        name_el = periph.find("name")
        base_el = periph.find("baseAddress")

        if name_el is None:
            continue

        pname = name_el.text.strip()
        base_addr = int(base_el.text, 0) if base_el is not None and base_el.text else 0

        registers = []
        for reg in periph.findall(".//register"):
            rname_el = reg.find("name")
            offset_el = reg.find("addressOffset")
            size_el = reg.find("size")
            reset_el = reg.find("resetValue")
            access_el = reg.find("access")

            if rname_el is None:
                continue

            rname = rname_el.text.strip()
            offset = int(offset_el.text, 0) if offset_el is not None and offset_el.text else 0
            size = int(size_el.text, 0) if size_el is not None and size_el.text else 32
            reset_value = int(reset_el.text, 0) if reset_el is not None and reset_el.text else 0
            access = access_el.text.strip() if access_el is not None and access_el.text else "read-write"

            fields = []
            for field in reg.findall(".//field"):
                fname_el = field.find("name")
                foffset_el = field.find("bitOffset")
                fwidth_el = field.find("bitWidth")
                if fname_el is None:
                    continue
                fields.append({
                    "name": fname_el.text.strip(),
                    "bit_offset": int(foffset_el.text, 0) if foffset_el is not None and foffset_el.text else 0,
                    "bit_width": int(fwidth_el.text, 0) if fwidth_el is not None and fwidth_el.text else 1,
                })

            registers.append({
                "name": rname,
                "offset": offset,
                "size": size,
                "reset_value": reset_value,
                "access": access,
                "fields": fields,
            })

        peripherals.append({
            "name": pname,
            "base_address": base_addr,
            "registers": registers,
        })

    return peripherals


def _c_type_for_size(size_bits):
    """Return the appropriate C integer type for a register size."""
    if size_bits <= 8:
        return "uint8_t"
    elif size_bits <= 16:
        return "uint16_t"
    else:
        return "uint32_t"


def _generate_reset_value_stub(periph):
    """Generate a C stub file for reset-value mode."""
    name = periph["name"]
    name_lower = name.lower()
    registers = periph["registers"]

    lines = []
    lines.append("/* Auto-generated peripheral stub: reset-value mode */")
    lines.append(f"/* Peripheral: {name} @ 0x{periph['base_address']:08x} */")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("")

    # Struct definition
    lines.append("typedef struct {")
    if registers:
        for reg in registers:
            ctype = _c_type_for_size(reg["size"])
            lines.append(f"    {ctype} {reg['name']};")
    else:
        lines.append("    uint32_t _reserved;")
    lines.append(f"}} {name_lower}_regs_t;")
    lines.append("")

    # Init function setting reset values
    lines.append(f"void {name_lower}_init({name_lower}_regs_t *regs) {{")
    for reg in registers:
        lines.append(f"    regs->{reg['name']} = 0x{reg['reset_value']:x};")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def _generate_read_write_stub(periph):
    """Generate a C stub file for read-write mode."""
    name = periph["name"]
    name_lower = name.lower()
    registers = periph["registers"]

    lines = []
    lines.append("/* Auto-generated peripheral stub: read-write mode */")
    lines.append(f"/* Peripheral: {name} @ 0x{periph['base_address']:08x} */")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("")

    # Struct definition
    lines.append("typedef struct {")
    if registers:
        for reg in registers:
            ctype = _c_type_for_size(reg["size"])
            lines.append(f"    {ctype} {reg['name']};")
    else:
        lines.append("    uint32_t _reserved;")
    lines.append(f"}} {name_lower}_regs_t;")
    lines.append("")

    # Static backing store
    lines.append(f"static {name_lower}_regs_t {name_lower}_state;")
    lines.append("")

    # Init function
    lines.append(f"void {name_lower}_init({name_lower}_regs_t *regs) {{")
    for reg in registers:
        lines.append(f"    regs->{reg['name']} = 0x{reg['reset_value']:x};")
    lines.append("}")
    lines.append("")

    # Read handler
    lines.append(f"uint32_t {name_lower}_read(uint32_t offset) {{")
    lines.append("    switch (offset) {")
    for reg in registers:
        if reg["access"] in ("read-only", "read-write"):
            lines.append(f"    case 0x{reg['offset']:x}:")
            lines.append(f"        return (uint32_t){name_lower}_state.{reg['name']};")
    lines.append("    default:")
    lines.append("        return 0;")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    # Write handler
    lines.append(f"void {name_lower}_write(uint32_t offset, uint32_t value) {{")
    lines.append("    switch (offset) {")
    for reg in registers:
        if reg["access"] in ("write-only", "read-write"):
            ctype = _c_type_for_size(reg["size"])
            lines.append(f"    case 0x{reg['offset']:x}:")
            lines.append(f"        {name_lower}_state.{reg['name']} = ({ctype})value;")
            lines.append("        break;")
    lines.append("    default:")
    lines.append("        break;")
    lines.append("    }")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def _generate_fuzzer_stub(periph):
    """Generate a C stub file for fuzzer mode."""
    name = periph["name"]
    name_lower = name.lower()
    registers = periph["registers"]

    lines = []
    lines.append("/* Auto-generated peripheral stub: fuzzer mode */")
    lines.append(f"/* Peripheral: {name} @ 0x{periph['base_address']:08x} */")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("#include <string.h>")
    lines.append("")

    # Struct definition
    lines.append("typedef struct {")
    if registers:
        for reg in registers:
            ctype = _c_type_for_size(reg["size"])
            lines.append(f"    {ctype} {reg['name']};")
    else:
        lines.append("    uint32_t _reserved;")
    lines.append(f"}} {name_lower}_regs_t;")
    lines.append("")

    # Fuzz buffer state
    lines.append(f"static const uint8_t *{name_lower}_fuzz_buf = (void *)0;")
    lines.append(f"static uint32_t {name_lower}_fuzz_len = 0;")
    lines.append(f"static uint32_t {name_lower}_fuzz_pos = 0;")
    lines.append("")

    # Setup function
    lines.append(f"void {name_lower}_fuzz_init(const uint8_t *buf, uint32_t len) {{")
    lines.append(f"    {name_lower}_fuzz_buf = buf;")
    lines.append(f"    {name_lower}_fuzz_len = len;")
    lines.append(f"    {name_lower}_fuzz_pos = 0;")
    lines.append("}")
    lines.append("")

    # Read handler: pulls bytes from fuzz buffer
    lines.append(f"uint32_t {name_lower}_read(uint32_t offset) {{")
    lines.append("    (void)offset;")
    lines.append("    uint32_t val = 0;")
    lines.append(f"    uint32_t remaining = {name_lower}_fuzz_len - {name_lower}_fuzz_pos;")
    lines.append("    uint32_t to_copy = remaining < 4 ? remaining : 4;")
    lines.append("    if (to_copy > 0) {")
    lines.append(f"        memcpy(&val, {name_lower}_fuzz_buf + {name_lower}_fuzz_pos, to_copy);")
    lines.append(f"        {name_lower}_fuzz_pos += to_copy;")
    lines.append("    }")
    lines.append("    return val;")
    lines.append("}")
    lines.append("")

    # Write handler: no-op in fuzzer mode
    lines.append(f"void {name_lower}_write(uint32_t offset, uint32_t value) {{")
    lines.append("    (void)offset;")
    lines.append("    (void)value;")
    lines.append("}")
    lines.append("")

    return "\n".join(lines)


def _generate_peripheral_map_header(peripherals, mode):
    """Generate a peripheral_map.h header mapping base addresses to handlers."""
    lines = []
    lines.append("/* Auto-generated peripheral map header */")
    lines.append(f"/* Mode: {mode} */")
    lines.append("")
    lines.append("#ifndef PERIPHERAL_MAP_H")
    lines.append("#define PERIPHERAL_MAP_H")
    lines.append("")
    lines.append("#include <stdint.h>")
    lines.append("")

    # Declare handler functions
    for periph in peripherals:
        name_lower = periph["name"].lower()
        lines.append(f"/* {periph['name']} @ 0x{periph['base_address']:08x} */")
        lines.append(f"uint32_t {name_lower}_read(uint32_t offset);")
        lines.append(f"void {name_lower}_write(uint32_t offset, uint32_t value);")
        lines.append("")

    # Peripheral map struct and table
    lines.append("typedef struct {")
    lines.append("    uint32_t base_address;")
    lines.append("    uint32_t size;")
    lines.append("    uint32_t (*read)(uint32_t offset);")
    lines.append("    void (*write)(uint32_t offset, uint32_t value);")
    lines.append("} peripheral_entry_t;")
    lines.append("")

    lines.append("static const peripheral_entry_t peripheral_map[] = {")
    for periph in peripherals:
        name_lower = periph["name"].lower()
        # Estimate peripheral size from max register offset + 4
        max_offset = 4
        for reg in periph["registers"]:
            end = reg["offset"] + (reg["size"] // 8)
            if end > max_offset:
                max_offset = end
        lines.append(f"    {{ 0x{periph['base_address']:08x}, 0x{max_offset:x}, {name_lower}_read, {name_lower}_write }},")
    lines.append("};")
    lines.append("")
    lines.append(f"#define PERIPHERAL_COUNT {len(peripherals)}")
    lines.append("")
    lines.append("#endif /* PERIPHERAL_MAP_H */")
    lines.append("")

    return "\n".join(lines)


@svd.command("generate")
@click.argument("svd_file", type=click.Path(exists=True))
@click.option("--mode", type=click.Choice(["reset-value", "read-write", "fuzzer"]), default="reset-value", show_default=True)
@click.option("--output", "-o", type=click.Path(), default="svd_stubs", show_default=True)
@click.pass_context
def svd_generate(ctx, svd_file, mode, output):
    """Generate C peripheral stubs from an SVD file."""
    import os
    os.makedirs(output, exist_ok=True)

    output_json = ctx.obj.get("output_json", False)

    # Parse SVD file
    try:
        peripherals = _parse_svd_peripherals(svd_file)
    except Exception as e:
        if output_json:
            import json
            click.echo(json.dumps({
                "svd_file": svd_file,
                "mode": mode,
                "output_dir": output,
                "files_generated": 0,
                "error": str(e),
            }))
        else:
            console.print(f"[red]Failed to parse SVD file: {e}[/red]")
        return

    # Select generator based on mode
    generators = {
        "reset-value": _generate_reset_value_stub,
        "read-write": _generate_read_write_stub,
        "fuzzer": _generate_fuzzer_stub,
    }
    gen_func = generators[mode]

    files_generated = []

    # Generate per-peripheral C files
    for periph in peripherals:
        filename = f"{periph['name'].lower()}.c"
        filepath = os.path.join(output, filename)
        content = gen_func(periph)
        with open(filepath, "w") as f:
            f.write(content)
        files_generated.append(filename)

    # Generate peripheral_map.h
    if peripherals:
        map_filename = "peripheral_map.h"
        map_filepath = os.path.join(output, map_filename)
        map_content = _generate_peripheral_map_header(peripherals, mode)
        with open(map_filepath, "w") as f:
            f.write(map_content)
        files_generated.append(map_filename)

    result = {
        "svd_file": svd_file,
        "mode": mode,
        "output_dir": output,
        "files_generated": len(files_generated),
        "files": files_generated,
    }

    if output_json:
        import json
        click.echo(json.dumps(result))
        return

    console.print(f"[dim]Generating {mode} stubs from {svd_file} -> {output}/[/dim]")
    for fname in files_generated:
        console.print(f"  [cyan]{fname}[/cyan]")
    console.print(f"[green]Done.[/green] {len(files_generated)} files written to: [cyan]{output}/[/cyan]")


@svd.command("download")
@click.option("--device", required=True, help="Target device/chip name (e.g. STM32F407, nRF52840)")
@click.option("--output", "-o", "output_dir", type=click.Path(), default=".", show_default=True, help="Directory to save the SVD file")
@click.pass_context
def svd_download(ctx, device, output_dir):
    """Download an SVD file from the CMSIS-SVD GitHub repository."""
    import urllib.request
    import urllib.error

    output_json = ctx.obj.get("output_json", False)

    vendor = _guess_vendor(device)
    if vendor is None:
        if output_json:
            import json
            click.echo(json.dumps({"error": f"Unknown vendor prefix for device: {device}", "device": device}))
        else:
            console.print(f"[red]Could not determine vendor for device: {device}[/red]")
            console.print("[dim]Known prefixes: " + ", ".join(sorted(_VENDOR_PREFIXES.keys())) + "[/dim]")
        raise SystemExit(1)

    # Try common filename patterns: exact name, uppercase, with .svd extension
    # Deduplicate while preserving order (e.g. when device is already uppercase)
    device_upper = device.upper()
    candidates = list(dict.fromkeys([
        f"{device}.svd",
        f"{device_upper}.svd",
        f"{device}.xml",
        f"{device_upper}.xml",
    ]))

    os.makedirs(output_dir, exist_ok=True)

    if not output_json:
        console.print(f"[dim]Vendor detected: [cyan]{vendor}[/cyan] for device [cyan]{device}[/cyan][/dim]")
        console.print("[dim]Searching CMSIS-SVD repository...[/dim]")

    downloaded_path = None
    last_error = None

    for filename in candidates:
        url = f"{_SVD_BASE_URL}{vendor}/{filename}"
        dest = os.path.join(output_dir, filename)

        try:
            if not output_json:
                console.print(f"[dim]  Trying: {url}[/dim]")
            urllib.request.urlretrieve(url, dest)
            downloaded_path = dest
            break
        except urllib.error.HTTPError as e:
            last_error = e
            # Clean up partial file if any
            if os.path.exists(dest):
                os.remove(dest)
            continue
        except urllib.error.URLError as e:
            last_error = e
            if os.path.exists(dest):
                os.remove(dest)
            continue

    if downloaded_path is None:
        if output_json:
            import json
            click.echo(json.dumps({
                "error": f"Could not download SVD for {device}",
                "vendor": vendor,
                "tried": candidates,
                "last_error": str(last_error),
            }))
        else:
            console.print(f"\n[red]Could not download SVD file for {device}[/red]")
            console.print(f"[dim]Vendor: {vendor}[/dim]")
            console.print(f"[dim]Tried: {', '.join(candidates)}[/dim]")
            console.print(f"[dim]Last error: {last_error}[/dim]")
            console.print("\n[yellow]You can browse available SVDs at:[/yellow]")
            console.print(f"  [cyan]https://github.com/cmsis-svd/cmsis-svd-data/tree/main/{vendor}[/cyan]")
        raise SystemExit(1)

    if output_json:
        import json
        click.echo(json.dumps({
            "device": device,
            "vendor": vendor,
            "file": downloaded_path,
            "url": url,
        }))
    else:
        console.print(f"\n[green]Downloaded:[/green] [cyan]{downloaded_path}[/cyan]")
        console.print(f"[dim]Parse with: rtosploit svd parse {downloaded_path}[/dim]")
