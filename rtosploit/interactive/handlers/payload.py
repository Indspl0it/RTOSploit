"""Payload generation handler for interactive mode."""

from __future__ import annotations

import logging

import questionary
from rich.console import Console

from rtosploit.interactive.session import InteractiveSession, normalize_path

logger = logging.getLogger(__name__)


def handle_payload(session: InteractiveSession, console: Console) -> None:
    """Payload generation sub-menu."""
    while True:
        action = questionary.select(
            "Payload Generation:",
            choices=[
                questionary.Choice("Generate Shellcode", value="shellcode"),
                questionary.Choice("Generate ROP Chain", value="rop"),
                questionary.Choice("Back", value="back"),
            ],
        ).ask()

        if not action or action == "back":
            return

        if action == "shellcode":
            _handle_shellcode(console)
        elif action == "rop":
            _handle_rop(session, console)


def _handle_shellcode(console: Console) -> None:
    """Generate shellcode interactively."""
    arch = questionary.select(
        "Target architecture:",
        choices=["arm", "thumb2", "riscv", "rv32"],
    ).ask()
    if not arch:
        return

    payload_type = questionary.select(
        "Payload type:",
        choices=[
            questionary.Choice("NOP Sled", value="nop"),
            questionary.Choice("Infinite Loop", value="loop"),
            questionary.Choice("MPU Disable (ARM only)", value="mpu_disable"),
            questionary.Choice("VTOR Redirect (ARM only)", value="vtor"),
            questionary.Choice("Register Dump (ARM only)", value="regdump"),
        ],
    ).ask()
    if not payload_type:
        return

    output_format = questionary.select(
        "Output format:",
        choices=[
            questionary.Choice("Hex string", value="hex"),
            questionary.Choice("C array", value="c_array"),
            questionary.Choice("Raw bytes", value="raw"),
        ],
    ).ask()
    if not output_format:
        return

    try:
        from rtosploit.payloads.shellcode import ShellcodeGenerator, filter_bad_chars

        gen = ShellcodeGenerator()
        payload = None

        if payload_type == "nop":
            length_str = questionary.text("Sled length (bytes):", default="32").ask()
            length = int(length_str) if length_str else 32
            payload = gen.nop_sled(arch, length)
        elif payload_type == "loop":
            payload = gen.infinite_loop(arch)
        elif payload_type == "mpu_disable":
            payload = gen.mpu_disable()
        elif payload_type == "vtor":
            addr_str = questionary.text("New vector table address (hex):", default="0x20000000").ask()
            addr = int(addr_str, 16) if addr_str else 0x20000000
            payload = gen.vtor_redirect(addr)
        elif payload_type == "regdump":
            addr_str = questionary.text("Destination address (hex):", default="0x20001000").ask()
            addr = int(addr_str, 16) if addr_str else 0x20001000
            payload = gen.register_dump(addr)

        if payload is None:
            console.print("[yellow]No payload generated.[/yellow]")
            return

        # Optional bad char filtering
        bad_chars_str = questionary.text(
            "Bad characters (hex, e.g. 000a0d, or empty):",
            default="",
        ).ask()
        if bad_chars_str:
            bad_chars = bytes.fromhex(bad_chars_str)
            payload = filter_bad_chars(payload, bad_chars)

        # Format output
        console.print()
        if output_format == "hex":
            console.print(f"[green]{payload.hex()}[/green]")
        elif output_format == "c_array":
            arr = ", ".join(f"0x{b:02x}" for b in payload)
            console.print(f"[green]unsigned char payload[] = {{{arr}}};[/green]")
        elif output_format == "raw":
            console.print(f"[green]{repr(payload)}[/green]")

        console.print(f"[dim]Size: {len(payload)} bytes[/dim]\n")

    except Exception as exc:
        console.print(f"[red]Shellcode generation failed: {exc}[/red]")


def _handle_rop(session: InteractiveSession, console: Console) -> None:
    """Generate ROP chain interactively."""
    binary_path = questionary.path("Binary file path:").ask()
    if not binary_path:
        return

    arch = questionary.select(
        "Architecture:",
        choices=["arm", "thumb2"],
    ).ask()
    if not arch:
        return

    load_addr_str = questionary.text(
        "Load address (hex):",
        default="0x08000000",
    ).ask()
    load_addr = int(load_addr_str, 16) if load_addr_str else 0x08000000

    goal = questionary.select(
        "ROP goal:",
        choices=[
            questionary.Choice("MPU Disable", value="mpu_disable"),
            questionary.Choice("Custom Write-What-Where", value="www"),
        ],
    ).ask()
    if not goal:
        return

    try:
        from rtosploit.payloads.rop import ROPHelper

        binary = normalize_path(binary_path).read_bytes()
        helper = ROPHelper()
        gadgets = helper.find_bxlr_gadgets(binary, load_addr)

        console.print(f"\n[dim]Found {len(gadgets)} gadgets.[/dim]")

        # Optional bad char filter
        bad_chars_str = questionary.text(
            "Bad characters (hex, or empty):",
            default="",
        ).ask()
        if bad_chars_str:
            bad_chars = bytes.fromhex(bad_chars_str)
            gadgets = helper.filter_bad_chars(gadgets, bad_chars)
            console.print(f"[dim]{len(gadgets)} gadgets after filtering.[/dim]")

        if not gadgets:
            console.print("[yellow]No usable gadgets found.[/yellow]")
            return

        chain = None
        if goal == "mpu_disable":
            chain = helper.build_mpu_disable(gadgets)
        elif goal == "www":
            addr_str = questionary.text("Target address (hex):").ask()
            val_str = questionary.text("Value to write (hex):").ask()
            if addr_str and val_str:
                chain = helper.build_write_what_where(
                    gadgets,
                    int(addr_str, 16),
                    int(val_str, 16),
                )

        if chain:
            console.print(f"\n[green]ROP chain ({len(chain)} bytes):[/green]")
            console.print(f"[green]{chain.hex()}[/green]\n")
        else:
            console.print("[yellow]Could not build ROP chain.[/yellow]")

    except Exception as exc:
        console.print(f"[red]ROP chain generation failed: {exc}[/red]")
