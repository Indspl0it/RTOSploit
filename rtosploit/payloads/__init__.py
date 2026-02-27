"""
Payload generation utilities for authorized CTF and penetration testing.

Provides shellcode templates and ROP chain infrastructure for QEMU-emulated
ARM Cortex-M (FreeRTOS, ThreadX, Zephyr) and RISC-V embedded systems.

Example
-------
>>> from rtosploit.payloads import ShellcodeGenerator, ROPHelper
>>> gen = ShellcodeGenerator()
>>> gen.nop_sled("arm", 8)
b'\\x00F\\x00F\\x00F\\x00F\\x00F\\x00F\\x00F\\x00F'
"""

from .shellcode import ShellcodeGenerator
from .rop import ROPHelper

__all__ = ["ShellcodeGenerator", "ROPHelper"]
