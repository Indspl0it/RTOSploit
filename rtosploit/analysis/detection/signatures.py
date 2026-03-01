"""Binary instruction patterns for HAL init sequence matching."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SignaturePattern:
    """A binary signature pattern for a known HAL initialization sequence."""
    name: str
    vendor: str
    peripheral: str
    peripheral_type: str
    anchor_bytes: bytes        # Byte pattern to search for (fast scan)
    anchor_mask: bytes         # Mask for anchor bytes (0xFF = exact match)
    expected_mnemonics: list[str]  # Expected mnemonic subsequence around anchor
    pre_context_bytes: int = 16   # Bytes to check before anchor
    post_context_bytes: int = 32  # Bytes to check after anchor

    def matches_sequence(self, mnemonics: list[str]) -> bool:
        """Check if expected mnemonics appear as a subsequence."""
        exp_idx = 0
        for m in mnemonics:
            if exp_idx >= len(self.expected_mnemonics):
                break
            if m == self.expected_mnemonics[exp_idx]:
                exp_idx += 1
        return exp_idx >= len(self.expected_mnemonics)


# STM32 UART init signature:
# RCC clock enable -> GPIO AF config -> USART_BRR write -> USART_CR1 enable
# The anchor is the USART_BRR write pattern (STR to USART base + 0x08)
SIGNATURES: list[SignaturePattern] = [
    SignaturePattern(
        name="stm32_uart_init",
        vendor="stm32",
        peripheral="UART",
        peripheral_type="uart",
        # STR Rx, [Ry, #0x08] — BRR register write (Thumb2: 60xx or 6xxx pattern)
        anchor_bytes=bytes([0x00, 0x60]),
        anchor_mask=bytes([0x00, 0xF8]),
        expected_mnemonics=["movw", "movt", "str", "ldr", "str"],
        pre_context_bytes=32,
        post_context_bytes=32,
    ),
    SignaturePattern(
        name="stm32_spi_init",
        vendor="stm32",
        peripheral="SPI",
        peripheral_type="spi",
        # SPI_CR1 write pattern
        anchor_bytes=bytes([0x00, 0x60]),
        anchor_mask=bytes([0x00, 0xF8]),
        expected_mnemonics=["movw", "movt", "str", "str"],
        pre_context_bytes=32,
        post_context_bytes=16,
    ),
    SignaturePattern(
        name="nrf52_uart_init",
        vendor="nrf5",
        peripheral="UART",
        peripheral_type="uart",
        # TASKS_STARTRX = 1 pattern: MOV R0, #1; STR R0, [Rn, #0]
        anchor_bytes=bytes([0x01, 0x20]),  # MOVS R0, #1
        anchor_mask=bytes([0xFF, 0xFF]),
        expected_mnemonics=["movs", "str", "str"],
        pre_context_bytes=16,
        post_context_bytes=32,
    ),
    SignaturePattern(
        name="nrf52_spi_init",
        vendor="nrf5",
        peripheral="SPI",
        peripheral_type="spi",
        anchor_bytes=bytes([0x01, 0x20]),  # MOVS R0, #1
        anchor_mask=bytes([0xFF, 0xFF]),
        expected_mnemonics=["movs", "str", "ldr", "str"],
        pre_context_bytes=16,
        post_context_bytes=32,
    ),
]
