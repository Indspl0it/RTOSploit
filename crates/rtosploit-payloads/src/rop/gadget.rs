//! ROP gadget finder for embedded binaries (ARM Thumb2 and RISC-V).
//!
//! Scans raw binary images for useful ROP gadgets ending in
//! `BX LR` or `POP {.., PC}` patterns.

use serde::{Deserialize, Serialize};

/// Semantic classification of a ROP gadget.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GadgetType {
    /// Loads values into registers (e.g. POP {R0, PC}).
    RegisterControl,
    /// Writes a value to memory (e.g. STR R0, [R1]; BX LR).
    MemoryWrite,
    /// Reads a value from memory (e.g. LDR R0, [R1]; BX LR).
    MemoryRead,
    /// Arithmetic / logic operation (e.g. ADD R0, R1; BX LR).
    Arithmetic,
    /// System-level operation (e.g. MSR, CPSID).
    System,
    /// Could not be classified.
    Unknown,
}

/// A single ROP gadget found in a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gadget {
    /// Absolute address of the first byte of this gadget in the target image.
    pub address: u32,
    /// Raw bytes of the gadget (including the terminating BX LR / POP PC).
    pub bytes: Vec<u8>,
    /// Semantic classification.
    pub gadget_type: GadgetType,
    /// Number of bytes consumed from the ROP stack (32-bit words × 4).
    pub stack_delta: usize,
    /// Human-readable description (e.g. `"POP {R0, PC}"`).
    pub description: String,
}

/// Check whether any byte of a 4-byte address (little-endian) is in `bad_chars`.
fn addr_contains_bad(addr: u32, bad_chars: &[u8]) -> bool {
    addr.to_le_bytes().iter().any(|b| bad_chars.contains(b))
}

/// Classify a gadget based on its bytes (excluding the final terminator).
///
/// Examines the bytes before the trailing BX LR / POP PC to determine
/// what the gadget does.
fn classify(body: &[u8]) -> GadgetType {
    if body.is_empty() {
        return GadgetType::Unknown;
    }

    // Walk 16-bit Thumb halfwords in the body (best-effort, not a full disassembler).
    let mut i = 0;
    while i + 1 < body.len() {
        let hi = body[i + 1];
        let _lo = body[i];

        // POP {Rlist} — high byte 0xBD or 0xBD area (pop includes PC)
        if hi & 0xFE == 0xBC {
            return GadgetType::RegisterControl;
        }

        // STR Rt, [Rn, #imm5]: 0110 0 imm5 Rn Rt → high nibble 0x60..0x67
        if hi & 0xF8 == 0x60 {
            return GadgetType::MemoryWrite;
        }

        // LDR Rt, [Rn, #imm5]: 0110 1 imm5 Rn Rt → high nibble 0x68..0x6F
        if hi & 0xF8 == 0x68 {
            return GadgetType::MemoryRead;
        }

        // ADD / SUB: 0001 1 → 0x18-0x1F or 0011 0 → 0x30-0x3F
        if ((hi & 0xFC) == 0x18) || ((hi & 0xF0) == 0x30) {
            return GadgetType::Arithmetic;
        }

        // MSR / MRS / CPSID etc. (32-bit Thumb-2 system instructions)
        if hi == 0xF3 || hi == 0xBF {
            return GadgetType::System;
        }

        i += 2;
    }

    GadgetType::Unknown
}

/// Scan `binary` (raw bytes loaded at `load_address`) for Thumb2 ROP gadgets.
///
/// A gadget is a sequence of instructions ending in:
/// - `BX LR` (`[0x70, 0x47]`)
/// - `POP {Rlist, PC}` — high byte `0xBD` with bit 8 (PC) set
///
/// Gadgets whose absolute address contains bytes in `bad_chars` are excluded.
pub fn find_gadgets(binary: &[u8], load_address: u32, bad_chars: &[u8]) -> Vec<Gadget> {
    let mut gadgets = Vec::new();

    let len = binary.len();
    if len < 2 {
        return gadgets;
    }

    // Scan for gadget terminators at 2-byte-aligned offsets.
    let mut offset = 0usize;
    while offset + 1 < len {
        let b0 = binary[offset];
        let b1 = binary[offset + 1];

        // BX LR pattern: [0x70, 0x47]
        if b0 == 0x70 && b1 == 0x47 {
            let gadget_addr = load_address.wrapping_add(offset as u32);

            if !addr_contains_bad(gadget_addr, bad_chars) {
                // Look back up to 16 bytes (8 instructions) for the gadget body.
                let start = offset.saturating_sub(16);
                // Align start to 2-byte boundary.
                let start = start & !1;

                let body = &binary[start..offset];
                let g_type = classify(body);
                let bytes = binary[start..offset + 2].to_vec();

                let description = format!("BX LR @ 0x{:08X}", gadget_addr);
                let stack_delta = 4; // BX LR consumes LR from register, not stack

                gadgets.push(Gadget {
                    address: load_address.wrapping_add(start as u32),
                    bytes,
                    gadget_type: g_type,
                    stack_delta,
                    description,
                });
            }

            offset += 2;
            continue;
        }

        // POP {Rlist, PC}: high byte 0xBD means POP with bit 8 (PC) in register list.
        // Thumb T1 POP: 1011 1 10 register_list — high byte 0xBD
        if b1 == 0xBD {
            let gadget_addr = load_address.wrapping_add(offset as u32);

            if !addr_contains_bad(gadget_addr, bad_chars) {
                let start = offset.saturating_sub(16);
                let start = start & !1;

                let body = &binary[start..offset];
                let g_type = if body.is_empty() {
                    // Pure POP {Rlist, PC} — excellent register control gadget
                    GadgetType::RegisterControl
                } else {
                    classify(body)
                };

                let bytes = binary[start..offset + 2].to_vec();

                // Count registers in the POP list to determine stack delta.
                let reg_list = b0;
                let pop_count = reg_list.count_ones() as usize + 1; // +1 for PC
                let stack_delta = pop_count * 4;

                let description = format!(
                    "POP {{Rlist=0x{:02X}, PC}} @ 0x{:08X}",
                    reg_list, gadget_addr
                );

                gadgets.push(Gadget {
                    address: load_address.wrapping_add(start as u32),
                    bytes,
                    gadget_type: g_type,
                    stack_delta,
                    description,
                });
            }

            offset += 2;
            continue;
        }

        offset += 2;
    }

    gadgets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_bxlr() {
        // Simple BX LR at offset 0
        let binary = vec![0x70, 0x47];
        let gadgets = find_gadgets(&binary, 0x2000_0000, &[]);
        assert!(!gadgets.is_empty());
    }

    #[test]
    fn filters_bad_addr() {
        // BX LR at address 0x2000_0000 — address contains 0x00 byte
        let binary = vec![0x70, 0x47];
        let gadgets = find_gadgets(&binary, 0x2000_0000, &[0x00]);
        assert!(gadgets.is_empty());
    }
}
