//! Embedded payload generator for ARM Cortex-M and RISC-V targets.
//!
//! This crate provides shellcode templates, payload encoders, and ROP chain
//! infrastructure for authorized CTF competition use and penetration testing
//! against QEMU-emulated RTOS-based embedded systems.

pub mod encoder;
pub mod rop;
pub mod shellcode;

// Re-export key types at crate root for convenience.
pub use encoder::{get_encoder, Encoder, NullFreeEncoder, RawEncoder, XorEncoder};
pub use rop::{
    build_chain, check_chain, filter_gadgets, find_gadgets, ChainGoal, Gadget, GadgetType,
};
pub use shellcode::thumb2::{InfiniteLoop as Thumb2InfiniteLoop, MPUDisable, NopSled as Thumb2NopSled, RegisterDump, UartWrite, VTORRedirect};
pub use shellcode::riscv::{InfiniteLoop as RiscvInfiniteLoop, NopSled as RiscvNopSled, PMPDisable};
