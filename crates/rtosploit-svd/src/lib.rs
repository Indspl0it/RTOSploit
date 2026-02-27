//! SVD Peripheral Stub Generator for QEMU MCU emulation.
//!
//! Parses ARM CMSIS SVD files and generates C peripheral stubs
//! compatible with QEMU's device model API.

pub mod parser;
pub mod registry;
pub mod stub;
