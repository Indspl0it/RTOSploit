//! Bad-character filtering for ROP gadgets and chains.
//!
//! Many input vulnerabilities (stack overflows via strcpy, etc.) have
//! restricted byte sets. These helpers filter out gadgets/chains whose
//! addresses or bytes contain disallowed characters.

use super::gadget::Gadget;

/// Filter out gadgets whose address contains any byte in `bad_chars`.
///
/// A gadget is usable only if its address (as a 4-byte LE value) contains
/// no bytes from the bad-character set.
pub fn filter_gadgets(gadgets: &[Gadget], bad_chars: &[u8]) -> Vec<Gadget> {
    if bad_chars.is_empty() {
        return gadgets.to_vec();
    }

    gadgets
        .iter()
        .filter(|g| {
            let addr_bytes = g.address.to_le_bytes();
            !addr_bytes.iter().any(|b| bad_chars.contains(b))
        })
        .cloned()
        .collect()
}

/// Check whether a ROP chain (flat byte sequence) is free of `bad_chars`.
///
/// Returns `true` if none of the bytes in `chain` appear in `bad_chars`.
pub fn check_chain(chain: &[u8], bad_chars: &[u8]) -> bool {
    if bad_chars.is_empty() {
        return true;
    }
    !chain.iter().any(|b| bad_chars.contains(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rop::gadget::{Gadget, GadgetType};

    fn make_gadget(addr: u32) -> Gadget {
        Gadget {
            address: addr,
            bytes: vec![0x70, 0x47],
            gadget_type: GadgetType::Unknown,
            stack_delta: 0,
            description: format!("BX LR @ 0x{:08X}", addr),
        }
    }

    #[test]
    fn filter_removes_bad_addr() {
        let gadgets = vec![
            make_gadget(0x0800_0100), // contains 0x00 bytes
            make_gadget(0x0801_0204), // also contains 0x00 ... let's use clean ones
        ];
        // 0x00 is common bad char; addr 0x0800_0100 contains it
        let filtered = filter_gadgets(&gadgets, &[0x00]);
        // All addresses here contain 0x00, so all get filtered
        assert!(filtered.is_empty());
    }

    #[test]
    fn filter_keeps_clean_gadgets() {
        let gadgets = vec![make_gadget(0x0801_0204)];
        // No 0x0A bad char in this address
        let filtered = filter_gadgets(&gadgets, &[0x0A]);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn check_chain_clean() {
        let chain = vec![0x01, 0x02, 0x03, 0x04];
        assert!(check_chain(&chain, &[0x00]));
    }

    #[test]
    fn check_chain_dirty() {
        let chain = vec![0x01, 0x00, 0x03];
        assert!(!check_chain(&chain, &[0x00]));
    }
}
