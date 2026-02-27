//! Payload encoders for authorized CTF and pen-testing.
//!
//! Encoders transform raw shellcode to avoid bad characters (e.g., null bytes)
//! that would terminate strings or be filtered by target input handlers.

use anyhow::anyhow;

/// Common interface for all payload encoders.
pub trait Encoder: Send + Sync {
    /// Short identifier for this encoder (e.g. "raw", "xor", "nullfree").
    fn name(&self) -> &str;

    /// Encode `raw` bytes, ensuring none of `bad_chars` appear in the output.
    ///
    /// Returns the encoded payload or an error if encoding is not possible.
    fn encode(&self, raw: &[u8], bad_chars: &[u8]) -> Result<Vec<u8>, anyhow::Error>;

    /// Approximate size overhead factor (e.g. 1.0 = same size, 1.2 = 20% larger).
    fn overhead(&self) -> f32;
}

// ---------------------------------------------------------------------------
// RawEncoder — pass-through, no transformation
// ---------------------------------------------------------------------------

/// Pass-through encoder: output equals input unchanged.
pub struct RawEncoder;

impl Encoder for RawEncoder {
    fn name(&self) -> &str {
        "raw"
    }

    fn encode(&self, raw: &[u8], bad_chars: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        // Verify no bad chars are present in the raw payload.
        for &b in raw {
            if bad_chars.contains(&b) {
                return Err(anyhow!(
                    "RawEncoder: byte 0x{:02X} is in bad_chars list; use a different encoder",
                    b
                ));
            }
        }
        Ok(raw.to_vec())
    }

    fn overhead(&self) -> f32 {
        1.0
    }
}

// ---------------------------------------------------------------------------
// XorEncoder — XOR each byte with a key
// ---------------------------------------------------------------------------

/// XOR encoder: each byte is XOR'd with `key`.
///
/// If `key` itself appears in `bad_chars`, the encoder automatically selects
/// the first key in 1..=255 that produces a clean output.
pub struct XorEncoder {
    pub key: u8,
}

impl XorEncoder {
    pub fn new(key: u8) -> Self {
        Self { key }
    }

    fn encode_with_key(raw: &[u8], key: u8) -> Vec<u8> {
        raw.iter().map(|&b| b ^ key).collect()
    }

    fn is_clean(data: &[u8], bad_chars: &[u8]) -> bool {
        !data.iter().any(|b| bad_chars.contains(b))
    }
}

impl Encoder for XorEncoder {
    fn name(&self) -> &str {
        "xor"
    }

    fn encode(&self, raw: &[u8], bad_chars: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        // Try the configured key first.
        let candidate = Self::encode_with_key(raw, self.key);
        if Self::is_clean(&candidate, bad_chars) && !bad_chars.contains(&self.key) {
            return Ok(candidate);
        }

        // Key is bad or produces bad chars — search for a valid key.
        for k in 1u8..=255 {
            if bad_chars.contains(&k) {
                continue;
            }
            let encoded = Self::encode_with_key(raw, k);
            if Self::is_clean(&encoded, bad_chars) {
                return Ok(encoded);
            }
        }

        Err(anyhow!(
            "XorEncoder: no single-byte XOR key produces output free of bad chars"
        ))
    }

    fn overhead(&self) -> f32 {
        1.0
    }
}

// ---------------------------------------------------------------------------
// NullFreeEncoder — replace null bytes with a safe placeholder
// ---------------------------------------------------------------------------

/// Null-free encoder: replaces every `0x00` byte with `0x01`.
///
/// This is a simplified implementation suitable for targets that use
/// C-string semantics. For production use, a stub decoder must be prepended.
pub struct NullFreeEncoder;

impl Encoder for NullFreeEncoder {
    fn name(&self) -> &str {
        "nullfree"
    }

    fn encode(&self, raw: &[u8], _bad_chars: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let encoded: Vec<u8> = raw
            .iter()
            .map(|&b| if b == 0x00 { 0x01 } else { b })
            .collect();
        Ok(encoded)
    }

    fn overhead(&self) -> f32 {
        1.2
    }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Construct an encoder by name.
///
/// - `"raw"`      → [`RawEncoder`]
/// - `"xor"`      → [`XorEncoder`] with `key` (defaults to 0x42 if None)
/// - `"nullfree"` → [`NullFreeEncoder`]
/// - anything else → [`RawEncoder`] as fallback
pub fn get_encoder(name: &str, key: Option<u8>) -> Box<dyn Encoder> {
    match name {
        "xor" => Box::new(XorEncoder::new(key.unwrap_or(0x42))),
        "nullfree" => Box::new(NullFreeEncoder),
        _ => Box::new(RawEncoder),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_encoder_passthrough() {
        let enc = RawEncoder;
        let data = vec![0x01, 0x02, 0x03];
        assert_eq!(enc.encode(&data, &[]).unwrap(), data);
    }

    #[test]
    fn xor_encoder_round_trip() {
        let enc = XorEncoder::new(0xAA);
        let original = vec![0x01, 0x02, 0x03, 0x04];
        let encoded = enc.encode(&original, &[]).unwrap();
        let decoded = enc.encode(&encoded, &[]).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn null_free_no_nulls() {
        let enc = NullFreeEncoder;
        let data = vec![0x00, 0x01, 0x00, 0x02];
        let encoded = enc.encode(&data, &[]).unwrap();
        assert!(!encoded.contains(&0x00));
    }
}
