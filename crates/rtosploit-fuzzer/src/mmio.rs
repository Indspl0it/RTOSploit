//! MMIO-aware input generation for peripheral-aware fuzzing.
//!
//! Each fuzzer input is logically split into two regions:
//!   - **app_input**: bytes consumed by the firmware application code.
//!   - **mmio_pool**: bytes consumed cyclically to answer MMIO read accesses.
//!
//! The splitter operates on a contiguous byte buffer so the fuzzer's mutation
//! engine treats both regions uniformly without special-casing.

// ── MMIOInputSplitter ─────────────────────────────────────────────────────────

/// Splits a flat input buffer into an app-input region and an MMIO response pool.
pub struct MMIOInputSplitter {
    pool_size: usize,
}

impl MMIOInputSplitter {
    pub fn new(pool_size: usize) -> Self {
        Self { pool_size }
    }

    /// Returns `(app_input, mmio_pool)`.
    ///
    /// The last `pool_size` bytes are the MMIO pool; the rest is app input.
    /// If the input is shorter than `pool_size` the entire input becomes the pool
    /// and `app_input` is empty.
    pub fn split<'a>(&self, input: &'a [u8]) -> (&'a [u8], &'a [u8]) {
        if input.len() <= self.pool_size {
            (&[], input)
        } else {
            let split = input.len() - self.pool_size;
            (&input[..split], &input[split..])
        }
    }
}

// ── MMIOResponseProvider ──────────────────────────────────────────────────────

/// Provides deterministic MMIO read responses from a pool of bytes.
///
/// When the cursor reaches the end of the pool it wraps back to the beginning,
/// so firmware that performs many MMIO reads is still served without panicking.
pub struct MMIOResponseProvider<'a> {
    pool: &'a [u8],
    cursor: usize,
}

impl<'a> MMIOResponseProvider<'a> {
    pub fn new(pool: &'a [u8]) -> Self {
        Self { pool, cursor: 0 }
    }

    /// Consume one byte, wrapping around when exhausted.
    pub fn read_u8(&mut self) -> u8 {
        if self.pool.is_empty() { return 0; }
        let val = self.pool[self.cursor % self.pool.len()];
        self.cursor = (self.cursor + 1) % self.pool.len();
        val
    }

    /// Consume two bytes as a little-endian u16, wrapping as needed.
    pub fn read_u16(&mut self) -> u16 {
        let lo = self.read_u8() as u16;
        let hi = self.read_u8() as u16;
        lo | (hi << 8)
    }

    /// Consume four bytes as a little-endian u32, wrapping as needed.
    pub fn read_u32(&mut self) -> u32 {
        let b0 = self.read_u8() as u32;
        let b1 = self.read_u8() as u32;
        let b2 = self.read_u8() as u32;
        let b3 = self.read_u8() as u32;
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    /// Reset cursor to the beginning of the pool.
    pub fn reset(&mut self) {
        self.cursor = 0;
    }
}

// ── MMIO access log ───────────────────────────────────────────────────────────

/// A single MMIO access captured during emulation.
#[derive(Debug, Clone)]
pub struct MMIOAccessLog {
    pub address: u32,
    pub value: u32,
    pub pc: u32,
    pub access_type: AccessType,
}

#[derive(Debug, Clone)]
pub enum AccessType {
    Read,
    Write,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── MMIOInputSplitter ────────────────────────────────────────────────────

    #[test]
    fn split_100_bytes_pool_32() {
        let input: Vec<u8> = (0..100).collect();
        let splitter = MMIOInputSplitter::new(32);
        let (app, pool) = splitter.split(&input);
        assert_eq!(app.len(), 68, "app_input should be 68 bytes");
        assert_eq!(pool.len(), 32, "mmio_pool should be 32 bytes");
        assert_eq!(app, &input[..68]);
        assert_eq!(pool, &input[68..]);
    }

    #[test]
    fn split_input_shorter_than_pool_size() {
        let input: Vec<u8> = vec![0xAA; 10];
        let splitter = MMIOInputSplitter::new(32);
        let (app, pool) = splitter.split(&input);
        assert!(app.is_empty(), "app_input should be empty when input < pool_size");
        assert_eq!(pool.len(), 10, "pool should be the entire input");
    }

    #[test]
    fn split_exactly_pool_size() {
        let input: Vec<u8> = vec![0xFF; 32];
        let splitter = MMIOInputSplitter::new(32);
        let (app, pool) = splitter.split(&input);
        assert!(app.is_empty());
        assert_eq!(pool.len(), 32);
    }

    #[test]
    fn split_empty_input() {
        let input: Vec<u8> = vec![];
        let splitter = MMIOInputSplitter::new(32);
        let (app, pool) = splitter.split(&input);
        assert!(app.is_empty());
        assert!(pool.is_empty());
    }

    // ── MMIOResponseProvider ─────────────────────────────────────────────────

    #[test]
    fn read_u32_little_endian() {
        let pool = [0x01u8, 0x02, 0x03, 0x04];
        let mut provider = MMIOResponseProvider::new(&pool);
        let val = provider.read_u32();
        // Little-endian: 0x04030201
        assert_eq!(val, 0x04030201u32, "Expected LE 0x04030201, got 0x{:08X}", val);
    }

    #[test]
    fn read_u16_little_endian() {
        let pool = [0xABu8, 0xCD];
        let mut provider = MMIOResponseProvider::new(&pool);
        let val = provider.read_u16();
        assert_eq!(val, 0xCDABu16);
    }

    #[test]
    fn cursor_wraps_around() {
        let pool = [0x11u8, 0x22, 0x33];
        let mut provider = MMIOResponseProvider::new(&pool);
        // Read 3 bytes to exhaust the pool
        assert_eq!(provider.read_u8(), 0x11);
        assert_eq!(provider.read_u8(), 0x22);
        assert_eq!(provider.read_u8(), 0x33);
        // Wrap: next read returns first byte again
        assert_eq!(provider.read_u8(), 0x11);
    }

    #[test]
    fn reset_restarts_from_beginning() {
        let pool = [0xAAu8, 0xBB];
        let mut provider = MMIOResponseProvider::new(&pool);
        assert_eq!(provider.read_u8(), 0xAA);
        provider.reset();
        assert_eq!(provider.read_u8(), 0xAA, "reset should restart from index 0");
    }

    #[test]
    fn empty_pool_returns_zero() {
        let pool = [];
        let mut provider = MMIOResponseProvider::new(&pool);
        assert_eq!(provider.read_u8(), 0);
        assert_eq!(provider.read_u16(), 0);
        assert_eq!(provider.read_u32(), 0);
    }
}
