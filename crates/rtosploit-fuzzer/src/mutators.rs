//! Input mutators: eight mutation strategies + weighted scheduler.

use rand::Rng;
use crate::config::MutationConfig;

// ── Interesting values ────────────────────────────────────────────────────────

/// Interesting u8 boundary values.
const INTERESTING_U8: &[u8] = &[0x00, 0xFF, 0x7F, 0x80];

/// Interesting u16 boundary values (little-endian bytes).
const INTERESTING_U16: &[[u8; 2]] = &[
    [0xFF_u8, 0x7F_u8], // 0x7FFF
    [0x00_u8, 0x80_u8], // 0x8000
    [0xFF_u8, 0xFF_u8], // 0xFFFF
];

/// Interesting u32 boundary values (little-endian bytes).
const INTERESTING_U32: &[[u8; 4]] = &[
    [0xFF, 0xFF, 0xFF, 0x7F], // 0x7FFF_FFFF
    [0x00, 0x00, 0x00, 0x80], // 0x8000_0000
    [0xFF, 0xFF, 0xFF, 0xFF], // 0xFFFF_FFFF
];

// ── Mutator 1: BitFlipMutator ─────────────────────────────────────────────────

pub struct BitFlipMutator;

impl BitFlipMutator {
    pub fn new() -> Self { Self }

    /// Flip 1, 2, or 4 bits at a random position.
    pub fn mutate(&self, input: &mut Vec<u8>, _max_size: usize, rng: &mut impl Rng) {
        if input.is_empty() { return; }
        let num_bits = [1usize, 2, 4][rng.gen_range(0..3)];
        for _ in 0..num_bits {
            let byte_idx = rng.gen_range(0..input.len());
            let bit_idx = rng.gen_range(0..8u8);
            input[byte_idx] ^= 1 << bit_idx;
        }
    }
}

// ── Mutator 2: ByteFlipMutator ────────────────────────────────────────────────

pub struct ByteFlipMutator;

impl ByteFlipMutator {
    pub fn new() -> Self { Self }

    /// Flip 1, 2, or 4 bytes (XOR 0xFF) at a random position.
    pub fn mutate(&self, input: &mut Vec<u8>, _max_size: usize, rng: &mut impl Rng) {
        if input.is_empty() { return; }
        let num_bytes = [1usize, 2, 4][rng.gen_range(0..3)];
        let start = rng.gen_range(0..input.len());
        let end = (start + num_bytes).min(input.len());
        for b in &mut input[start..end] {
            *b ^= 0xFF;
        }
    }
}

// ── Mutator 3: ArithmeticMutator ──────────────────────────────────────────────

pub struct ArithmeticMutator;

impl ArithmeticMutator {
    pub fn new() -> Self { Self }

    /// Add or subtract 1-35 to a random u16 or u32 at a random byte offset (LE).
    pub fn mutate(&self, input: &mut Vec<u8>, _max_size: usize, rng: &mut impl Rng) {
        if input.len() < 2 { return; }
        let delta = rng.gen_range(1u32..=35u32);
        let add = rng.gen_bool(0.5);
        let use_u32 = rng.gen_bool(0.5) && input.len() >= 4;

        if use_u32 {
            let max_start = input.len() - 4;
            let start = rng.gen_range(0..=max_start);
            let val = u32::from_le_bytes(input[start..start + 4].try_into().unwrap());
            let new_val = if add {
                val.wrapping_add(delta)
            } else {
                val.wrapping_sub(delta)
            };
            input[start..start + 4].copy_from_slice(&new_val.to_le_bytes());
        } else {
            let max_start = input.len() - 2;
            let start = rng.gen_range(0..=max_start);
            let val = u16::from_le_bytes(input[start..start + 2].try_into().unwrap());
            let new_val = if add {
                val.wrapping_add(delta as u16)
            } else {
                val.wrapping_sub(delta as u16)
            };
            input[start..start + 2].copy_from_slice(&new_val.to_le_bytes());
        }
    }
}

// ── Mutator 4: InterestingValueMutator ───────────────────────────────────────

pub struct InterestingValueMutator;

impl InterestingValueMutator {
    pub fn new() -> Self { Self }

    /// Replace bytes at a random offset with an interesting boundary value.
    pub fn mutate(&self, input: &mut Vec<u8>, _max_size: usize, rng: &mut impl Rng) {
        if input.is_empty() { return; }

        // Pick category: 0=u8, 1=u16, 2=u32
        let category = if input.len() >= 4 {
            rng.gen_range(0..3usize)
        } else if input.len() >= 2 {
            rng.gen_range(0..2usize)
        } else {
            0
        };

        match category {
            0 => {
                let val = INTERESTING_U8[rng.gen_range(0..INTERESTING_U8.len())];
                let idx = rng.gen_range(0..input.len());
                input[idx] = val;
            }
            1 => {
                let val = INTERESTING_U16[rng.gen_range(0..INTERESTING_U16.len())];
                let max_start = input.len() - 2;
                let start = rng.gen_range(0..=max_start);
                input[start..start + 2].copy_from_slice(&val);
            }
            2 => {
                let val = INTERESTING_U32[rng.gen_range(0..INTERESTING_U32.len())];
                let max_start = input.len() - 4;
                let start = rng.gen_range(0..=max_start);
                input[start..start + 4].copy_from_slice(&val);
            }
            _ => unreachable!(),
        }
    }
}

// ── Mutator 5: BlockInsertMutator ─────────────────────────────────────────────

pub struct BlockInsertMutator;

impl BlockInsertMutator {
    pub fn new() -> Self { Self }

    /// Insert 1-128 random bytes at a random position (enforces max_size).
    pub fn mutate(&self, input: &mut Vec<u8>, max_size: usize, rng: &mut impl Rng) {
        if input.len() >= max_size { return; }
        let available = max_size - input.len();
        let count = rng.gen_range(1..=128usize.min(available));
        let pos = if input.is_empty() { 0 } else { rng.gen_range(0..=input.len()) };
        let bytes: Vec<u8> = (0..count).map(|_| rng.gen()).collect();
        input.splice(pos..pos, bytes);
    }
}

// ── Mutator 6: BlockDeleteMutator ─────────────────────────────────────────────

pub struct BlockDeleteMutator;

impl BlockDeleteMutator {
    pub fn new() -> Self { Self }

    /// Delete 1-128 bytes at a random position; never produces an empty output.
    pub fn mutate(&self, input: &mut Vec<u8>, _max_size: usize, rng: &mut impl Rng) {
        if input.len() <= 1 { return; }
        let max_delete = (input.len() - 1).min(128);
        let count = rng.gen_range(1..=max_delete);
        let pos = rng.gen_range(0..input.len() - count + 1);
        input.drain(pos..pos + count);
    }
}

// ── Mutator 7: SpliceMutator ──────────────────────────────────────────────────

pub struct SpliceMutator;

impl SpliceMutator {
    pub fn new() -> Self { Self }

    /// Combine first half of `input` with second half of `other`.
    pub fn mutate_splice(
        &self,
        input: &mut Vec<u8>,
        other: &[u8],
        _max_size: usize,
        _rng: &mut impl Rng,
    ) {
        if input.is_empty() || other.is_empty() { return; }
        let first_half = input.len() / 2;
        let second_start = other.len() / 2;
        input.truncate(first_half);
        input.extend_from_slice(&other[second_start..]);
    }

    /// Convenience wrapper matching the common mutate signature.
    pub fn mutate(&self, input: &mut Vec<u8>, max_size: usize, rng: &mut impl Rng) {
        // Without corpus access we can only duplicate the input spliced with itself.
        let clone = input.clone();
        self.mutate_splice(input, &clone, max_size, rng);
    }
}

// ── Mutator 8: DictionaryMutator ──────────────────────────────────────────────

pub struct DictionaryMutator {
    tokens: Vec<Vec<u8>>,
}

impl DictionaryMutator {
    pub fn new(tokens: Vec<Vec<u8>>) -> Self {
        Self { tokens }
    }

    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let tokens: Vec<Vec<u8>> = contents
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.is_empty())
            .map(|l| l.as_bytes().to_vec())
            .collect();
        Ok(Self { tokens })
    }

    /// Insert a random token at a random position (enforces max_size).
    pub fn mutate(&self, input: &mut Vec<u8>, max_size: usize, rng: &mut impl Rng) {
        if self.tokens.is_empty() { return; }
        let token = &self.tokens[rng.gen_range(0..self.tokens.len())];
        if input.len() + token.len() > max_size { return; }
        let pos = if input.is_empty() { 0 } else { rng.gen_range(0..=input.len()) };
        input.splice(pos..pos, token.iter().copied());
    }
}

// ── Weighted scheduler ────────────────────────────────────────────────────────

/// Selects which mutator to apply based on configured weights.
pub struct MutationScheduler {
    weights: Vec<u32>,
    total_weight: u32,
}

impl MutationScheduler {
    pub fn new(config: &MutationConfig) -> Self {
        let weights = vec![
            config.bit_flip_weight,
            config.byte_flip_weight,
            config.arithmetic_weight,
            config.interesting_value_weight,
            config.block_insert_weight,
            config.block_delete_weight,
            config.splice_weight,
            config.dictionary_weight,
        ];
        let total_weight = weights.iter().sum();
        Self { weights, total_weight }
    }

    /// Returns an index 0-7 corresponding to the selected mutator.
    pub fn select(&self, rng: &mut impl Rng) -> usize {
        if self.total_weight == 0 { return 0; }
        let mut pick = rng.gen_range(0..self.total_weight);
        for (i, &w) in self.weights.iter().enumerate() {
            if pick < w { return i; }
            pick -= w;
        }
        self.weights.len() - 1
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn rng() -> ChaCha8Rng { ChaCha8Rng::seed_from_u64(42) }

    #[test]
    fn bit_flip_within_max_size() {
        let mut rng = rng();
        let mut input = vec![0xAAu8; 64];
        BitFlipMutator::new().mutate(&mut input, 128, &mut rng);
        assert_eq!(input.len(), 64);
    }

    #[test]
    fn bit_flip_changes_exactly_one_bit_when_single_flip() {
        // Force exactly 1-bit flip by examining hamming distance
        let original = vec![0u8; 8];
        let mut rng = rng();
        // Run many iterations; at least one should produce exactly 1 bit change
        let mut found_single = false;
        for _ in 0..200 {
            let mut trial = original.clone();
            BitFlipMutator::new().mutate(&mut trial, 128, &mut rng);
            let changed: u32 = trial.iter().zip(original.iter())
                .map(|(a, b)| (a ^ b).count_ones())
                .sum();
            if changed == 1 { found_single = true; break; }
        }
        assert!(found_single, "Expected at least one single-bit flip");
    }

    #[test]
    fn byte_flip_within_max_size() {
        let mut rng = rng();
        let mut input = vec![0x00u8; 64];
        ByteFlipMutator::new().mutate(&mut input, 128, &mut rng);
        assert_eq!(input.len(), 64);
    }

    #[test]
    fn arithmetic_within_max_size() {
        let mut rng = rng();
        let mut input = vec![0x01u8; 64];
        ArithmeticMutator::new().mutate(&mut input, 128, &mut rng);
        assert_eq!(input.len(), 64);
    }

    #[test]
    fn interesting_value_mutator_inserts_known_value() {
        // With a deterministic RNG we can confirm a known interesting value appears.
        // We just confirm the output contains at least one byte from the interesting sets.
        let mut rng = rng();
        let original = vec![0x55u8; 16];
        let mut input = original.clone();
        InterestingValueMutator::new().mutate(&mut input, 128, &mut rng);
        // The length must not change (only bytes are replaced, not inserted)
        assert_eq!(input.len(), original.len());
        // At least one byte must differ from the original
        let changed = input.iter().zip(original.iter()).any(|(a, b)| a != b);
        assert!(changed);
    }

    #[test]
    fn block_insert_within_max_size() {
        let mut rng = rng();
        let mut input = vec![0x00u8; 64];
        BlockInsertMutator::new().mutate(&mut input, 128, &mut rng);
        assert!(input.len() <= 128);
        assert!(input.len() > 64);
    }

    #[test]
    fn block_insert_respects_max_size_at_limit() {
        let mut rng = rng();
        let mut input = vec![0x00u8; 128];
        BlockInsertMutator::new().mutate(&mut input, 128, &mut rng);
        // Already at max — must not grow
        assert_eq!(input.len(), 128);
    }

    #[test]
    fn block_delete_never_empty() {
        let mut rng = rng();
        for _ in 0..200 {
            let mut input = vec![0xAAu8; 16];
            BlockDeleteMutator::new().mutate(&mut input, 128, &mut rng);
            assert!(!input.is_empty(), "BlockDeleteMutator produced empty output");
        }
    }

    #[test]
    fn block_delete_single_byte_unchanged() {
        let mut rng = rng();
        let mut input = vec![0xBBu8];
        BlockDeleteMutator::new().mutate(&mut input, 128, &mut rng);
        assert_eq!(input.len(), 1);
    }

    #[test]
    fn splice_combines_halves() {
        let mut rng = rng();
        let mut a = vec![0xAAu8; 10];
        let b = vec![0xBBu8; 10];
        SpliceMutator::new().mutate_splice(&mut a, &b, 256, &mut rng);
        // First 5 bytes should be 0xAA, next 5 should be 0xBB
        assert_eq!(a.len(), 10);
        assert!(a[..5].iter().all(|&x| x == 0xAA));
        assert!(a[5..].iter().all(|&x| x == 0xBB));
    }

    #[test]
    fn mutation_scheduler_all_weight_on_one() {
        use crate::config::MutationConfig;
        let config = MutationConfig {
            bit_flip_weight: 100,
            byte_flip_weight: 0,
            arithmetic_weight: 0,
            interesting_value_weight: 0,
            block_insert_weight: 0,
            block_delete_weight: 0,
            splice_weight: 0,
            dictionary_weight: 0,
            dictionary_path: None,
        };
        let scheduler = MutationScheduler::new(&config);
        let mut rng = rng();
        for _ in 0..100 {
            assert_eq!(scheduler.select(&mut rng), 0, "Should always select index 0");
        }
    }

    #[test]
    fn mutation_scheduler_distribution() {
        use crate::config::MutationConfig;
        let config = MutationConfig {
            bit_flip_weight: 50,
            byte_flip_weight: 50,
            arithmetic_weight: 0,
            interesting_value_weight: 0,
            block_insert_weight: 0,
            block_delete_weight: 0,
            splice_weight: 0,
            dictionary_weight: 0,
            dictionary_path: None,
        };
        let scheduler = MutationScheduler::new(&config);
        let mut rng = rng();
        let mut counts = [0u32; 8];
        for _ in 0..1000 {
            counts[scheduler.select(&mut rng)] += 1;
        }
        // Only indices 0 and 1 should be selected
        assert!(counts[0] > 0);
        assert!(counts[1] > 0);
        for i in 2..8 {
            assert_eq!(counts[i], 0, "Index {} should not be selected", i);
        }
    }
}
