//! Fuzzing loop and input mutation engine.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::config::FuzzerConfig;
use crate::coverage::{CoverageBitmap, FuzzerStats};
use crate::mutators::{
    ArithmeticMutator, BitFlipMutator, BlockDeleteMutator, BlockInsertMutator,
    ByteFlipMutator, DictionaryMutator, InterestingValueMutator, MutationScheduler,
    SpliceMutator,
};

// ── ExecutionResult ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ExecutionResult {
    /// The input completed normally, producing a coverage bitmap.
    Normal { coverage: CoverageBitmap },
    /// The firmware crashed (signal, program counter, register dump).
    Crash { signal: u32, pc: u32, registers: Vec<u32> },
    /// The input caused a timeout.
    Timeout,
}

// ── FuzzerState ───────────────────────────────────────────────────────────────

pub struct FuzzerState {
    pub stats: FuzzerStats,
    pub corpus: Vec<Vec<u8>>,
    pub global_coverage: CoverageBitmap,
    running: bool,
}

// ── FuzzerEngine ──────────────────────────────────────────────────────────────

pub struct FuzzerEngine {
    config: FuzzerConfig,
    state: FuzzerState,
    rng: ChaCha8Rng,
    // Mutators (constructed once; stateless apart from DictionaryMutator).
    bit_flip: BitFlipMutator,
    byte_flip: ByteFlipMutator,
    arithmetic: ArithmeticMutator,
    interesting: InterestingValueMutator,
    block_insert: BlockInsertMutator,
    block_delete: BlockDeleteMutator,
    splice: SpliceMutator,
    dictionary: DictionaryMutator,
    scheduler: MutationScheduler,
}

impl FuzzerEngine {
    pub fn new(config: FuzzerConfig) -> Self {
        let scheduler = MutationScheduler::new(&config.mutation);

        // Load dictionary if configured.
        let dictionary = if let Some(ref path) = config.mutation.dictionary_path {
            DictionaryMutator::from_file(path).unwrap_or_else(|e| {
                log::warn!("Failed to load dictionary {}: {}", path.display(), e);
                DictionaryMutator::new(vec![])
            })
        } else {
            DictionaryMutator::new(vec![])
        };

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            config,
            state: FuzzerState {
                stats: FuzzerStats {
                    start_time_unix: now_unix,
                    last_new_edge_unix: now_unix,
                    ..Default::default()
                },
                corpus: Vec::new(),
                global_coverage: CoverageBitmap::new(),
                running: false,
            },
            rng: ChaCha8Rng::from_entropy(),
            bit_flip: BitFlipMutator::new(),
            byte_flip: ByteFlipMutator::new(),
            arithmetic: ArithmeticMutator::new(),
            interesting: InterestingValueMutator::new(),
            block_insert: BlockInsertMutator::new(),
            block_delete: BlockDeleteMutator::new(),
            splice: SpliceMutator::new(),
            dictionary,
            scheduler,
        }
    }

    /// Add a seed directly to the corpus.
    pub fn add_seed(&mut self, seed: Vec<u8>) {
        self.state.corpus.push(seed);
        self.state.stats.corpus_size = self.state.corpus.len() as u32;
    }

    /// Load all files from a directory as seeds.  Returns the number loaded.
    pub fn load_seeds_from_dir(&mut self, dir: &Path) -> anyhow::Result<usize> {
        let mut count = 0usize;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                match std::fs::read(&path) {
                    Ok(bytes) => {
                        self.add_seed(bytes);
                        count += 1;
                    }
                    Err(e) => {
                        log::warn!("Failed to read seed {}: {}", path.display(), e);
                    }
                }
            }
        }
        Ok(count)
    }

    /// Persist current stats to `<output_dir>/stats.json` and `<output_dir>/stats.csv`.
    pub fn save_stats(&self, output_dir: &Path) -> anyhow::Result<()> {
        std::fs::create_dir_all(output_dir)?;

        // JSON
        let json_path = output_dir.join("stats.json");
        std::fs::write(&json_path, self.state.stats.to_json())?;

        // CSV (append mode — create header if new file)
        let csv_path = output_dir.join("stats.csv");
        let write_header = !csv_path.exists();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&csv_path)?;
        use std::io::Write;
        if write_header {
            writeln!(file, "start_time,unique_edges,execs_per_second,corpus_size,crash_count,total_executions")?;
        }
        writeln!(file, "{}", self.state.stats.to_csv_row())?;

        Ok(())
    }

    pub fn get_stats(&self) -> &FuzzerStats {
        &self.state.stats
    }

    pub fn is_running(&self) -> bool {
        self.state.running
    }

    pub fn stop(&mut self) {
        self.state.running = false;
    }

    // ── Mutation ─────────────────────────────────────────────────────────────

    /// Pick a random input from the corpus (falls back to an empty vec).
    fn pick_corpus_input(&mut self) -> Vec<u8> {
        if self.state.corpus.is_empty() {
            return vec![0u8; 4];
        }
        use rand::Rng;
        let idx = self.rng.gen_range(0..self.state.corpus.len());
        self.state.corpus[idx].clone()
    }

    /// Apply one randomly chosen mutation to `input`.
    pub fn mutate_input(&mut self, input: &mut Vec<u8>) {
        let max = self.config.max_input_size;
        let choice = self.scheduler.select(&mut self.rng);
        match choice {
            0 => self.bit_flip.mutate(input, max, &mut self.rng),
            1 => self.byte_flip.mutate(input, max, &mut self.rng),
            2 => self.arithmetic.mutate(input, max, &mut self.rng),
            3 => self.interesting.mutate(input, max, &mut self.rng),
            4 => self.block_insert.mutate(input, max, &mut self.rng),
            5 => self.block_delete.mutate(input, max, &mut self.rng),
            6 => {
                let other = self.pick_corpus_input();
                self.splice.mutate_splice(input, &other, max, &mut self.rng);
            }
            7 => self.dictionary.mutate(input, max, &mut self.rng),
            _ => {}
        }
    }

    // ── Simulation (no QEMU required) ─────────────────────────────────────────

    /// Simulate one execution step for testing and CI without a real QEMU binary.
    ///
    /// Uses the input bytes to deterministically produce fake coverage so that
    /// corpus growth and stats tracking can be exercised end-to-end.
    pub fn simulate_execution(&mut self, input: &[u8]) -> ExecutionResult {
        self.state.stats.total_executions += 1;

        // Derive a fake "coverage" from the input content so different inputs
        // produce genuinely different bitmaps (useful for unit tests).
        let mut cov = CoverageBitmap::new();
        let mut prev: u32 = 0x0800_0000; // Simulated reset vector
        for (i, &byte) in input.iter().enumerate() {
            let next = prev.wrapping_add(byte as u32).wrapping_add(i as u32 * 4);
            cov.set_edge(prev, next);
            prev = next;
        }

        // Detect new coverage and update stats.
        if cov.has_new_coverage(&self.state.global_coverage) {
            cov.merge_into(&mut self.state.global_coverage);
            self.state.stats.unique_edges = self.state.global_coverage.count_edges();
            self.state.stats.last_new_edge_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }

        // Simulate a crash for inputs containing 0xDE 0xAD 0xBE 0xEF.
        let crash_pattern = [0xDE, 0xAD, 0xBE, 0xEF];
        if input.windows(4).any(|w| w == crash_pattern) {
            self.state.stats.crash_count += 1;
            return ExecutionResult::Crash {
                signal: 11, // SIGSEGV
                pc: 0xDEAD_BEEF,
                registers: vec![0; 16],
            };
        }

        ExecutionResult::Normal { coverage: cov }
    }
}

// ── QEMU-only integration (compiled out by default) ───────────────────────────

#[cfg(feature = "qemu")]
pub mod qemu_executor {
    //! QEMU executor integration — only compiled with `--features qemu`.
    //!
    //! This module would contain:
    //!   - QEMU process spawning with the firmware binary
    //!   - Shared-memory bitmap mapping for coverage
    //!   - MMIO interception hooks via QEMU plugins
    //!   - Crash signal handling (SIGSEGV, SIGABRT, custom watchdog)
    //!
    //! Stub retained here to document the intended extension point.

    use crate::config::FuzzerConfig;

    pub struct QemuExecutor {
        _config: FuzzerConfig,
    }

    impl QemuExecutor {
        pub fn new(config: FuzzerConfig, _firmware_path: &std::path::Path) -> anyhow::Result<Self> {
            Ok(Self { _config: config })
        }

        pub fn execute(&mut self, _input: &[u8]) -> super::ExecutionResult {
            // TODO: spawn QEMU, wait for completion, read bitmap
            unimplemented!("QEMU executor not yet implemented")
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FuzzerConfig;

    fn engine() -> FuzzerEngine {
        FuzzerEngine::new(FuzzerConfig::default_config())
    }

    #[test]
    fn add_seed_grows_corpus() {
        let mut eng = engine();
        assert_eq!(eng.state.corpus.len(), 0);
        eng.add_seed(vec![1, 2, 3]);
        assert_eq!(eng.state.corpus.len(), 1);
        assert_eq!(eng.get_stats().corpus_size, 1);
    }

    #[test]
    fn simulate_normal_execution() {
        let mut eng = engine();
        let input = vec![0xAA, 0xBB, 0xCC];
        let result = eng.simulate_execution(&input);
        assert!(matches!(result, ExecutionResult::Normal { .. }));
        assert_eq!(eng.get_stats().total_executions, 1);
    }

    #[test]
    fn simulate_crash_on_pattern() {
        let mut eng = engine();
        let input = vec![0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let result = eng.simulate_execution(&input);
        assert!(matches!(result, ExecutionResult::Crash { signal: 11, .. }));
        assert_eq!(eng.get_stats().crash_count, 1);
    }

    #[test]
    fn unique_edges_grow_with_diverse_inputs() {
        let mut eng = engine();
        let input1 = vec![0x01, 0x02, 0x03];
        let input2 = vec![0xF0, 0xE1, 0xD2, 0xC3];
        eng.simulate_execution(&input1);
        let edges_after_first = eng.get_stats().unique_edges;
        eng.simulate_execution(&input2);
        // Different inputs should produce at least as many edges
        assert!(eng.get_stats().unique_edges >= edges_after_first);
    }

    #[test]
    fn mutate_input_stays_within_max_size() {
        let mut eng = engine();
        let max = eng.config.max_input_size;
        for _ in 0..100 {
            let mut input = vec![0xAAu8; 256];
            eng.mutate_input(&mut input);
            assert!(input.len() <= max, "input grew beyond max_size: {}", input.len());
        }
    }

    #[test]
    fn is_running_starts_false() {
        let eng = engine();
        assert!(!eng.is_running());
    }

    #[test]
    fn stop_sets_running_false() {
        let mut eng = engine();
        eng.state.running = true;
        assert!(eng.is_running());
        eng.stop();
        assert!(!eng.is_running());
    }

    #[test]
    fn save_stats_creates_files() {
        let mut eng = engine();
        eng.simulate_execution(&[1, 2, 3]);
        let dir = std::env::temp_dir().join("rtosploit-fuzzer-test-stats");
        eng.save_stats(&dir).expect("save_stats failed");
        assert!(dir.join("stats.json").exists());
        assert!(dir.join("stats.csv").exists());
        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_seeds_from_dir_counts_files() {
        let dir = std::env::temp_dir().join("rtosploit-fuzzer-test-seeds");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("seed1"), b"hello").unwrap();
        std::fs::write(dir.join("seed2"), b"world").unwrap();
        let mut eng = engine();
        let count = eng.load_seeds_from_dir(&dir).expect("load_seeds_from_dir failed");
        assert_eq!(count, 2);
        assert_eq!(eng.state.corpus.len(), 2);
        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }
}
