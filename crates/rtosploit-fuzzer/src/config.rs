//! Fuzzer configuration: loaded from YAML presets or built with defaults.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

// ── Flat config used throughout the engine ───────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzerConfig {
    pub timeout_ms: u64,
    pub watchdog_ms: u64,
    pub memory_limit_mb: u64,
    pub corpus_max_size: usize,
    pub crash_dedup: bool,
    pub coverage_mode: CoverageMode,
    pub mutation: MutationConfig,
    pub mmio: MMIOConfig,
    pub jobs: usize,
    pub max_input_size: usize,
    pub seed_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageMode {
    EdgeCoverage,
    BlockCoverage,
    MMIOAware,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutationConfig {
    pub bit_flip_weight: u32,
    pub byte_flip_weight: u32,
    pub arithmetic_weight: u32,
    pub interesting_value_weight: u32,
    pub block_insert_weight: u32,
    pub block_delete_weight: u32,
    pub splice_weight: u32,
    pub dictionary_weight: u32,
    pub dictionary_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MMIOConfig {
    pub enabled: bool,
    pub pool_size: usize,
    pub interesting_value_boost: u32,
}

// ── YAML file shape (nested) ──────────────────────────────────────────────────

/// Mirrors the nested structure of `configs/fuzzer/*.yaml`.
#[derive(Debug, Deserialize)]
struct YamlRoot {
    fuzzer: YamlFuzzer,
    #[serde(default)]
    coverage: YamlCoverage,
    #[serde(default)]
    mutation: YamlMutation,
}

#[derive(Debug, Deserialize)]
struct YamlFuzzer {
    timeout_ms: u64,
    #[serde(default = "default_watchdog_ms")]
    watchdog_ms: u64,
    #[serde(default = "default_memory_limit_mb")]
    memory_limit_mb: u64,
    #[serde(default = "default_corpus_max_size")]
    corpus_max_size: usize,
    #[serde(default = "bool_true")]
    crash_dedup: bool,
}

#[derive(Debug, Deserialize, Default)]
struct YamlCoverage {
    #[serde(default)]
    mode: String,
}

#[derive(Debug, Deserialize, Default)]
struct YamlMutation {
    #[serde(default = "default_max_input_size")]
    max_input_size: usize,
    #[serde(default = "default_mmio_pool_size")]
    mmio_pool_size: usize,
    #[serde(default)]
    dictionary: Option<PathBuf>,
}

fn default_watchdog_ms() -> u64 { 30_000 }
fn default_memory_limit_mb() -> u64 { 256 }
fn default_corpus_max_size() -> usize { 10_000 }
fn default_max_input_size() -> usize { 4096 }
fn default_mmio_pool_size() -> usize { 256 }
fn bool_true() -> bool { true }

// ── Construction ─────────────────────────────────────────────────────────────

impl FuzzerConfig {
    /// Load from a YAML preset file (configs/fuzzer/*.yaml).
    pub fn from_yaml(path: &std::path::Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let root: YamlRoot = serde_yaml::from_str(&contents)?;

        let coverage_mode = match root.coverage.mode.as_str() {
            "edge+mmio" => CoverageMode::MMIOAware,
            "block" => CoverageMode::BlockCoverage,
            _ => CoverageMode::EdgeCoverage,
        };

        let mmio_enabled = coverage_mode == CoverageMode::MMIOAware;

        Ok(Self {
            timeout_ms: root.fuzzer.timeout_ms,
            watchdog_ms: root.fuzzer.watchdog_ms,
            memory_limit_mb: root.fuzzer.memory_limit_mb,
            corpus_max_size: root.fuzzer.corpus_max_size,
            crash_dedup: root.fuzzer.crash_dedup,
            coverage_mode,
            jobs: 1,
            max_input_size: root.mutation.max_input_size,
            seed_timeout_ms: root.fuzzer.timeout_ms * 5,
            mutation: MutationConfig {
                bit_flip_weight: 20,
                byte_flip_weight: 20,
                arithmetic_weight: 15,
                interesting_value_weight: 15,
                block_insert_weight: 10,
                block_delete_weight: 10,
                splice_weight: 5,
                dictionary_weight: 5,
                dictionary_path: root.mutation.dictionary,
            },
            mmio: MMIOConfig {
                enabled: mmio_enabled,
                pool_size: root.mutation.mmio_pool_size,
                interesting_value_boost: 10,
            },
        })
    }

    /// Sensible defaults matching configs/fuzzer/default.yaml.
    pub fn default_config() -> Self {
        Self {
            timeout_ms: 1000,
            watchdog_ms: 30_000,
            memory_limit_mb: 512,
            corpus_max_size: 10_000,
            crash_dedup: true,
            coverage_mode: CoverageMode::MMIOAware,
            jobs: 1,
            max_input_size: 4096,
            seed_timeout_ms: 5000,
            mutation: MutationConfig {
                bit_flip_weight: 20,
                byte_flip_weight: 20,
                arithmetic_weight: 15,
                interesting_value_weight: 15,
                block_insert_weight: 10,
                block_delete_weight: 10,
                splice_weight: 5,
                dictionary_weight: 5,
                dictionary_path: None,
            },
            mmio: MMIOConfig {
                enabled: true,
                pool_size: 256,
                interesting_value_boost: 10,
            },
        }
    }

    /// Sum of all mutation weights (used for validation).
    pub fn total_mutation_weight(&self) -> u32 {
        let m = &self.mutation;
        m.bit_flip_weight
            + m.byte_flip_weight
            + m.arithmetic_weight
            + m.interesting_value_weight
            + m.block_insert_weight
            + m.block_delete_weight
            + m.splice_weight
            + m.dictionary_weight
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn default_config_weights_sum_to_100() {
        let cfg = FuzzerConfig::default_config();
        assert_eq!(cfg.total_mutation_weight(), 100);
    }

    #[test]
    fn load_default_yaml() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(manifest)
            .join("../../configs/fuzzer/default.yaml");
        let cfg = FuzzerConfig::from_yaml(&path).expect("parse default.yaml");
        assert_eq!(cfg.timeout_ms, 1000);
        assert_eq!(cfg.corpus_max_size, 10_000);
        assert!(cfg.crash_dedup);
    }

    #[test]
    fn load_fast_yaml() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(manifest)
            .join("../../configs/fuzzer/fast.yaml");
        FuzzerConfig::from_yaml(&path).expect("parse fast.yaml");
    }

    #[test]
    fn load_thorough_yaml() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let path = Path::new(manifest)
            .join("../../configs/fuzzer/thorough.yaml");
        let cfg = FuzzerConfig::from_yaml(&path).expect("parse thorough.yaml");
        assert_eq!(cfg.coverage_mode, CoverageMode::MMIOAware);
    }
}
