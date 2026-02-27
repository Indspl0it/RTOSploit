//! Corpus management: seed loading, queue, crash storage.

use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use crate::coverage::CoverageBitmap;
use crate::crash::CrashReport;

/// Metadata stored alongside each corpus entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub id: u64,
    pub parent_id: Option<u64>,
    pub filename: String,
    pub time_ms: u64,     // time when discovered
    pub exec_count: u64,  // executions when discovered
    pub mutator: String,  // which mutator produced this
    pub new_edges: u32,   // new coverage edges introduced
}

pub struct Corpus {
    pub output_dir: PathBuf,
    entries: Vec<CorpusEntry>,
    next_id: u64,
    max_size: usize,
}

impl Corpus {
    pub fn new(output_dir: PathBuf, max_size: usize) -> anyhow::Result<Self> {
        // Create directory structure
        for subdir in &["seed", "queue", "crashes", "timeouts", ".state"] {
            fs::create_dir_all(output_dir.join(subdir))?;
        }
        Ok(Self {
            output_dir,
            entries: Vec::new(),
            next_id: 0,
            max_size,
        })
    }

    pub fn load_seeds(&mut self) -> anyhow::Result<Vec<Vec<u8>>> {
        let seed_dir = self.output_dir.join("seed");
        let mut seeds = Vec::new();
        if seed_dir.exists() {
            for entry in fs::read_dir(&seed_dir)? {
                let entry = entry?;
                if entry.path().is_file() {
                    seeds.push(fs::read(entry.path())?);
                }
            }
        }
        Ok(seeds)
    }

    pub fn add_to_queue(
        &mut self,
        input: &[u8],
        new_edges: u32,
        mutator: &str,
        parent_id: Option<u64>,
        exec_count: u64,
    ) -> anyhow::Result<u64> {
        let id = self.next_id;
        self.next_id += 1;
        let time_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let filename = format!(
            "id:{:06},sig:{:04x},src:{},time:{},execs:{},op:{}.bin",
            id,
            new_edges,
            parent_id
                .map(|p| p.to_string())
                .unwrap_or_else(|| "seed".to_string()),
            time_ms,
            exec_count,
            mutator,
        );

        let path = self.output_dir.join("queue").join(&filename);
        fs::write(&path, input)?;

        let entry = CorpusEntry {
            id,
            parent_id,
            filename,
            time_ms,
            exec_count,
            mutator: mutator.to_string(),
            new_edges,
        };
        self.entries.push(entry);

        // Trim if needed
        if self.entries.len() > self.max_size {
            self.trim_by_coverage();
        }

        Ok(id)
    }

    fn trim_by_coverage(&mut self) {
        // Remove entries with lowest new_edges (least unique coverage contribution)
        if self.entries.len() <= self.max_size {
            return;
        }
        self.entries.sort_by_key(|e| e.new_edges);
        let to_remove: Vec<_> = self
            .entries
            .drain(0..self.entries.len() - self.max_size)
            .collect();
        for entry in to_remove {
            let path = self.output_dir.join("queue").join(&entry.filename);
            let _ = fs::remove_file(path);
        }
    }

    pub fn save_crash(&self, input: &[u8], report: &CrashReport) -> anyhow::Result<()> {
        let crash_dir = self.output_dir.join("crashes");
        let base = format!("crash_{}", report.crash_id);
        fs::write(crash_dir.join(format!("{}.bin", base)), input)?;
        fs::write(crash_dir.join(format!("{}.json", base)), report.to_json())?;
        Ok(())
    }

    pub fn save_timeout(&self, input: &[u8], report: &CrashReport) -> anyhow::Result<()> {
        let timeout_dir = self.output_dir.join("timeouts");
        let base = format!("timeout_{}", report.crash_id);
        fs::write(timeout_dir.join(format!("{}.bin", base)), input)?;
        fs::write(timeout_dir.join(format!("{}.json", base)), report.to_json())?;
        Ok(())
    }

    pub fn save_state(&self, bitmap: &CoverageBitmap, stats_json: &str) -> anyhow::Result<()> {
        let state_dir = self.output_dir.join(".state");
        fs::write(state_dir.join("bitmap.bin"), bitmap.as_bytes())?;
        fs::write(state_dir.join("stats.json"), stats_json)?;
        Ok(())
    }

    pub fn load_state(&self) -> anyhow::Result<Option<Vec<u8>>> {
        let bitmap_path = self.output_dir.join(".state").join("bitmap.bin");
        if bitmap_path.exists() {
            Ok(Some(fs::read(bitmap_path)?))
        } else {
            Ok(None)
        }
    }

    pub fn corpus_size(&self) -> usize {
        self.entries.len()
    }

    pub fn save_dedup_summary(&self, unique_crashes: usize) -> anyhow::Result<()> {
        let summary = serde_json::json!({
            "total_unique_crashes": unique_crashes,
            "crash_files": self.list_crashes()?,
        });
        let path = self.output_dir.join("crashes").join("dedup_summary.json");
        fs::write(path, serde_json::to_string_pretty(&summary)?)?;
        Ok(())
    }

    fn list_crashes(&self) -> anyhow::Result<Vec<String>> {
        let crash_dir = self.output_dir.join("crashes");
        let mut names = Vec::new();
        if crash_dir.exists() {
            for entry in fs::read_dir(&crash_dir)? {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".json") {
                    names.push(name);
                }
            }
        }
        Ok(names)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crash::{CrashReport, CrashType};

    fn make_crash_report(id: &str) -> CrashReport {
        CrashReport::new(id, CrashType::HardFault, "L1_hardfault")
    }

    #[test]
    fn corpus_new_creates_directory_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("fuzz_out");
        let _corpus = Corpus::new(base.clone(), 100).unwrap();
        assert!(base.join("seed").exists());
        assert!(base.join("queue").exists());
        assert!(base.join("crashes").exists());
        assert!(base.join("timeouts").exists());
        assert!(base.join(".state").exists());
    }

    #[test]
    fn add_to_queue_writes_file_and_returns_incrementing_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let mut corpus = Corpus::new(tmp.path().join("fuzz_out"), 100).unwrap();
        let id0 = corpus
            .add_to_queue(b"hello", 3, "bit_flip", None, 0)
            .unwrap();
        let id1 = corpus
            .add_to_queue(b"world", 5, "byte_flip", Some(id0), 1)
            .unwrap();
        assert_eq!(id0, 0);
        assert_eq!(id1, 1);
        assert_eq!(corpus.corpus_size(), 2);
        // Check that at least one .bin file exists in queue/
        let queue_dir = tmp.path().join("fuzz_out").join("queue");
        let files: Vec<_> = fs::read_dir(&queue_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn load_seeds_returns_empty_vec_when_seed_dir_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let mut corpus = Corpus::new(tmp.path().join("fuzz_out"), 100).unwrap();
        let seeds = corpus.load_seeds().unwrap();
        assert!(seeds.is_empty());
    }

    #[test]
    fn load_seeds_reads_files_from_seed_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("fuzz_out");
        let mut corpus = Corpus::new(base.clone(), 100).unwrap();
        fs::write(base.join("seed").join("s1.bin"), b"seed_data_a").unwrap();
        fs::write(base.join("seed").join("s2.bin"), b"seed_data_b").unwrap();
        let seeds = corpus.load_seeds().unwrap();
        assert_eq!(seeds.len(), 2);
    }

    #[test]
    fn save_crash_writes_bin_and_json_files() {
        let tmp = tempfile::tempdir().unwrap();
        let corpus = Corpus::new(tmp.path().join("fuzz_out"), 100).unwrap();
        let report = make_crash_report("deadbeef");
        corpus.save_crash(b"crash_input", &report).unwrap();
        let crash_dir = tmp.path().join("fuzz_out").join("crashes");
        assert!(crash_dir.join("crash_deadbeef.bin").exists());
        assert!(crash_dir.join("crash_deadbeef.json").exists());
    }

    #[test]
    fn save_timeout_writes_to_timeouts_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let corpus = Corpus::new(tmp.path().join("fuzz_out"), 100).unwrap();
        let report = make_crash_report("cafe0001");
        corpus.save_timeout(b"timeout_input", &report).unwrap();
        let timeout_dir = tmp.path().join("fuzz_out").join("timeouts");
        assert!(timeout_dir.join("timeout_cafe0001.bin").exists());
        assert!(timeout_dir.join("timeout_cafe0001.json").exists());
    }

    #[test]
    fn corpus_size_reflects_added_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let mut corpus = Corpus::new(tmp.path().join("fuzz_out"), 100).unwrap();
        assert_eq!(corpus.corpus_size(), 0);
        corpus.add_to_queue(b"a", 1, "flip", None, 0).unwrap();
        assert_eq!(corpus.corpus_size(), 1);
        corpus.add_to_queue(b"b", 2, "flip", None, 1).unwrap();
        assert_eq!(corpus.corpus_size(), 2);
    }

    #[test]
    fn save_state_and_load_state_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let corpus = Corpus::new(tmp.path().join("fuzz_out"), 100).unwrap();
        let mut bm = CoverageBitmap::new();
        // Set a known byte in the bitmap
        // We'll use raw access via the public API: set_edge to touch a known slot
        bm.set_edge(0x0800_0000, 0x0800_0100);
        corpus.save_state(&bm, r#"{"total_executions":42}"#).unwrap();
        let loaded = corpus.load_state().unwrap();
        assert!(loaded.is_some());
        let bytes = loaded.unwrap();
        assert_eq!(bytes.len(), crate::coverage::BITMAP_SIZE);
        // Verify the saved bytes are non-zero (some edge was set)
        assert!(bytes.iter().any(|&b| b != 0));
    }

    #[test]
    fn load_state_returns_none_when_no_state_file() {
        let tmp = tempfile::tempdir().unwrap();
        let corpus = Corpus::new(tmp.path().join("fuzz_out"), 100).unwrap();
        let loaded = corpus.load_state().unwrap();
        assert!(loaded.is_none());
    }
}
