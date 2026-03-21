//! Edge coverage tracking via shared memory bitmap (AFL-style).

/// Size of the shared memory coverage bitmap in bytes (64 KB = 65 536 entries).
pub const BITMAP_SIZE: usize = 65_536;

// ── CoverageBitmap ────────────────────────────────────────────────────────────

/// A heap-allocated bitmap tracking which edges (from → to) were hit.
pub struct CoverageBitmap {
    data: Box<[u8; BITMAP_SIZE]>,
}

impl std::fmt::Debug for CoverageBitmap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CoverageBitmap(edges={})", self.count_edges())
    }
}

impl CoverageBitmap {
    pub fn new() -> Self {
        Self {
            data: Box::new([0u8; BITMAP_SIZE]),
        }
    }

    /// Record a taken edge using the AFL-style hash.
    #[inline]
    pub fn set_edge(&mut self, from: u32, to: u32) {
        let id = compute_edge_id(from, to);
        self.data[id] = self.data[id].saturating_add(1);
    }

    /// Returns `true` if any edge in `self` is not present in `global`.
    pub fn has_new_coverage(&self, global: &Self) -> bool {
        self.data
            .iter()
            .zip(global.data.iter())
            .any(|(&s, &g)| s != 0 && g == 0)
    }

    /// OR `self` into `global` (adds new edges to the global bitmap).
    pub fn merge_into(&self, global: &mut Self) {
        for (g, s) in global.data.iter_mut().zip(self.data.iter()) {
            *g |= s;
        }
    }

    /// Count the number of non-zero entries (distinct edges hit at least once).
    pub fn count_edges(&self) -> u32 {
        self.data.iter().filter(|&&b| b != 0).count() as u32
    }

    pub fn clear(&mut self) {
        self.data.fill(0);
    }

    /// Return raw bitmap bytes (for persistence / state saving).
    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_ref()
    }

    /// Raw access for testing.
    #[cfg(test)]
    pub(crate) fn raw_set(&mut self, idx: usize, val: u8) {
        self.data[idx] = val;
    }

    #[cfg(test)]
    pub(crate) fn raw_get(&self, idx: usize) -> u8 {
        self.data[idx]
    }
}

impl Default for CoverageBitmap {
    fn default() -> Self {
        Self::new()
    }
}

// ── Edge ID computation ───────────────────────────────────────────────────────

/// AFL-style edge hash: `(from >> 1) XOR to`, mapped into `[0, BITMAP_SIZE)`.
#[inline]
pub fn compute_edge_id(from_addr: u32, to_addr: u32) -> usize {
    let prev = (from_addr >> 1) as usize;
    let cur = to_addr as usize;
    (prev ^ cur) % BITMAP_SIZE
}

// ── FuzzerStats ───────────────────────────────────────────────────────────────

/// Snapshot of fuzzer progress statistics.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct FuzzerStats {
    pub total_executions: u64,
    pub unique_edges: u32,
    pub corpus_size: u32,
    pub crash_count: u32,
    pub timeout_count: u32,
    pub start_time_unix: u64,
    pub last_new_edge_unix: u64,
    pub execs_per_second: f64,
}

impl FuzzerStats {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    /// Comma-separated row: start_time, unique_edges, execs/s, corpus, crashes, total_execs.
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.start_time_unix,
            self.unique_edges,
            self.execs_per_second,
            self.corpus_size,
            self.crash_count,
            self.total_executions,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_edge_id_in_range() {
        for from in [0u32, 0x0800_0000, 0xFFFF_FFFF, 1, 12345] {
            for to in [0u32, 0x0800_0100, 0xDEAD_BEEF, 2, 99999] {
                let id = compute_edge_id(from, to);
                assert!(id < BITMAP_SIZE, "edge_id {} out of range", id);
            }
        }
    }

    #[test]
    fn has_new_coverage_detects_new_bit() {
        let mut local = CoverageBitmap::new();
        let global = CoverageBitmap::new();

        // Set an edge that does not exist in global
        local.raw_set(42, 1);
        assert!(local.has_new_coverage(&global));
    }

    #[test]
    fn has_new_coverage_false_when_subset() {
        let local = CoverageBitmap::new();
        let mut global = CoverageBitmap::new();
        global.raw_set(42, 1);

        // local has no edges — global is a superset
        assert!(!local.has_new_coverage(&global));
    }

    #[test]
    fn has_new_coverage_false_when_already_in_global() {
        let mut local = CoverageBitmap::new();
        let mut global = CoverageBitmap::new();
        local.raw_set(42, 1);
        global.raw_set(42, 1);
        assert!(!local.has_new_coverage(&global));
    }

    #[test]
    fn merge_into_ors_bitmaps() {
        let mut local = CoverageBitmap::new();
        let mut global = CoverageBitmap::new();
        local.raw_set(10, 0xFF);
        global.raw_set(20, 0x0F);

        local.merge_into(&mut global);

        assert_eq!(global.raw_get(10), 0xFF, "bit at 10 should come from local");
        assert_eq!(global.raw_get(20), 0x0F, "bit at 20 should be preserved");
    }

    #[test]
    fn count_edges_correct() {
        let mut bm = CoverageBitmap::new();
        assert_eq!(bm.count_edges(), 0);
        bm.raw_set(0, 1);
        bm.raw_set(100, 5);
        bm.raw_set(200, 255);
        assert_eq!(bm.count_edges(), 3);
    }

    #[test]
    fn clear_resets_bitmap() {
        let mut bm = CoverageBitmap::new();
        bm.raw_set(0, 1);
        bm.clear();
        assert_eq!(bm.count_edges(), 0);
    }

    #[test]
    fn set_edge_increments() {
        let mut bm = CoverageBitmap::new();
        let id = compute_edge_id(0x0800_0000, 0x0800_0100);
        bm.set_edge(0x0800_0000, 0x0800_0100);
        assert_ne!(bm.raw_get(id), 0);
    }

    #[test]
    fn stats_to_csv_row_format() {
        let stats = FuzzerStats {
            start_time_unix: 1_700_000_000,
            unique_edges: 42,
            execs_per_second: 1234.5,
            corpus_size: 10,
            crash_count: 2,
            total_executions: 100_000,
            ..Default::default()
        };
        let row = stats.to_csv_row();
        let parts: Vec<&str> = row.split(',').collect();
        assert_eq!(parts.len(), 6, "CSV row should have 6 fields: {}", row);
        assert_eq!(parts[0], "1700000000");
        assert_eq!(parts[1], "42");
        assert_eq!(parts[3], "10");
        assert_eq!(parts[4], "2");
        assert_eq!(parts[5], "100000");
    }

    #[test]
    fn stats_to_json_roundtrip() {
        let stats = FuzzerStats {
            total_executions: 999,
            unique_edges: 7,
            ..Default::default()
        };
        let json = stats.to_json();
        assert!(json.contains("\"total_executions\":999"));
        assert!(json.contains("\"unique_edges\":7"));
    }
}
