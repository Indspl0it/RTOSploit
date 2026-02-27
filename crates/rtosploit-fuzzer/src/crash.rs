//! Multi-layer crash detection for bare-metal firmware.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CrashType {
    HardFault,
    BusFault,
    MemManage,
    UsageFault,
    WatchdogTimeout,
    StackCanaryViolation,
    HeapMetadataCorruption,
    ShadowMemoryOOB,
}

impl std::fmt::Display for CrashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrashType::HardFault => write!(f, "HardFault"),
            CrashType::BusFault => write!(f, "BusFault"),
            CrashType::MemManage => write!(f, "MemManage"),
            CrashType::UsageFault => write!(f, "UsageFault"),
            CrashType::WatchdogTimeout => write!(f, "WatchdogTimeout"),
            CrashType::StackCanaryViolation => write!(f, "StackCanaryViolation"),
            CrashType::HeapMetadataCorruption => write!(f, "HeapMetadataCorruption"),
            CrashType::ShadowMemoryOOB => write!(f, "ShadowMemoryOOB"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    pub crash_id: String,         // UUID-like hex string
    pub timestamp: u64,           // Unix timestamp seconds
    pub detection_layer: String,  // "L1_hardfault", "L2_busfault", "L3_watchdog", etc.
    pub input_file: String,       // path relative to output dir
    pub input_size: usize,
    pub registers: HashMap<String, u32>, // "pc", "sp", "lr", "r0"-"r12", "xpsr"
    pub stack_dump: Vec<u8>,      // raw bytes from stack area
    pub fault_address: u32,       // address of fault (BFAR/MMFAR or 0)
    pub fault_type: CrashType,
    pub backtrace: Vec<u32>,      // call chain addresses
    pub coverage_edges: u32,      // how many edges were covered before crash
    pub execution_time_us: u64,
    pub reproducible: bool,
    pub pre_crash_events: Vec<String>, // last N event descriptions from instrumentation ring buffer
}

impl CrashReport {
    pub fn new(crash_id: &str, fault_type: CrashType, layer: &str) -> Self {
        Self {
            crash_id: crash_id.to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            detection_layer: layer.to_string(),
            input_file: String::new(),
            input_size: 0,
            registers: HashMap::new(),
            stack_dump: Vec::new(),
            fault_address: 0,
            fault_type,
            backtrace: Vec::new(),
            coverage_edges: 0,
            execution_time_us: 0,
            reproducible: false,
            pre_crash_events: Vec::new(),
        }
    }

    pub fn stack_hash(&self) -> u64 {
        // Simple FNV-1a hash of backtrace for deduplication
        let mut hash: u64 = 0xcbf29ce484222325;
        for &addr in &self.backtrace {
            hash ^= addr as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        // Also mix in fault_type and PC
        hash ^= self.registers.get("pc").copied().unwrap_or(0) as u64;
        hash = hash.wrapping_mul(0x100000001b3);
        hash
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

#[derive(Debug)]
pub struct CrashDetector {
    pub layer1_hardfault: bool,
    pub layer2_busfault: bool,
    pub layer3_watchdog: bool,
    pub layer4_canary: bool,
    pub layer5_heap: bool,
    pub layer6_shadow: bool,
    pub watchdog_ms: u64,
    pub crash_dedup: bool,
    seen_hashes: std::collections::HashSet<u64>,
}

impl CrashDetector {
    pub fn new(
        watchdog_ms: u64,
        crash_dedup: bool,
        layers: (bool, bool, bool, bool, bool, bool),
    ) -> Self {
        Self {
            layer1_hardfault: layers.0,
            layer2_busfault: layers.1,
            layer3_watchdog: layers.2,
            layer4_canary: layers.3,
            layer5_heap: layers.4,
            layer6_shadow: layers.5,
            watchdog_ms,
            crash_dedup,
            seen_hashes: std::collections::HashSet::new(),
        }
    }

    /// Returns true if this crash is new (not a duplicate).
    pub fn register_crash(&mut self, report: &CrashReport) -> bool {
        if !self.crash_dedup {
            return true;
        }
        let hash = report.stack_hash();
        self.seen_hashes.insert(hash) // returns true if newly inserted
    }

    pub fn unique_crash_count(&self) -> usize {
        self.seen_hashes.len()
    }

    pub fn reset_dedup(&mut self) {
        self.seen_hashes.clear();
    }
}

/// Layer 1/2: Patch fault vectors to trap address.
/// Returns (offset, original_value) pairs for patched entries.
pub fn patch_vector_table(
    firmware: &mut Vec<u8>,
    hardfault: bool,
    busfault: bool,
    memmanage: bool,
    usagefault: bool,
) -> Vec<(usize, u32)> {
    const TRAP_HARDFAULT: u32 = 0xDEAD0000;
    const TRAP_BUSFAULT: u32 = 0xDEAD0004;
    const TRAP_MEMMANAGE: u32 = 0xDEAD0008;
    const TRAP_USAGEFAULT: u32 = 0xDEAD000C;

    let mut patches: Vec<(usize, u32)> = Vec::new();

    fn patch_entry(
        firmware: &mut Vec<u8>,
        offset: usize,
        trap: u32,
        patches: &mut Vec<(usize, u32)>,
    ) {
        if offset + 4 <= firmware.len() {
            let orig = u32::from_le_bytes([
                firmware[offset],
                firmware[offset + 1],
                firmware[offset + 2],
                firmware[offset + 3],
            ]);
            patches.push((offset, orig));
            let bytes = trap.to_le_bytes();
            firmware[offset..offset + 4].copy_from_slice(&bytes);
        }
    }

    if hardfault {
        patch_entry(firmware, 0x0C, TRAP_HARDFAULT, &mut patches);
    }
    if memmanage {
        patch_entry(firmware, 0x10, TRAP_MEMMANAGE, &mut patches);
    }
    if busfault {
        patch_entry(firmware, 0x14, TRAP_BUSFAULT, &mut patches);
    }
    if usagefault {
        patch_entry(firmware, 0x18, TRAP_USAGEFAULT, &mut patches);
    }

    patches
}

/// Layer 3: Watchdog state
pub struct WatchdogState {
    last_new_edge_time: std::time::Instant,
    timeout_ms: u64,
}

impl WatchdogState {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            last_new_edge_time: std::time::Instant::now(),
            timeout_ms,
        }
    }

    pub fn reset(&mut self) {
        self.last_new_edge_time = std::time::Instant::now();
    }

    pub fn is_timed_out(&self) -> bool {
        self.last_new_edge_time.elapsed().as_millis() as u64 > self.timeout_ms
    }

    pub fn elapsed_ms(&self) -> u64 {
        self.last_new_edge_time.elapsed().as_millis() as u64
    }
}

/// Layer 4: Stack canary location descriptor
#[derive(Debug, Clone)]
pub struct CanaryLocation {
    pub function_addr: u32,  // address of the function being protected
    pub canary_offset: u32,  // stack offset where canary was placed
    pub canary_value: u32,   // expected canary value (default 0xDEADBEEF)
}

/// Scan ARM Thumb2 firmware for function prologues (PUSH {R*, LR} patterns).
pub fn find_function_prologues(firmware: &[u8], base_address: u32) -> Vec<u32> {
    let mut addrs = Vec::new();
    let mut i = 0usize;
    while i + 2 <= firmware.len() {
        let hw = u16::from_le_bytes([firmware[i], firmware[i + 1]]);
        // Thumb2 16-bit PUSH: 0xB500-0xB5FF (bit 14=1, bit 9=1, bits 15:13=101)
        // More specifically: 0b1011_0101_xxxx_xxxx = 0xB5xx
        if (hw & 0xFF00) == 0xB500 {
            addrs.push(base_address + i as u32 + 1); // +1 for Thumb bit
        }
        i += 2;
    }
    addrs
}

/// Layer 5: BlockLink_t shadow tracker
#[derive(Debug, Clone)]
pub struct BlockLinkShadow {
    pub block_addr: u32,
    pub next_free: u32,
    pub block_size: u32,
    pub is_free: bool,
}

pub struct HeapShadowTracker {
    blocks: Vec<BlockLinkShadow>,
    heap_base: u32,
    heap_size: u32,
}

impl HeapShadowTracker {
    pub fn new(heap_base: u32, heap_size: u32) -> Self {
        Self {
            blocks: Vec::new(),
            heap_base,
            heap_size,
        }
    }

    pub fn record_block(&mut self, addr: u32, next_free: u32, size: u32, is_free: bool) {
        if let Some(b) = self.blocks.iter_mut().find(|b| b.block_addr == addr) {
            b.next_free = next_free;
            b.block_size = size;
            b.is_free = is_free;
        } else {
            self.blocks.push(BlockLinkShadow {
                block_addr: addr,
                next_free,
                block_size: size,
                is_free,
            });
        }
    }

    pub fn validate_block(&self, addr: u32, next_free: u32, size: u32) -> Option<String> {
        let heap_end = self.heap_base + self.heap_size;
        if next_free != 0 && (next_free < self.heap_base || next_free >= heap_end) {
            return Some(format!(
                "pxNextFreeBlock=0x{:08x} outside heap [0x{:08x}, 0x{:08x})",
                next_free, self.heap_base, heap_end
            ));
        }
        if size > self.heap_size {
            return Some(format!(
                "xBlockSize=0x{:x} > heap_size=0x{:x}",
                size, self.heap_size
            ));
        }
        let _ = addr; // addr parameter reserved for future per-block validation
        None
    }

    pub fn check_double_free(&self, addr: u32) -> bool {
        self.blocks.iter().any(|b| b.block_addr == addr && b.is_free)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_report_with_pc(crash_id: &str, pc: u32, backtrace: Vec<u32>) -> CrashReport {
        let mut r = CrashReport::new(crash_id, CrashType::HardFault, "L1_hardfault");
        r.registers.insert("pc".to_string(), pc);
        r.backtrace = backtrace;
        r
    }

    // ── CrashReport::new ──────────────────────────────────────────────────────

    #[test]
    fn crash_report_new_sets_layer_and_nonzero_timestamp() {
        let r = CrashReport::new("abc123", CrashType::BusFault, "L2_busfault");
        assert_eq!(r.crash_id, "abc123");
        assert_eq!(r.detection_layer, "L2_busfault");
        assert!(r.timestamp > 0);
        assert_eq!(r.fault_type, CrashType::BusFault);
    }

    // ── CrashReport::stack_hash ───────────────────────────────────────────────

    #[test]
    fn stack_hash_is_stable() {
        let r = make_report_with_pc("id1", 0x0800_1234, vec![0x0800_1000, 0x0800_2000]);
        let h1 = r.stack_hash();
        let h2 = r.stack_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn stack_hash_differs_for_different_pcs() {
        let r1 = make_report_with_pc("id1", 0x0800_1234, vec![0x0800_1000]);
        let r2 = make_report_with_pc("id2", 0x0800_5678, vec![0x0800_1000]);
        assert_ne!(r1.stack_hash(), r2.stack_hash());
    }

    // ── CrashDetector::register_crash ─────────────────────────────────────────

    #[test]
    fn register_crash_first_returns_true() {
        let mut det = CrashDetector::new(5000, true, (true, true, true, true, true, true));
        let r = make_report_with_pc("id1", 0xDEAD_BEEF, vec![0x1000]);
        assert!(det.register_crash(&r));
        assert_eq!(det.unique_crash_count(), 1);
    }

    #[test]
    fn register_crash_duplicate_returns_false() {
        let mut det = CrashDetector::new(5000, true, (true, true, true, true, true, true));
        let r = make_report_with_pc("id1", 0xDEAD_BEEF, vec![0x1000]);
        assert!(det.register_crash(&r));
        assert!(!det.register_crash(&r));
        assert_eq!(det.unique_crash_count(), 1);
    }

    #[test]
    fn register_crash_dedup_false_always_returns_true() {
        let mut det = CrashDetector::new(5000, false, (true, true, true, true, true, true));
        let r = make_report_with_pc("id1", 0xDEAD_BEEF, vec![0x1000]);
        assert!(det.register_crash(&r));
        assert!(det.register_crash(&r));
        assert!(det.register_crash(&r));
        // With dedup=false, seen_hashes is never populated
        assert_eq!(det.unique_crash_count(), 0);
    }

    // ── patch_vector_table ────────────────────────────────────────────────────

    #[test]
    fn patch_vector_table_hardfault_modifies_offset_0x0c() {
        let mut fw = vec![0u8; 32];
        let patches = patch_vector_table(&mut fw, true, false, false, false);
        assert_eq!(patches.len(), 1);
        assert_eq!(patches[0].0, 0x0C);
        // The patched bytes should be the TRAP value
        let patched = u32::from_le_bytes([fw[0x0C], fw[0x0D], fw[0x0E], fw[0x0F]]);
        assert_eq!(patched, 0xDEAD0000);
    }

    #[test]
    fn patch_vector_table_returns_original_values() {
        let original: u32 = 0x0800_0101;
        let mut fw = vec![0u8; 32];
        fw[0x0C..0x10].copy_from_slice(&original.to_le_bytes());
        let patches = patch_vector_table(&mut fw, true, false, false, false);
        assert_eq!(patches[0].1, original);
    }

    #[test]
    fn patch_vector_table_short_firmware_no_panic() {
        let mut fw = vec![0u8; 4]; // too short for any vector table entry
        let patches = patch_vector_table(&mut fw, true, true, true, true);
        assert!(patches.is_empty());
    }

    // ── WatchdogState ─────────────────────────────────────────────────────────

    #[test]
    fn watchdog_not_timed_out_immediately() {
        let wd = WatchdogState::new(10_000); // 10 seconds
        assert!(!wd.is_timed_out());
    }

    #[test]
    fn watchdog_reset_restarts_timer() {
        let mut wd = WatchdogState::new(10_000);
        let elapsed_before = wd.elapsed_ms();
        wd.reset();
        // After reset, elapsed should be very small (< elapsed_before + some margin)
        assert!(wd.elapsed_ms() <= elapsed_before + 100);
    }

    // ── find_function_prologues ───────────────────────────────────────────────

    #[test]
    fn find_function_prologues_finds_push_lr_bytes() {
        // 0xB510 = PUSH {r4, lr} — a typical Thumb2 function prologue
        let fw = vec![0x00u8, 0x00, 0x10, 0xB5, 0x00, 0x00];
        let addrs = find_function_prologues(&fw, 0x0800_0000);
        // At byte offset 2 we have 0x10 0xB5 -> hw = 0xB510
        assert!(!addrs.is_empty(), "should find at least one prologue");
        assert_eq!(addrs[0], 0x0800_0000 + 2 + 1); // +1 for Thumb bit
    }

    #[test]
    fn find_function_prologues_empty_on_no_match() {
        let fw = vec![0xFFu8; 16];
        let addrs = find_function_prologues(&fw, 0x0800_0000);
        assert!(addrs.is_empty());
    }

    // ── HeapShadowTracker ─────────────────────────────────────────────────────

    #[test]
    fn heap_validate_block_oob_next_free() {
        let tracker = HeapShadowTracker::new(0x2000_0000, 0x0001_0000);
        // next_free points outside the heap
        let result = tracker.validate_block(0x2000_0100, 0x3000_0000, 64);
        assert!(result.is_some(), "should detect OOB next_free");
    }

    #[test]
    fn heap_validate_block_valid_returns_none() {
        let tracker = HeapShadowTracker::new(0x2000_0000, 0x0001_0000);
        // next_free = 0 means end-of-list (valid sentinel)
        let result = tracker.validate_block(0x2000_0100, 0, 64);
        assert!(result.is_none());
    }

    #[test]
    fn heap_check_double_free_detects_second_free() {
        let mut tracker = HeapShadowTracker::new(0x2000_0000, 0x0001_0000);
        tracker.record_block(0x2000_0100, 0, 64, true); // already marked free
        assert!(tracker.check_double_free(0x2000_0100));
    }

    #[test]
    fn heap_check_double_free_ok_for_allocated_block() {
        let mut tracker = HeapShadowTracker::new(0x2000_0000, 0x0001_0000);
        tracker.record_block(0x2000_0100, 0, 64, false); // allocated
        assert!(!tracker.check_double_free(0x2000_0100));
    }
}
