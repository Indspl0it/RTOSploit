//! Crash report generation and serialization.
//!
//! This module provides [`FuzzReport`] — a high-level report that wraps
//! execution results, input data, and crash diagnostics into a single
//! serialisable artifact suitable for triage dashboards and CI pipelines.
//!
//! It complements [`crate::crash::CrashReport`] (low-level per-crash record)
//! with richer metadata: severity classification, deduplication hashing,
//! base64-encoded reproducer input, and both JSON and human-readable output.

use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::engine::ExecutionResult;
use crate::crash::CrashType;

// ── CrashSeverity ────────────────────────────────────────────────────────────

/// Severity rating attached to a crash for triage prioritisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CrashSeverity {
    /// Informational only (e.g. unexpected but non-exploitable behaviour).
    Info,
    /// Low severity — unlikely to be exploitable.
    Low,
    /// Medium severity — potential denial-of-service or limited corruption.
    Medium,
    /// High severity — likely exploitable memory corruption.
    High,
    /// Critical — confirmed code execution or full memory control.
    Critical,
}

impl fmt::Display for CrashSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrashSeverity::Info => write!(f, "INFO"),
            CrashSeverity::Low => write!(f, "LOW"),
            CrashSeverity::Medium => write!(f, "MEDIUM"),
            CrashSeverity::High => write!(f, "HIGH"),
            CrashSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ── ReportCrashType ──────────────────────────────────────────────────────────

/// Crash type classification for reports.
///
/// This mirrors — and extends — [`CrashType`] with additional categories that
/// are only meaningful at the reporting layer (e.g. `StackOverflow`, `Unknown`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportCrashType {
    HardFault,
    MemManage,
    BusFault,
    UsageFault,
    StackOverflow,
    HeapCorruption,
    WatchdogTimeout,
    Unknown,
}

impl fmt::Display for ReportCrashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReportCrashType::HardFault => write!(f, "HardFault"),
            ReportCrashType::MemManage => write!(f, "MemManage"),
            ReportCrashType::BusFault => write!(f, "BusFault"),
            ReportCrashType::UsageFault => write!(f, "UsageFault"),
            ReportCrashType::StackOverflow => write!(f, "StackOverflow"),
            ReportCrashType::HeapCorruption => write!(f, "HeapCorruption"),
            ReportCrashType::WatchdogTimeout => write!(f, "WatchdogTimeout"),
            ReportCrashType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<&CrashType> for ReportCrashType {
    fn from(ct: &CrashType) -> Self {
        match ct {
            CrashType::HardFault => ReportCrashType::HardFault,
            CrashType::BusFault => ReportCrashType::BusFault,
            CrashType::MemManage => ReportCrashType::MemManage,
            CrashType::UsageFault => ReportCrashType::UsageFault,
            CrashType::WatchdogTimeout => ReportCrashType::WatchdogTimeout,
            CrashType::StackCanaryViolation => ReportCrashType::StackOverflow,
            CrashType::HeapMetadataCorruption => ReportCrashType::HeapCorruption,
            CrashType::ShadowMemoryOOB => ReportCrashType::HeapCorruption,
        }
    }
}

// ── FuzzReport ───────────────────────────────────────────────────────────────

/// A full crash/fuzz report suitable for serialisation and triage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzReport {
    /// Unique report identifier (hex string derived from timestamp + input hash).
    pub id: String,
    /// Unix timestamp (seconds) when the report was generated.
    pub timestamp: u64,
    /// Hex-encoded hash of the triggering input.
    pub input_hash: String,
    /// Classification of the crash.
    pub crash_type: ReportCrashType,
    /// Severity rating.
    pub severity: CrashSeverity,
    /// Program counter at the point of failure.
    pub pc: u32,
    /// Faulting memory address (BFAR/MMFAR), or 0 when not applicable.
    pub fault_address: u32,
    /// Named register dump (e.g. `"r0"` -> value).
    pub registers: HashMap<String, u32>,
    /// Symbolic backtrace addresses.
    pub stack_trace: Vec<u32>,
    /// The triggering input, base64-encoded.
    pub input_data: String,
    /// Optional filesystem path to a standalone reproducer file.
    pub reproducer_path: Option<String>,
    /// Deduplication hash (crash_type + pc) for grouping equivalent crashes.
    pub dedup_hash: String,
}

impl FuzzReport {
    /// Construct a new report with all fields specified.
    pub fn new(
        crash_type: ReportCrashType,
        severity: CrashSeverity,
        pc: u32,
        fault_address: u32,
        registers: HashMap<String, u32>,
        stack_trace: Vec<u32>,
        input: &[u8],
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let input_hash = fnv1a_hex(input);
        let input_data = base64_encode(input);
        let dedup_hash = Self::compute_dedup_hash(&crash_type, pc);
        let id = format!("{:016x}-{}", timestamp, &input_hash[..8.min(input_hash.len())]);

        Self {
            id,
            timestamp,
            input_hash,
            crash_type,
            severity,
            pc,
            fault_address,
            registers,
            stack_trace,
            input_data,
            reproducer_path: None,
            dedup_hash,
        }
    }

    /// Build a report from an [`ExecutionResult`] and the raw input bytes.
    ///
    /// For non-crash results the report will have crash_type `Unknown` and
    /// severity `Info`.
    pub fn from_execution(result: &ExecutionResult, input: &[u8]) -> Self {
        match result {
            ExecutionResult::Crash { signal, pc, registers } => {
                let crash_type = signal_to_crash_type(*signal);
                let severity = classify_severity(&crash_type);
                let mut reg_map = HashMap::new();
                for (i, &val) in registers.iter().enumerate() {
                    reg_map.insert(format!("r{}", i), val);
                }
                reg_map.insert("pc".to_string(), *pc);

                Self::new(
                    crash_type,
                    severity,
                    *pc,
                    0, // fault address not available from ExecutionResult
                    reg_map,
                    Vec::new(), // no stack trace from engine result
                    input,
                )
            }
            ExecutionResult::Timeout => Self::new(
                ReportCrashType::WatchdogTimeout,
                CrashSeverity::Medium,
                0,
                0,
                HashMap::new(),
                Vec::new(),
                input,
            ),
            ExecutionResult::Normal { .. } => Self::new(
                ReportCrashType::Unknown,
                CrashSeverity::Info,
                0,
                0,
                HashMap::new(),
                Vec::new(),
                input,
            ),
        }
    }

    /// Serialise the report to pretty-printed JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Render a human-readable text summary.
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("=== Crash Report {} ===\n", self.id));
        out.push_str(&format!("Timestamp:     {}\n", self.timestamp));
        out.push_str(&format!("Crash Type:    {}\n", self.crash_type));
        out.push_str(&format!("Severity:      {}\n", self.severity));
        out.push_str(&format!("PC:            0x{:08X}\n", self.pc));
        out.push_str(&format!("Fault Address: 0x{:08X}\n", self.fault_address));
        out.push_str(&format!("Input Hash:    {}\n", self.input_hash));
        out.push_str(&format!("Dedup Hash:    {}\n", self.dedup_hash));

        if !self.registers.is_empty() {
            out.push_str("Registers:\n");
            let mut regs: Vec<_> = self.registers.iter().collect();
            regs.sort_by_key(|(k, _)| (*k).clone());
            for (name, val) in &regs {
                out.push_str(&format!("  {:<6} = 0x{:08X}\n", name, val));
            }
        }

        if !self.stack_trace.is_empty() {
            out.push_str("Stack Trace:\n");
            for (i, &addr) in self.stack_trace.iter().enumerate() {
                out.push_str(&format!("  #{}: 0x{:08X}\n", i, addr));
            }
        }

        if let Some(ref path) = self.reproducer_path {
            out.push_str(&format!("Reproducer:    {}\n", path));
        }

        out
    }

    /// Compute a deduplication hash from crash type and program counter.
    ///
    /// Two crashes with the same type and PC are considered duplicates.
    pub fn compute_dedup_hash(crash_type: &ReportCrashType, pc: u32) -> String {
        let key = format!("{}:{:08x}", crash_type, pc);
        fnv1a_hex(key.as_bytes())
    }

    /// Return the deduplication hash for this report.
    pub fn dedup_hash(&self) -> &str {
        &self.dedup_hash
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Map a POSIX signal number to a [`ReportCrashType`].
fn signal_to_crash_type(signal: u32) -> ReportCrashType {
    match signal {
        11 => ReportCrashType::HardFault, // SIGSEGV
        7 => ReportCrashType::BusFault,   // SIGBUS
        6 => ReportCrashType::UsageFault, // SIGABRT
        14 => ReportCrashType::WatchdogTimeout, // SIGALRM
        _ => ReportCrashType::Unknown,
    }
}

/// Classify severity from crash type.
fn classify_severity(crash_type: &ReportCrashType) -> CrashSeverity {
    match crash_type {
        ReportCrashType::HardFault => CrashSeverity::High,
        ReportCrashType::MemManage => CrashSeverity::High,
        ReportCrashType::BusFault => CrashSeverity::High,
        ReportCrashType::UsageFault => CrashSeverity::Medium,
        ReportCrashType::StackOverflow => CrashSeverity::Critical,
        ReportCrashType::HeapCorruption => CrashSeverity::Critical,
        ReportCrashType::WatchdogTimeout => CrashSeverity::Medium,
        ReportCrashType::Unknown => CrashSeverity::Low,
    }
}

/// FNV-1a 64-bit hash, returned as a hex string.
fn fnv1a_hex(data: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", hash)
}

/// Simple base64 encoding (no external dependency needed).
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }

        if chunk.len() > 2 {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coverage::CoverageBitmap;

    // ── FuzzReport::new ──────────────────────────────────────────────────────

    #[test]
    fn new_report_has_nonzero_timestamp() {
        let r = FuzzReport::new(
            ReportCrashType::HardFault,
            CrashSeverity::High,
            0x0800_1234,
            0,
            HashMap::new(),
            Vec::new(),
            &[1, 2, 3],
        );
        assert!(r.timestamp > 0);
        assert!(!r.id.is_empty());
        assert!(!r.dedup_hash.is_empty());
    }

    // ── FuzzReport::from_execution ───────────────────────────────────────────

    #[test]
    fn from_execution_crash() {
        let result = ExecutionResult::Crash {
            signal: 11,
            pc: 0xDEAD_BEEF,
            registers: vec![0; 16],
        };
        let r = FuzzReport::from_execution(&result, &[0xDE, 0xAD]);
        assert_eq!(r.crash_type, ReportCrashType::HardFault);
        assert_eq!(r.pc, 0xDEAD_BEEF);
        assert_eq!(r.severity, CrashSeverity::High);
    }

    #[test]
    fn from_execution_timeout() {
        let result = ExecutionResult::Timeout;
        let r = FuzzReport::from_execution(&result, &[0x00]);
        assert_eq!(r.crash_type, ReportCrashType::WatchdogTimeout);
        assert_eq!(r.severity, CrashSeverity::Medium);
    }

    #[test]
    fn from_execution_normal() {
        let result = ExecutionResult::Normal {
            coverage: CoverageBitmap::new(),
        };
        let r = FuzzReport::from_execution(&result, &[0xAA]);
        assert_eq!(r.crash_type, ReportCrashType::Unknown);
        assert_eq!(r.severity, CrashSeverity::Info);
    }

    // ── Serialisation ────────────────────────────────────────────────────────

    #[test]
    fn to_json_is_valid_json() {
        let r = FuzzReport::new(
            ReportCrashType::BusFault,
            CrashSeverity::High,
            0x0800_0100,
            0x2000_0000,
            HashMap::new(),
            Vec::new(),
            &[1, 2, 3, 4],
        );
        let json = r.to_json();
        // Should be parseable back
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(parsed["crash_type"], "BusFault");
    }

    #[test]
    fn to_text_contains_key_fields() {
        let mut regs = HashMap::new();
        regs.insert("pc".to_string(), 0x0800_1234);
        let r = FuzzReport::new(
            ReportCrashType::StackOverflow,
            CrashSeverity::Critical,
            0x0800_1234,
            0,
            regs,
            vec![0x0800_1000, 0x0800_2000],
            &[0xFF],
        );
        let text = r.to_text();
        assert!(text.contains("Crash Report"), "missing header");
        assert!(text.contains("StackOverflow"), "missing crash type");
        assert!(text.contains("CRITICAL"), "missing severity");
        assert!(text.contains("08001234"), "missing PC");
        assert!(text.contains("Stack Trace"), "missing stack trace header");
    }

    // ── Dedup hash ───────────────────────────────────────────────────────────

    #[test]
    fn dedup_hash_stable() {
        let h1 = FuzzReport::compute_dedup_hash(&ReportCrashType::HardFault, 0x0800_1234);
        let h2 = FuzzReport::compute_dedup_hash(&ReportCrashType::HardFault, 0x0800_1234);
        assert_eq!(h1, h2);
    }

    #[test]
    fn dedup_hash_differs_for_different_pc() {
        let h1 = FuzzReport::compute_dedup_hash(&ReportCrashType::HardFault, 0x0800_1234);
        let h2 = FuzzReport::compute_dedup_hash(&ReportCrashType::HardFault, 0x0800_5678);
        assert_ne!(h1, h2);
    }

    #[test]
    fn dedup_hash_differs_for_different_type() {
        let h1 = FuzzReport::compute_dedup_hash(&ReportCrashType::HardFault, 0x0800_1234);
        let h2 = FuzzReport::compute_dedup_hash(&ReportCrashType::BusFault, 0x0800_1234);
        assert_ne!(h1, h2);
    }

    // ── base64 ───────────────────────────────────────────────────────────────

    #[test]
    fn base64_encode_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    // ── CrashSeverity ordering ───────────────────────────────────────────────

    #[test]
    fn severity_ordering() {
        assert!(CrashSeverity::Info < CrashSeverity::Low);
        assert!(CrashSeverity::Low < CrashSeverity::Medium);
        assert!(CrashSeverity::Medium < CrashSeverity::High);
        assert!(CrashSeverity::High < CrashSeverity::Critical);
    }
}
