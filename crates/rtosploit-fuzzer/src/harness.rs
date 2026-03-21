//! RTOS-specific fuzz harnesses (FreeRTOS, ThreadX, Zephyr).
//!
//! Provides the `FuzzHarness` trait for pluggable execution backends and two
//! concrete implementations:
//!
//! - [`QemuHarness`] — spawns firmware in QEMU, monitors via QMP/GDB
//! - [`InProcessHarness`] — mock execution for testing without QEMU

use std::path::PathBuf;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::config::FuzzerConfig;

// ── HarnessConfig ────────────────────────────────────────────────────────────

/// Configuration for initialising a fuzz harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessConfig {
    /// Path to the firmware binary (ELF or raw .bin).
    pub firmware_path: PathBuf,
    /// QEMU machine type, e.g. `"lm3s6965evb"`, `"stm32vldiscovery"`.
    pub machine: String,
    /// Target RTOS name, e.g. `"freertos"`, `"zephyr"`, `"threadx"`.
    pub rtos: String,
    /// Per-execution timeout in milliseconds.
    pub timeout_ms: u64,
    /// TCP port for GDB stub (0 = disabled).
    pub gdb_port: u16,
    /// TCP port for QMP control socket (0 = disabled).
    pub qmp_port: u16,
}

impl HarnessConfig {
    pub fn new(firmware_path: PathBuf, machine: &str, rtos: &str, timeout_ms: u64) -> Self {
        Self {
            firmware_path,
            machine: machine.to_string(),
            rtos: rtos.to_string(),
            timeout_ms,
            gdb_port: 0,
            qmp_port: 0,
        }
    }
}

// ── ExitCode & CrashInfo ─────────────────────────────────────────────────────

/// Describes *how* the firmware exited after a single fuzz iteration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExitCode {
    /// Ran to completion / returned normally.
    Normal,
    /// Crashed — includes diagnostic information.
    Crash(CrashInfo),
    /// Exceeded the configured timeout.
    Timeout,
    /// Stopped making forward progress (e.g. infinite loop without crashing).
    Hang,
}

/// Diagnostic payload attached to [`ExitCode::Crash`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CrashInfo {
    /// Human-readable crash classification, e.g. `"HardFault"`, `"BusFault"`.
    pub crash_type: String,
    /// Program counter at time of fault.
    pub pc: u32,
    /// Faulting address (BFAR/MMFAR), or `0` when not applicable.
    pub fault_address: u32,
    /// Register dump: r0-r12, sp, lr, pc, xpsr (index = register number).
    pub registers: Vec<u32>,
}

// ── ExecutionResult ──────────────────────────────────────────────────────────

/// The full result returned by a harness after running one input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessExecutionResult {
    /// How the execution terminated.
    pub exit_code: ExitCode,
    /// AFL-style edge coverage bitmap collected during execution.
    #[serde(skip)]
    pub coverage_bitmap: Vec<u8>,
    /// Wall-clock execution time in milliseconds.
    pub execution_time_ms: u64,
    /// Captured standard output (may be empty).
    pub stdout: String,
    /// Captured standard error (may be empty).
    pub stderr: String,
}

// ── FuzzHarness trait ────────────────────────────────────────────────────────

/// Pluggable execution backend for the fuzzer.
///
/// Implementors are responsible for:
/// 1. Setting up the execution environment ([`setup`]).
/// 2. Running one fuzz input and collecting results ([`execute`]).
/// 3. Resetting state between iterations ([`reset`]).
/// 4. Tearing down resources when the campaign ends ([`teardown`]).
pub trait FuzzHarness {
    /// Human-readable name of this harness (used in logs and reports).
    fn name(&self) -> &str;

    /// One-time initialisation: load firmware, start QEMU, etc.
    fn setup(&mut self, config: &HarnessConfig) -> anyhow::Result<()>;

    /// Run a single fuzz input and return the result.
    fn execute(&mut self, input: &[u8]) -> anyhow::Result<HarnessExecutionResult>;

    /// Reset the target to a clean state between iterations.
    fn reset(&mut self) -> anyhow::Result<()>;

    /// Tear down the execution environment (kill processes, free resources).
    fn teardown(&mut self) -> anyhow::Result<()>;
}

// ── QemuHarness ──────────────────────────────────────────────────────────────

/// Runs firmware in a QEMU system-emulation process, monitoring execution via
/// QMP and GDB.
///
/// Requires the `qemu` feature flag for real process spawning; without it the
/// struct can still be constructed but [`execute`] will return an error.
pub struct QemuHarness {
    config: Option<HarnessConfig>,
    #[allow(dead_code)]
    fuzzer_config: FuzzerConfig,
    /// QEMU child process handle (populated after setup).
    #[cfg(feature = "qemu")]
    child: Option<std::process::Child>,
}

impl QemuHarness {
    pub fn new(fuzzer_config: FuzzerConfig) -> Self {
        Self {
            config: None,
            fuzzer_config,
            #[cfg(feature = "qemu")]
            child: None,
        }
    }
}

impl FuzzHarness for QemuHarness {
    fn name(&self) -> &str {
        "qemu"
    }

    fn setup(&mut self, config: &HarnessConfig) -> anyhow::Result<()> {
        if !config.firmware_path.exists() {
            anyhow::bail!("firmware not found: {}", config.firmware_path.display());
        }
        self.config = Some(config.clone());
        log::info!(
            "QemuHarness: setup machine={} rtos={} firmware={}",
            config.machine,
            config.rtos,
            config.firmware_path.display(),
        );
        // Real QEMU spawning is behind the `qemu` feature flag and not yet
        // implemented — see `engine::qemu_executor` for the planned extension
        // point.
        Ok(())
    }

    fn execute(&mut self, input: &[u8]) -> anyhow::Result<HarnessExecutionResult> {
        let _config = self
            .config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("QemuHarness: setup() has not been called"))?;

        let start = Instant::now();

        // Without the `qemu` feature we cannot actually spawn a process.
        // Return a timeout result so callers can still exercise the pipeline.
        #[cfg(not(feature = "qemu"))]
        {
            let _ = input;
            let elapsed = start.elapsed().as_millis() as u64;
            log::debug!("QemuHarness: qemu feature not enabled, returning stub timeout");
            return Ok(HarnessExecutionResult {
                exit_code: ExitCode::Timeout,
                coverage_bitmap: Vec::new(),
                execution_time_ms: elapsed,
                stdout: String::new(),
                stderr: "QEMU feature not enabled".to_string(),
            });
        }

        #[cfg(feature = "qemu")]
        {
            // TODO: full QEMU integration
            //  1. Write `input` to a shared-memory region or temp file.
            //  2. Resume the QEMU guest via QMP `cont`.
            //  3. Wait for the guest to hit the exit breakpoint, crash, or timeout.
            //  4. Read coverage bitmap from shared memory.
            //  5. Collect crash info from GDB if applicable.
            let _ = (input, config);
            let elapsed = start.elapsed().as_millis() as u64;
            Ok(HarnessExecutionResult {
                exit_code: ExitCode::Normal,
                coverage_bitmap: Vec::new(),
                execution_time_ms: elapsed,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        // Reset guest state via QMP `system_reset` (when QEMU is running).
        log::trace!("QemuHarness: reset");
        Ok(())
    }

    fn teardown(&mut self) -> anyhow::Result<()> {
        log::info!("QemuHarness: teardown");
        #[cfg(feature = "qemu")]
        {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        self.config = None;
        Ok(())
    }
}

// ── InProcessHarness ─────────────────────────────────────────────────────────

/// Mock harness for unit tests and CI — no QEMU required.
///
/// Uses deterministic, input-derived behaviour so that coverage growth and
/// crash detection can be exercised end-to-end.
pub struct InProcessHarness {
    config: Option<HarnessConfig>,
    execution_count: u64,
}

impl InProcessHarness {
    pub fn new() -> Self {
        Self {
            config: None,
            execution_count: 0,
        }
    }

    pub fn execution_count(&self) -> u64 {
        self.execution_count
    }
}

impl Default for InProcessHarness {
    fn default() -> Self {
        Self::new()
    }
}

impl FuzzHarness for InProcessHarness {
    fn name(&self) -> &str {
        "in-process"
    }

    fn setup(&mut self, config: &HarnessConfig) -> anyhow::Result<()> {
        log::info!(
            "InProcessHarness: setup (firmware={}, rtos={})",
            config.firmware_path.display(),
            config.rtos,
        );
        self.config = Some(config.clone());
        Ok(())
    }

    fn execute(&mut self, input: &[u8]) -> anyhow::Result<HarnessExecutionResult> {
        let _config = self
            .config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("InProcessHarness: setup() has not been called"))?;

        let start = Instant::now();
        self.execution_count += 1;

        // Deterministic crash on the 0xDEADBEEF pattern (mirrors engine::simulate_execution).
        let crash_pattern: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
        if input.windows(4).any(|w| w == crash_pattern) {
            let elapsed = start.elapsed().as_millis() as u64;
            return Ok(HarnessExecutionResult {
                exit_code: ExitCode::Crash(CrashInfo {
                    crash_type: "HardFault".to_string(),
                    pc: 0xDEAD_BEEF,
                    fault_address: 0xDEAD_BEEF,
                    registers: vec![0; 16],
                }),
                coverage_bitmap: Vec::new(),
                execution_time_ms: elapsed,
                stdout: String::new(),
                stderr: "simulated HardFault on DEADBEEF pattern".to_string(),
            });
        }

        // Simulate a hang on all-zero input.
        if !input.is_empty() && input.iter().all(|&b| b == 0) {
            let elapsed = start.elapsed().as_millis() as u64;
            return Ok(HarnessExecutionResult {
                exit_code: ExitCode::Hang,
                coverage_bitmap: Vec::new(),
                execution_time_ms: elapsed,
                stdout: String::new(),
                stderr: "simulated hang on all-zero input".to_string(),
            });
        }

        // Normal execution: derive fake coverage from input bytes.
        let mut bitmap = vec![0u8; crate::coverage::BITMAP_SIZE];
        let mut prev: u32 = 0x0800_0000;
        for (i, &byte) in input.iter().enumerate() {
            let next = prev.wrapping_add(byte as u32).wrapping_add(i as u32 * 4);
            let id = crate::coverage::compute_edge_id(prev, next);
            bitmap[id] = bitmap[id].saturating_add(1);
            prev = next;
        }

        let elapsed = start.elapsed().as_millis() as u64;
        Ok(HarnessExecutionResult {
            exit_code: ExitCode::Normal,
            coverage_bitmap: bitmap,
            execution_time_ms: elapsed,
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    fn reset(&mut self) -> anyhow::Result<()> {
        Ok(())
    }

    fn teardown(&mut self) -> anyhow::Result<()> {
        self.config = None;
        self.execution_count = 0;
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_config() -> HarnessConfig {
        HarnessConfig {
            firmware_path: PathBuf::from("/dev/null"), // dummy
            machine: "lm3s6965evb".to_string(),
            rtos: "freertos".to_string(),
            timeout_ms: 1000,
            gdb_port: 0,
            qmp_port: 0,
        }
    }

    // ── InProcessHarness ─────────────────────────────────────────────────────

    #[test]
    fn in_process_name() {
        let h = InProcessHarness::new();
        assert_eq!(h.name(), "in-process");
    }

    #[test]
    fn in_process_setup_and_normal_execution() {
        let mut h = InProcessHarness::new();
        h.setup(&test_config()).unwrap();
        let res = h.execute(&[0xAA, 0xBB, 0xCC]).unwrap();
        assert_eq!(res.exit_code, ExitCode::Normal);
        assert_eq!(h.execution_count(), 1);
    }

    #[test]
    fn in_process_crash_on_deadbeef() {
        let mut h = InProcessHarness::new();
        h.setup(&test_config()).unwrap();
        let res = h.execute(&[0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00]).unwrap();
        assert!(matches!(res.exit_code, ExitCode::Crash(_)));
    }

    #[test]
    fn in_process_hang_on_all_zeros() {
        let mut h = InProcessHarness::new();
        h.setup(&test_config()).unwrap();
        let res = h.execute(&[0, 0, 0, 0]).unwrap();
        assert_eq!(res.exit_code, ExitCode::Hang);
    }

    #[test]
    fn in_process_execute_without_setup_errors() {
        let mut h = InProcessHarness::new();
        let res = h.execute(&[1, 2, 3]);
        assert!(res.is_err());
    }

    #[test]
    fn in_process_teardown_resets_count() {
        let mut h = InProcessHarness::new();
        h.setup(&test_config()).unwrap();
        h.execute(&[1]).unwrap();
        assert_eq!(h.execution_count(), 1);
        h.teardown().unwrap();
        assert_eq!(h.execution_count(), 0);
    }

    // ── QemuHarness (without qemu feature) ───────────────────────────────────

    #[test]
    fn qemu_harness_name() {
        let h = QemuHarness::new(FuzzerConfig::default_config());
        assert_eq!(h.name(), "qemu");
    }

    #[test]
    fn qemu_harness_execute_without_setup_errors() {
        let mut h = QemuHarness::new(FuzzerConfig::default_config());
        let res = h.execute(&[1, 2, 3]);
        assert!(res.is_err());
    }

    // ── HarnessConfig ────────────────────────────────────────────────────────

    #[test]
    fn harness_config_new() {
        let cfg = HarnessConfig::new(
            PathBuf::from("/firmware.bin"),
            "stm32vldiscovery",
            "zephyr",
            2000,
        );
        assert_eq!(cfg.machine, "stm32vldiscovery");
        assert_eq!(cfg.rtos, "zephyr");
        assert_eq!(cfg.timeout_ms, 2000);
        assert_eq!(cfg.gdb_port, 0);
        assert_eq!(cfg.qmp_port, 0);
    }

    // ── ExitCode ─────────────────────────────────────────────────────────────

    #[test]
    fn exit_code_variants_are_distinct() {
        let normal = ExitCode::Normal;
        let timeout = ExitCode::Timeout;
        let hang = ExitCode::Hang;
        assert_ne!(normal, timeout);
        assert_ne!(timeout, hang);
    }
}
