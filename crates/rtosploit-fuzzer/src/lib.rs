//! BareFuzz — Coverage-guided bare-metal RTOS firmware fuzzer.

pub mod config;
pub mod corpus;
pub mod coverage;
pub mod crash;
pub mod engine;
pub mod harness;
pub mod mmio;
pub mod mutators;
pub mod report;

pub use config::FuzzerConfig;
pub use coverage::{CoverageBitmap, FuzzerStats};
pub use engine::{ExecutionResult, FuzzerEngine};
pub use mmio::{MMIOInputSplitter, MMIOResponseProvider};
pub use mutators::MutationScheduler;
pub use crash::{
    CrashType, CrashReport, CrashDetector, patch_vector_table, WatchdogState,
    find_function_prologues, HeapShadowTracker,
};
pub use corpus::{Corpus, CorpusEntry};
pub use harness::{FuzzHarness, HarnessConfig, HarnessExecutionResult, ExitCode, CrashInfo, QemuHarness, InProcessHarness};
pub use report::{FuzzReport, CrashSeverity, ReportCrashType};
