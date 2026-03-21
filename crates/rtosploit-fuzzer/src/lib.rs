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
pub use corpus::{Corpus, CorpusEntry};
pub use coverage::{CoverageBitmap, FuzzerStats};
pub use crash::{
    find_function_prologues, patch_vector_table, CrashDetector, CrashReport, CrashType,
    HeapShadowTracker, WatchdogState,
};
pub use engine::{ExecutionResult, FuzzerEngine};
pub use harness::{
    CrashInfo, ExitCode, FuzzHarness, HarnessConfig, HarnessExecutionResult, InProcessHarness,
    QemuHarness,
};
pub use mmio::{MMIOInputSplitter, MMIOResponseProvider};
pub use mutators::MutationScheduler;
pub use report::{CrashSeverity, FuzzReport, ReportCrashType};
