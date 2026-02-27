//! SVD stub generator CLI — standalone binary entry point.

use anyhow::Result;
use clap::Parser;
use rtosploit_svd::{
    parser::parse_svd,
    registry::{peripheral_priority, sort_by_priority},
    stub::{generate_all_stubs, StubMode},
};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "svd-gen", about = "Generate QEMU peripheral stubs from ARM CMSIS SVD files")]
struct Args {
    /// Path to SVD file
    svd: PathBuf,

    /// Output directory
    #[arg(short, long, default_value = "svd-stubs")]
    output: PathBuf,

    /// Stub generation mode: reset-value, read-write, fuzzer-driven
    #[arg(short, long, default_value = "reset-value")]
    mode: String,

    /// MCU name prefix for generated files
    #[arg(short, long)]
    name: Option<String>,

    /// Maximum number of peripherals to generate (0 = all)
    #[arg(long, default_value = "0")]
    max_peripherals: usize,

    /// Print peripheral list without generating files
    #[arg(long)]
    list: bool,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let device = parse_svd(&args.svd)?;
    let mcu_name = args.name.unwrap_or_else(|| device.name.clone());
    let mode = StubMode::from_str(&args.mode);

    println!("Device: {} ({} peripherals)", device.name, device.peripherals.len());

    let mut peripherals = device.peripherals.clone();
    sort_by_priority(&mut peripherals, |p| &p.name);

    if args.list {
        for p in &peripherals {
            println!(
                "  {:20} base=0x{:08x} regs={:3} priority={:?}",
                p.name,
                p.base_address,
                p.registers.len(),
                peripheral_priority(&p.name),
            );
        }
        return Ok(());
    }

    let to_generate = if args.max_peripherals > 0 && args.max_peripherals < peripherals.len() {
        &peripherals[..args.max_peripherals]
    } else {
        &peripherals
    };

    let output_dir = args.output.join(&mcu_name.to_lowercase());
    std::fs::create_dir_all(&output_dir)?;

    let stubs = generate_all_stubs(to_generate, &mcu_name, mode);
    for (filename, content) in &stubs {
        let path = output_dir.join(filename);
        std::fs::write(&path, content)?;
        println!("  Generated: {}", path.display());
    }

    println!("Done: {} stub files in {}", stubs.len(), output_dir.display());
    Ok(())
}
