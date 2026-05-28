use clap::Parser;
use log::{info, error};
use std::path::PathBuf;
use std::fs;

use dexe::frontend;
use dexe::cfg;
use dexe::ir;
use dexe::backend;

/// dEXE — x86_64 ELF/PE binary decompiler to C99
#[derive(Parser, Debug)]
#[command(name = "dexe", version, about)]
struct Args {
    /// Path to the input binary (ELF or PE)
    #[arg(short = 'i', long = "input")]
    input: PathBuf,

    /// Path for the output C file
    #[arg(short = 'o', long = "output")]
    output: PathBuf,
}

fn main() {
    // Initialize logger (controlled by RUST_LOG env var)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .target(env_logger::Target::Stderr)
        .init();

    let args = Args::parse();

    info!("dEXE decompiler v{}", env!("CARGO_PKG_VERSION"));
    info!("Input:  {}", args.input.display());
    info!("Output: {}", args.output.display());

    // ── Stage 1: Load binary ──────────────────────────────────────────
    info!("═══ Stage 1/4: Loading binary ═══");
    let binary_info = match frontend::load_binary(&args.input) {
        Ok(info) => info,
        Err(e) => {
            error!("Failed to load binary: {}", e);
            std::process::exit(1);
        }
    };
    info!(
        "Loaded {:?} binary, entry=0x{:x}, .text={} bytes, {} symbols",
        binary_info.format,
        binary_info.entry_point,
        binary_info.text_data.len(),
        binary_info.symbols.len()
    );

    // ── Stage 2: Discover functions & build CFGs ──────────────────────
    info!("═══ Stage 2/4: Discovering functions & building CFGs ═══");
    let functions = match frontend::discover_functions(&binary_info) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to discover functions: {}", e);
            std::process::exit(1);
        }
    };
    info!("Discovered {} function(s)", functions.len());

    let cfgs: Vec<_> = functions.iter().map(|f| {
        let c = cfg::build_cfg(f);
        info!(
            "  CFG for {} @ 0x{:x}: {} block(s), {} edge(s)",
            c.func_name, c.func_addr,
            c.blocks.len(), c.edges.len()
        );
        c
    }).collect();

    // ── Stage 3: Lift to IR ───────────────────────────────────────────
    info!("═══ Stage 3/4: Lifting to SSA IR ═══");
    let ir_functions: Vec<_> = cfgs.iter().map(|c| {
        let ir_func = ir::lift_function(c);
        let total_ir: usize = ir_func.blocks.values().map(|b| b.instructions.len()).sum();
        info!(
            "  Lifted {} @ 0x{:x}: {} block(s), {} IR instruction(s)",
            ir_func.name, ir_func.addr,
            ir_func.blocks.len(), total_ir
        );
        ir_func
    }).collect();

    // ── Stage 4: Emit C code ──────────────────────────────────────────
    info!("═══ Stage 4/4: Emitting C99 code ═══");
    let c_source = backend::emit_c(&ir_functions, &binary_info.symbols);

    match fs::write(&args.output, &c_source) {
        Ok(()) => {
            info!(
                "Wrote {} bytes of C source to {}",
                c_source.len(),
                args.output.display()
            );
        }
        Err(e) => {
            error!("Failed to write output: {}", e);
            std::process::exit(1);
        }
    }

    info!("═══ Decompilation complete ═══");
}
