// frontend.rs — Binary Parser & Disassembler
//
// Loads ELF / PE binaries, extracts the .text section and symbol table,
// then disassembles x86‑64 instructions and discovers function boundaries.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use capstone::prelude::*;
use capstone::Insn;
use log::{debug, info};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};

// ─── Public types ────────────────────────────────────────────────────────────

/// Maps virtual addresses to human‑readable symbol names.
pub type SymbolTable = BTreeMap<u64, String>;

/// Recognised binary container formats.
#[derive(Debug, Clone)]
pub enum BinaryFormat {
    Elf,
    Pe,
    Unknown,
}

/// Everything we need from the parsed binary before disassembly.
#[derive(Debug, Clone)]
pub struct BinaryInfo {
    pub format: BinaryFormat,
    pub entry_point: u64,
    pub text_section_addr: u64,
    pub text_data: Vec<u8>,
    pub symbols: SymbolTable,
}

/// A single disassembled machine instruction.
#[derive(Debug, Clone)]
pub struct DisassembledInsn {
    pub address: u64,
    pub size: u8,
    pub mnemonic: String,
    pub op_str: String,
    pub bytes: Vec<u8>,
}

/// A contiguous range of instructions that belong to one function.
#[derive(Debug, Clone)]
pub struct DisassembledFunction {
    pub name: String,
    pub start_addr: u64,
    pub end_addr: u64,
    pub instructions: Vec<DisassembledInsn>,
}

// ─── Binary loading ──────────────────────────────────────────────────────────

/// Read and parse a binary from disk, returning metadata and the raw `.text`
/// section bytes required for disassembly.
pub fn load_binary(path: &Path) -> Result<BinaryInfo, Box<dyn std::error::Error>> {
    let raw = std::fs::read(path)?;
    let obj = object::File::parse(&*raw)?;

    // Detect format
    let format = match obj.format() {
        object::BinaryFormat::Elf => BinaryFormat::Elf,
        object::BinaryFormat::Pe => BinaryFormat::Pe,
        _ => BinaryFormat::Unknown,
    };

    let entry_point = obj.entry();

    // Try to find .text, fall back to whichever section contains the entry
    let (text_addr, text_data) = find_text_section(&obj, entry_point)?;

    // Collect function symbols
    let mut symbols = SymbolTable::new();
    for sym in obj.symbols() {
        if sym.kind() == SymbolKind::Text {
            if let Ok(name) = sym.name() {
                if !name.is_empty() {
                    symbols.insert(sym.address(), name.to_string());
                }
            }
        }
    }

    info!(
        "Loaded {:?} binary — entry 0x{:x}, .text @ 0x{:x} ({} bytes), {} symbols",
        format,
        entry_point,
        text_addr,
        text_data.len(),
        symbols.len(),
    );

    Ok(BinaryInfo {
        format,
        entry_point,
        text_section_addr: text_addr,
        text_data,
        symbols,
    })
}

/// Locate the `.text` section.  If absent, fall back to the section that
/// contains the entry point address.
fn find_text_section(
    obj: &object::File,
    entry: u64,
) -> Result<(u64, Vec<u8>), Box<dyn std::error::Error>> {
    // 1. Look for an explicit .text section
    if let Some(sec) = obj.section_by_name(".text") {
        let data = sec.data()?.to_vec();
        return Ok((sec.address(), data));
    }

    // 2. Fallback: section that spans the entry point
    for sec in obj.sections() {
        let start = sec.address();
        let end = start + sec.size();
        if entry >= start && entry < end {
            let data = sec.data()?.to_vec();
            info!(
                "No .text section — using section \"{}\" (0x{:x}..0x{:x})",
                sec.name().unwrap_or("<unnamed>"),
                start,
                end
            );
            return Ok((start, data));
        }
    }

    Err("Could not locate a .text section or a section containing the entry point".into())
}

// ─── Function discovery ──────────────────────────────────────────────────────

/// Disassemble the text section and heuristically split it into functions.
pub fn discover_functions(
    info: &BinaryInfo,
) -> Result<Vec<DisassembledFunction>, Box<dyn std::error::Error>> {
    // 1. Set up Capstone in x86‑64 / detail mode
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
        .map_err(|e| format!("capstone init: {e}"))?;

    // 2. Disassemble the entire text section
    let insns = cs
        .disasm_all(&info.text_data, info.text_section_addr)
        .map_err(|e| format!("capstone disasm: {e}"))?;

    info!(
        "Disassembled {} instructions from text section",
        insns.len()
    );

    // Convert into our owned type so we can slice freely later
    let all_insns: Vec<DisassembledInsn> = insns
        .iter()
        .map(|i| insn_to_owned(&i))
        .collect();

    // Build address → index lookup
    let addr_to_idx: BTreeMap<u64, usize> = all_insns
        .iter()
        .enumerate()
        .map(|(idx, i)| (i.address, idx))
        .collect();

    // 3. Seed function starts
    let mut func_starts: BTreeSet<u64> = BTreeSet::new();

    // (a) Every symbol from the symbol table
    let text_start = info.text_section_addr;
    let text_end = text_start + info.text_data.len() as u64;
    for &addr in info.symbols.keys() {
        if addr >= text_start && addr < text_end {
            func_starts.insert(addr);
        }
    }

    // (b) Entry point
    if info.entry_point >= text_start && info.entry_point < text_end {
        func_starts.insert(info.entry_point);
    }

    // (c) push rbp prologue scan  (0x55 == push rbp)
    //     We only consider it a function start when the byte actually
    //     lines up with the start of a disassembled instruction.
    for insn in &all_insns {
        if insn.bytes.first() == Some(&0x55)
            && insn.mnemonic == "push"
            && insn.op_str.contains("rbp")
        {
            func_starts.insert(insn.address);
        }
    }

    // (d) Follow direct call targets
    for insn in &all_insns {
        if insn.mnemonic == "call" {
            if let Some(target) = parse_hex_target(&insn.op_str) {
                if target >= text_start && target < text_end && addr_to_idx.contains_key(&target) {
                    func_starts.insert(target);
                }
            }
        }
    }

    debug!("Discovered {} candidate function starts", func_starts.len());

    // 4. Sort function starts and build DisassembledFunction objects
    let starts: Vec<u64> = func_starts.into_iter().collect();
    let mut functions: Vec<DisassembledFunction> = Vec::with_capacity(starts.len());

    for (i, &start) in starts.iter().enumerate() {
        // End address is the start of the *next* function, or end of text
        let end = if i + 1 < starts.len() {
            starts[i + 1]
        } else {
            text_end
        };

        // Slice instructions belonging to this range
        let func_insns: Vec<DisassembledInsn> = all_insns
            .iter()
            .filter(|ins| ins.address >= start && ins.address < end)
            .cloned()
            .collect();

        if func_insns.is_empty() {
            continue;
        }

        let name = info
            .symbols
            .get(&start)
            .cloned()
            .unwrap_or_else(|| format!("func_0x{:x}", start));

        info!("Function: {} @ 0x{:x} ({} insns)", name, start, func_insns.len());

        functions.push(DisassembledFunction {
            name,
            start_addr: start,
            end_addr: end,
            instructions: func_insns,
        });
    }

    Ok(functions)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Convert a capstone `Insn` reference into our owned `DisassembledInsn`.
fn insn_to_owned(insn: &Insn) -> DisassembledInsn {
    DisassembledInsn {
        address: insn.address(),
        size: insn.len() as u8,
        mnemonic: insn.mnemonic().unwrap_or("").to_string(),
        op_str: insn.op_str().unwrap_or("").to_string(),
        bytes: insn.bytes().to_vec(),
    }
}

/// Try to parse a hexadecimal immediate from capstone's operand string.
/// Handles both `0x1234` and bare `1234` (hex) forms.
fn parse_hex_target(op_str: &str) -> Option<u64> {
    let s = op_str.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok()
    } else {
        // Try as plain hex
        u64::from_str_radix(s, 16).ok()
    }
}
