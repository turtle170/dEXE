// cfg.rs — Control Flow Graph Constructor
//
// Takes a `DisassembledFunction` and splits it into `BasicBlock`s connected
// by typed edges (jump, conditional branch, call, return, etc.).

use std::collections::{BTreeMap, BTreeSet};

use log::{info, warn};

use crate::frontend::{DisassembledFunction, DisassembledInsn};

// ─── Public types ────────────────────────────────────────────────────────────

/// A block identifier — simple sequential index.
pub type BlockId = usize;

/// How a basic block transfers control.
#[derive(Debug, Clone)]
pub enum Terminator {
    /// Falls through to the next sequential block.
    Fallthrough(BlockId),
    /// Unconditional jump.
    Jump(BlockId),
    /// Conditional branch (e.g. `je`, `jne`, …).
    ConditionalJump {
        taken: BlockId,
        fallthrough: BlockId,
        condition: String,
    },
    /// Function return (`ret` / `retn`).
    Return,
    /// A `call` instruction — control returns to `fallthrough` afterwards.
    Call { target: u64, fallthrough: BlockId },
    /// Halt / trap / undefined instruction.
    Halt,
}

/// A maximal straight‑line sequence of instructions.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockId,
    pub start_addr: u64,
    pub end_addr: u64,
    pub instructions: Vec<DisassembledInsn>,
    pub terminator: Terminator,
}

/// The complete CFG for a single function.
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    pub func_name: String,
    pub func_addr: u64,
    pub blocks: BTreeMap<BlockId, BasicBlock>,
    pub entry_block: BlockId,
    pub edges: Vec<(BlockId, BlockId)>,
    pub addr_to_block: BTreeMap<u64, BlockId>,
}

// ─── Conditional‑branch mnemonics ────────────────────────────────────────────

const COND_JUMPS: &[&str] = &[
    "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "jo", "jno",
    "js", "jns", "jp", "jnp",
];

const HALT_MNEMONICS: &[&str] = &["hlt", "int3", "ud2"];

// ─── Builder ─────────────────────────────────────────────────────────────────

/// Build a control‑flow graph from a disassembled function.
pub fn build_cfg(func: &DisassembledFunction) -> ControlFlowGraph {
    let insns = &func.instructions;

    if insns.is_empty() {
        info!(
            "CFG for {} @ 0x{:x}: 0 blocks (empty function)",
            func.name, func.start_addr
        );
        return ControlFlowGraph {
            func_name: func.name.clone(),
            func_addr: func.start_addr,
            blocks: BTreeMap::new(),
            entry_block: 0,
            edges: Vec::new(),
            addr_to_block: BTreeMap::new(),
        };
    }

    // ── 1. Identify block leaders ────────────────────────────────────────

    let mut leaders: BTreeSet<u64> = BTreeSet::new();

    // (a) Function entry is always a leader
    leaders.insert(insns[0].address);

    // Build a set of valid instruction addresses for quick membership tests
    let valid_addrs: BTreeSet<u64> = insns.iter().map(|i| i.address).collect();

    for (idx, insn) in insns.iter().enumerate() {
        let mn = insn.mnemonic.as_str();

        let is_jump = mn == "jmp" || COND_JUMPS.contains(&mn);
        let is_call = mn == "call";
        let is_ret = mn == "ret" || mn == "retn";
        let is_halt = HALT_MNEMONICS.contains(&mn);

        if is_jump || is_call || is_ret || is_halt {
            // (c) The instruction *after* any branch / call / ret is a leader
            if idx + 1 < insns.len() {
                leaders.insert(insns[idx + 1].address);
            }

            // (b) Jump / conditional‑jump targets are leaders
            if is_jump || (COND_JUMPS.contains(&mn)) {
                if let Some(target) = parse_hex_target(&insn.op_str) {
                    if valid_addrs.contains(&target) {
                        leaders.insert(target);
                    }
                }
            }
        }
    }

    // ── 2. Partition instructions into basic blocks ──────────────────────

    let leader_vec: Vec<u64> = leaders.iter().copied().collect();
    let _leader_set: BTreeSet<u64> = leaders; // move, kept for potential future use

    // Map: leader_addr → BlockId
    let mut addr_to_block: BTreeMap<u64, BlockId> = BTreeMap::new();
    for (id, &addr) in leader_vec.iter().enumerate() {
        addr_to_block.insert(addr, id);
    }

    // Collect instructions per block
    let mut block_insns: Vec<Vec<DisassembledInsn>> = vec![Vec::new(); leader_vec.len()];
    let mut current_block: usize = 0;

    for insn in insns {
        // If this instruction is a leader (and not the first instruction of
        // the current block), advance to the next block.
        if let Some(&bid) = addr_to_block.get(&insn.address) {
            current_block = bid;
        }
        block_insns[current_block].push(insn.clone());
    }

    // ── 3. Classify terminators & build blocks ───────────────────────────

    let mut blocks: BTreeMap<BlockId, BasicBlock> = BTreeMap::new();
    let mut edges: Vec<(BlockId, BlockId)> = Vec::new();

    for (id, bi) in block_insns.iter().enumerate() {
        if bi.is_empty() {
            continue;
        }

        let start_addr = bi.first().unwrap().address;
        let last = bi.last().unwrap();
        let end_addr = last.address + last.size as u64;
        let mn = last.mnemonic.as_str();

        let next_block_id = id + 1; // may be out of range
        let has_next = next_block_id < leader_vec.len();

        let terminator = if mn == "ret" || mn == "retn" {
            Terminator::Return
        } else if mn == "jmp" {
            match resolve_jump_target(&last.op_str, &addr_to_block, id) {
                Some(target_bid) => {
                    edges.push((id, target_bid));
                    Terminator::Jump(target_bid)
                }
                None => Terminator::Halt, // indirect jump we can't resolve
            }
        } else if COND_JUMPS.contains(&mn) {
            let taken = resolve_jump_target(&last.op_str, &addr_to_block, id);
            let fallthrough = if has_next { Some(next_block_id) } else { None };

            match (taken, fallthrough) {
                (Some(t), Some(f)) => {
                    edges.push((id, t));
                    edges.push((id, f));
                    Terminator::ConditionalJump {
                        taken: t,
                        fallthrough: f,
                        condition: mn.to_string(),
                    }
                }
                (Some(t), None) => {
                    edges.push((id, t));
                    // No fallthrough possible (last block), degenerate to jump
                    Terminator::Jump(t)
                }
                (None, Some(f)) => {
                    // Unresolvable target — treat taken as fallthrough
                    edges.push((id, f));
                    warn!(
                        "Unresolvable conditional target at 0x{:x}, falling through",
                        last.address
                    );
                    Terminator::Fallthrough(f)
                }
                (None, None) => Terminator::Halt,
            }
        } else if mn == "call" {
            let target_addr = parse_hex_target(&last.op_str).unwrap_or(0);
            if has_next {
                edges.push((id, next_block_id));
                Terminator::Call {
                    target: target_addr,
                    fallthrough: next_block_id,
                }
            } else {
                Terminator::Call {
                    target: target_addr,
                    fallthrough: id, // self‑loop as sentinel
                }
            }
        } else if HALT_MNEMONICS.contains(&mn) {
            Terminator::Halt
        } else {
            // Ordinary instruction at end of block — fallthrough
            if has_next {
                edges.push((id, next_block_id));
                Terminator::Fallthrough(next_block_id)
            } else {
                // Last block, no successor — treat as implicit return
                Terminator::Return
            }
        };

        blocks.insert(
            id,
            BasicBlock {
                id,
                start_addr,
                end_addr,
                instructions: bi.clone(),
                terminator,
            },
        );
    }

    let entry_block = *addr_to_block
        .get(&func.start_addr)
        .unwrap_or(&0);

    info!(
        "CFG for {} @ 0x{:x}: {} blocks, {} edges",
        func.name,
        func.start_addr,
        blocks.len(),
        edges.len(),
    );

    ControlFlowGraph {
        func_name: func.name.clone(),
        func_addr: func.start_addr,
        blocks,
        entry_block,
        edges,
        addr_to_block,
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Try to resolve a jump operand to a `BlockId`.
fn resolve_jump_target(
    op_str: &str,
    addr_to_block: &BTreeMap<u64, BlockId>,
    _self_id: BlockId,
) -> Option<BlockId> {
    parse_hex_target(op_str).and_then(|addr| addr_to_block.get(&addr).copied())
}

/// Parse a hex immediate from capstone's operand string (`0x1234` or bare hex).
fn parse_hex_target(op_str: &str) -> Option<u64> {
    let s = op_str.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).ok()
    } else {
        u64::from_str_radix(s, 16).ok()
    }
}
