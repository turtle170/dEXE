//! SSA Intermediate Representation Lifter
//!
//! Converts x86_64 disassembled instructions (from capstone via the CFG) into
//! a typed, SSA-versioned intermediate representation suitable for analysis
//! and code generation.

use std::collections::{BTreeMap, HashMap};

use crate::cfg::{BlockId, ControlFlowGraph};

// ---------------------------------------------------------------------------
// Core IR types
// ---------------------------------------------------------------------------

/// Base register or temporary variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VarBase {
    RAX,
    RBX,
    RCX,
    RDX,
    RSI,
    RDI,
    RSP,
    RBP,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    RFlags,
    Temp(u32),
}

/// An SSA-versioned variable identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VarId {
    pub base: VarBase,
    pub version: u32,
}

/// An operand in the IR.
#[derive(Debug, Clone)]
pub enum Operand {
    Var(VarId),
    Imm(i64),
    Mem {
        base: Option<VarId>,
        index: Option<VarId>,
        scale: u8,
        disp: i64,
    },
}

/// Condition codes for conditional jumps.
#[derive(Debug, Clone)]
pub enum Condition {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Below,
    BelowEqual,
    Above,
    AboveEqual,
    Sign,
    NotSign,
    Overflow,
    NotOverflow,
    Parity,
    NotParity,
}

/// Target of a call instruction.
#[derive(Debug, Clone)]
pub enum CallTarget {
    Direct(u64),
    Indirect(Operand),
    External(String),
}

/// IR opcodes – the core instruction set of the decompiler's IR.
#[derive(Debug, Clone)]
pub enum Opcode {
    Mov { dst: VarId, src: Operand },
    Load { dst: VarId, addr: Operand },
    Store { addr: Operand, src: Operand },
    Add { dst: VarId, lhs: Operand, rhs: Operand },
    Sub { dst: VarId, lhs: Operand, rhs: Operand },
    Mul { dst: VarId, lhs: Operand, rhs: Operand },
    And { dst: VarId, lhs: Operand, rhs: Operand },
    Or  { dst: VarId, lhs: Operand, rhs: Operand },
    Xor { dst: VarId, lhs: Operand, rhs: Operand },
    Shl { dst: VarId, lhs: Operand, rhs: Operand },
    Shr { dst: VarId, lhs: Operand, rhs: Operand },
    Not { dst: VarId, src: Operand },
    Neg { dst: VarId, src: Operand },
    Lea { dst: VarId, addr: Operand },
    Cmp { lhs: Operand, rhs: Operand },
    Test { lhs: Operand, rhs: Operand },
    Jmp { target: u64 },
    Jcc { condition: Condition, target: u64, fallthrough: u64 },
    Cmovcc { condition: Condition, dst: VarId, src: Operand },
    Setcc { condition: Condition, dst: VarId },
    Call { target: CallTarget, fallthrough: u64 },
    Ret,
    Nop,
    Push { src: Operand },
    Pop { dst: VarId },
    AtomicRMW { op: String, addr: Operand, src: Operand },
    Unknown { mnemonic: String, addr: u64 },
}

/// A single IR instruction, tied to a source address.
#[derive(Debug, Clone)]
pub struct IRInstruction {
    pub addr: u64,
    pub opcode: Opcode,
}

/// An IR basic block.
#[derive(Debug, Clone)]
pub struct IRBlock {
    pub id: BlockId,
    pub start_addr: u64,
    pub instructions: Vec<IRInstruction>,
}

/// An entire lifted function in SSA IR form.
#[derive(Debug, Clone)]
pub struct IRFunction {
    pub name: String,
    pub addr: u64,
    pub blocks: BTreeMap<BlockId, IRBlock>,
    pub entry_block: BlockId,
    pub block_addrs: BTreeMap<BlockId, u64>,
}

// ---------------------------------------------------------------------------
// SSA versioning helpers
// ---------------------------------------------------------------------------

/// Allocate a new SSA version for `base`, returning the new VarId.
fn new_version(versions: &mut HashMap<VarBase, u32>, base: VarBase) -> VarId {
    let ver = versions.entry(base).or_insert(0);
    *ver += 1;
    VarId { base, version: *ver }
}

/// Get the current SSA VarId for `base` (version 0 if never written).
fn current_var(versions: &HashMap<VarBase, u32>, base: VarBase) -> VarId {
    let version = versions.get(&base).copied().unwrap_or(0);
    VarId { base, version }
}

// ---------------------------------------------------------------------------
// Operand / register parsing helpers
// ---------------------------------------------------------------------------

/// Try to map a textual register name to a `VarBase`.
/// Maps 32-bit, 16-bit, and 8-bit sub-registers to their 64-bit parent.
fn parse_register(s: &str) -> Option<VarBase> {
    let s = s.trim().to_lowercase();
    match s.as_str() {
        "rax" | "eax" | "ax" | "al" | "ah" => Some(VarBase::RAX),
        "rbx" | "ebx" | "bx" | "bl" | "bh" => Some(VarBase::RBX),
        "rcx" | "ecx" | "cx" | "cl" | "ch" => Some(VarBase::RCX),
        "rdx" | "edx" | "dx" | "dl" | "dh" => Some(VarBase::RDX),
        "rsi" | "esi" | "si" | "sil"       => Some(VarBase::RSI),
        "rdi" | "edi" | "di" | "dil"       => Some(VarBase::RDI),
        "rsp" | "esp" | "sp" | "spl"       => Some(VarBase::RSP),
        "rbp" | "ebp" | "bp" | "bpl"       => Some(VarBase::RBP),
        "r8"  | "r8d"  | "r8w"  | "r8b"    => Some(VarBase::R8),
        "r9"  | "r9d"  | "r9w"  | "r9b"    => Some(VarBase::R9),
        "r10" | "r10d" | "r10w" | "r10b"   => Some(VarBase::R10),
        "r11" | "r11d" | "r11w" | "r11b"   => Some(VarBase::R11),
        "r12" | "r12d" | "r12w" | "r12b"   => Some(VarBase::R12),
        "r13" | "r13d" | "r13w" | "r13b"   => Some(VarBase::R13),
        "r14" | "r14d" | "r14w" | "r14b"   => Some(VarBase::R14),
        "r15" | "r15d" | "r15w" | "r15b"   => Some(VarBase::R15),
        "rflags" | "eflags" | "flags"      => Some(VarBase::RFlags),
        _ => None,
    }
}

/// Parse an immediate value (hex with `0x` prefix, or decimal).
fn parse_immediate(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Handle negative immediates
    if let Some(rest) = s.strip_prefix('-') {
        let rest = rest.trim();
        if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            i64::from_str_radix(hex, 16).ok().map(|v| -v)
        } else {
            rest.parse::<i64>().ok().map(|v| -v)
        }
    } else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        // Positive hex – parse as u64 first to handle large constants, then bitcast
        u64::from_str_radix(hex, 16).ok().map(|v| v as i64)
    } else {
        // Try decimal
        s.parse::<i64>().ok()
    }
}

/// Split an `op_str` such as `"rax, [rbp - 0x8]"` into individual operand strings,
/// respecting square brackets (so commas inside `[…]` are not split).
fn parse_operands(op_str: &str) -> Vec<String> {
    let op_str = op_str.trim();
    if op_str.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut current = String::new();
    let mut bracket_depth = 0u32;

    for ch in op_str.chars() {
        match ch {
            '[' => {
                bracket_depth += 1;
                current.push(ch);
            }
            ']' => {
                bracket_depth = bracket_depth.saturating_sub(1);
                current.push(ch);
            }
            ',' if bracket_depth == 0 => {
                let piece = current.trim().to_string();
                if !piece.is_empty() {
                    result.push(piece);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let piece = current.trim().to_string();
    if !piece.is_empty() {
        result.push(piece);
    }
    result
}

/// Strip size-prefix keywords such as `qword ptr`, `dword ptr`, etc.
fn strip_size_prefix(s: &str) -> &str {
    // We need to do case-insensitive matching but return a slice of the
    // original string, so we check the lowercased version for the prefix
    // length and then slice the original.
    let lower = s.to_lowercase();
    let prefixes: &[&str] = &[
        "xmmword ptr ",
        "ymmword ptr ",
        "zmmword ptr ",
        "tbyte ptr ",
        "tword ptr ",
        "oword ptr ",
        "qword ptr ",
        "dword ptr ",
        "word ptr ",
        "byte ptr ",
    ];
    for prefix in prefixes {
        if lower.starts_with(prefix) {
            return &s[prefix.len()..];
        }
    }
    s
}

/// Parse a memory operand like `[rbp - 0x10]`, `[rsp + rax*4 + 0x8]`, etc.
/// The input may or may not include surrounding brackets and size prefixes.
/// Returns an `Operand::Mem`.
fn parse_memory_operand(s: &str, versions: &HashMap<VarBase, u32>) -> Operand {
    // Strip size prefixes first
    let s = strip_size_prefix(s.trim());

    // Extract the contents between '[' and ']'
    let inner = if let Some(start) = s.find('[') {
        if let Some(end) = s.rfind(']') {
            s[start + 1..end].trim()
        } else {
            s.trim_start_matches('[').trim()
        }
    } else {
        s
    };

    let mut base_reg: Option<VarId> = None;
    let mut index_reg: Option<VarId> = None;
    let mut scale: u8 = 1;
    let mut disp: i64 = 0;

    // Normalize: replace " - " with " + -" so every component is +-separated
    let normalized = inner.replace(" - ", " + -").replace("- ", "+ -");
    let terms: Vec<&str> = normalized
        .split('+')
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .collect();

    for term in &terms {
        let term = term.trim();
        if term.is_empty() {
            continue;
        }

        // Check for scale pattern: reg*N or N*reg
        if term.contains('*') {
            let parts: Vec<&str> = term.split('*').map(|p| p.trim()).collect();
            if parts.len() == 2 {
                let (reg_part, scale_part) = if parse_register(parts[0]).is_some() {
                    (parts[0], parts[1])
                } else {
                    (parts[1], parts[0])
                };
                if let Some(vb) = parse_register(reg_part) {
                    index_reg = Some(current_var(versions, vb));
                    scale = parse_immediate(scale_part).unwrap_or(1) as u8;
                } else {
                    // Can't parse – treat entire term as displacement
                    if let Some(imm) = parse_immediate(term) {
                        disp = disp.wrapping_add(imm);
                    }
                }
            }
        } else if let Some(vb) = parse_register(term.trim_start_matches('-')) {
            // Register term (possibly negated — unusual but handled)
            if base_reg.is_none() {
                base_reg = Some(current_var(versions, vb));
            } else if index_reg.is_none() {
                index_reg = Some(current_var(versions, vb));
                // scale stays 1
            }
            // Extra registers beyond 2 are silently ignored
        } else if let Some(imm) = parse_immediate(term) {
            disp = disp.wrapping_add(imm);
        }
        // Unknown tokens are silently skipped
    }

    Operand::Mem {
        base: base_reg,
        index: index_reg,
        scale,
        disp,
    }
}

/// Determine if an operand string represents a memory access (contains `[`).
fn is_memory_operand(s: &str) -> bool {
    s.contains('[')
}

/// Parse a single operand string into an `Operand`.
fn parse_single_operand(s: &str, versions: &HashMap<VarBase, u32>) -> Operand {
    let s = s.trim();
    if is_memory_operand(s) {
        parse_memory_operand(s, versions)
    } else if let Some(vb) = parse_register(s) {
        Operand::Var(current_var(versions, vb))
    } else if let Some(imm) = parse_immediate(s) {
        Operand::Imm(imm)
    } else {
        // Could be a symbol name or something we can't resolve; treat as zero
        log::warn!("Cannot parse operand '{}', treating as Imm(0)", s);
        Operand::Imm(0)
    }
}

/// Try to extract the destination register base from an operand string.
fn dst_register(s: &str) -> Option<VarBase> {
    let s = s.trim();
    parse_register(strip_size_prefix(s))
}

// ---------------------------------------------------------------------------
// Condition-code parsing
// ---------------------------------------------------------------------------

/// Map capstone condition-code mnemonics (the suffix of jcc instructions) to
/// our `Condition` enum.
fn parse_condition_suffix(mnemonic: &str) -> Condition {
    let suffix = if mnemonic.starts_with('j') {
        &mnemonic[1..]
    } else {
        mnemonic
    };

    match suffix {
        "e" | "z"         => Condition::Equal,
        "ne" | "nz"       => Condition::NotEqual,
        "l" | "nge"       => Condition::Less,
        "le" | "ng"       => Condition::LessEqual,
        "g" | "nle"       => Condition::Greater,
        "ge" | "nl"       => Condition::GreaterEqual,
        "b" | "nae" | "c" => Condition::Below,
        "be" | "na"       => Condition::BelowEqual,
        "a" | "nbe"       => Condition::Above,
        "ae" | "nb" | "nc"=> Condition::AboveEqual,
        "s"               => Condition::Sign,
        "ns"              => Condition::NotSign,
        "o"               => Condition::Overflow,
        "no"              => Condition::NotOverflow,
        "p" | "pe"        => Condition::Parity,
        "np" | "po"       => Condition::NotParity,
        _ => {
            log::warn!("Unknown condition suffix '{}', defaulting to Equal", suffix);
            Condition::Equal
        }
    }
}


// ---------------------------------------------------------------------------
// Instruction lifting helpers
// ---------------------------------------------------------------------------

/// Check if the mnemonic is a conditional jump (jcc).
fn is_conditional_jump(mnemonic: &str) -> bool {
    mnemonic.starts_with('j') && mnemonic != "jmp"
}

/// Lift a binary ALU instruction (add, sub, and, or, xor, shl, shr, imul).
fn lift_binary_alu(
    mnemonic: &str,
    operands: &[String],
    addr: u64,
    versions: &mut HashMap<VarBase, u32>,
) -> Opcode {
    if operands.len() < 2 {
        return Opcode::Unknown {
            mnemonic: mnemonic.to_string(),
            addr,
        };
    }

    let rhs = parse_single_operand(&operands[operands.len() - 1], versions);

    // For three-operand imul: imul rax, rbx, 0x10
    let (dst_str, lhs_op) = if operands.len() >= 3 {
        (&operands[0], parse_single_operand(&operands[1], versions))
    } else {
        (&operands[0], parse_single_operand(&operands[0], versions))
    };

    let dst_base = dst_register(dst_str).unwrap_or(VarBase::RAX);
    let dst = new_version(versions, dst_base);

    match mnemonic {
        "add"           => Opcode::Add { dst, lhs: lhs_op, rhs },
        "sub"           => Opcode::Sub { dst, lhs: lhs_op, rhs },
        "imul" | "mul"  => Opcode::Mul { dst, lhs: lhs_op, rhs },
        "and"           => Opcode::And { dst, lhs: lhs_op, rhs },
        "or"            => Opcode::Or  { dst, lhs: lhs_op, rhs },
        "xor"           => Opcode::Xor { dst, lhs: lhs_op, rhs },
        "shl" | "sal"   => Opcode::Shl { dst, lhs: lhs_op, rhs },
        "shr" | "sar"   => Opcode::Shr { dst, lhs: lhs_op, rhs },
        _ => Opcode::Unknown { mnemonic: mnemonic.to_string(), addr },
    }
}

// ---------------------------------------------------------------------------
// Public lifter entry point
// ---------------------------------------------------------------------------

/// Lift an entire `ControlFlowGraph` into an `IRFunction`.
///
/// This walks each basic block, translates every disassembled instruction into
/// one or more IR opcodes, and converts the block's terminator into IR as well.
pub fn lift_function(cfg: &ControlFlowGraph) -> IRFunction {
    let mut ir_blocks: BTreeMap<BlockId, IRBlock> = BTreeMap::new();
    let mut block_addrs: BTreeMap<BlockId, u64> = BTreeMap::new();

    for (&block_id, basic_block) in &cfg.blocks {
        let mut ir_instructions: Vec<IRInstruction> = Vec::new();
        // Per-block SSA version map
        let mut versions: HashMap<VarBase, u32> = HashMap::new();

        block_addrs.insert(block_id, basic_block.start_addr);

        // ---------------------------------------------------------------
        // Lift each disassembled instruction
        // ---------------------------------------------------------------

        for insn in &basic_block.instructions {
            let mnemonic_raw = insn.mnemonic.to_lowercase();
            let mut mnemonic_str = mnemonic_raw.as_str();
            let is_lock = if mnemonic_str.starts_with("lock ") {
                mnemonic_str = mnemonic_str.trim_start_matches("lock ");
                true
            } else {
                false
            };
            let mnemonic = mnemonic_str.to_string();
            let operands = parse_operands(&insn.op_str);

            let opcode = match mnemonic_str {
                // --- NOP-like ---
                "nop" | "endbr64" | "endbr32" | "fnop" | "pause" => Opcode::Nop,

                // --- MOV family ---
                "mov" | "movabs" | "movzx" | "movsx" | "movsxd" | "movq" | "movd" => {
                    lift_mov(&operands, &mnemonic, insn.address, &mut versions)
                }

                // --- LEA ---
                "lea" => {
                    if operands.len() >= 2 {
                        let dst_base = dst_register(&operands[0]).unwrap_or(VarBase::RAX);
                        let dst = new_version(&mut versions, dst_base);
                        let addr_op = parse_memory_operand(&operands[1], &versions);
                        Opcode::Lea { dst, addr: addr_op }
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                // --- Binary ALU ---
                "add" | "sub" | "imul" | "and" | "or" | "xor"
                | "shl" | "sal" | "shr" | "sar" => {
                    lift_binary_alu(mnemonic_str, &operands, insn.address, &mut versions)
                }

                // --- Single-operand MUL (result in RDX:RAX) ---
                "mul" => {
                    if operands.len() == 1 {
                        let src = parse_single_operand(&operands[0], &versions);
                        let lhs = Operand::Var(current_var(&versions, VarBase::RAX));
                        let dst = new_version(&mut versions, VarBase::RAX);
                        Opcode::Mul { dst, lhs, rhs: src }
                    } else {
                        lift_binary_alu("imul", &operands, insn.address, &mut versions)
                    }
                }

                // --- NOT ---
                "not" => lift_unary_reg("not", &operands, insn.address, &mut versions),

                // --- NEG ---
                "neg" => lift_unary_reg("neg", &operands, insn.address, &mut versions),

                // --- CMP / TEST ---
                "cmp" => {
                    if operands.len() >= 2 {
                        let lhs = parse_single_operand(&operands[0], &versions);
                        let rhs = parse_single_operand(&operands[1], &versions);
                        Opcode::Cmp { lhs, rhs }
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                "test" => {
                    if operands.len() >= 2 {
                        let lhs = parse_single_operand(&operands[0], &versions);
                        let rhs = parse_single_operand(&operands[1], &versions);
                        Opcode::Test { lhs, rhs }
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                // --- PUSH / POP ---
                "push" => {
                    if !operands.is_empty() {
                        let src = parse_single_operand(&operands[0], &versions);
                        Opcode::Push { src }
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                "pop" => {
                    if !operands.is_empty() {
                        let base = dst_register(&operands[0]).unwrap_or(VarBase::RAX);
                        let dst = new_version(&mut versions, base);
                        Opcode::Pop { dst }
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                // --- CALL ---
                "call" => {
                    if !operands.is_empty() {
                        lift_call(&operands[0], &versions, insn.address + insn.size as u64)
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                // --- RET ---
                "ret" | "retn" | "retf" => Opcode::Ret,

                // --- JMP ---
                "jmp" => {
                    if !operands.is_empty() {
                        lift_jmp(&operands[0], &versions)
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                // --- Atomic RMW (lock prefix) ---
                m if is_lock => {
                    if operands.len() >= 2 {
                        let dst_op = parse_single_operand(&operands[0], &versions);
                        let src_op = parse_single_operand(&operands[1], &versions);
                        Opcode::AtomicRMW { op: m.to_string(), addr: dst_op, src: src_op }
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                // --- Conditional moves ---
                m if m.starts_with("cmov") => {
                    if operands.len() >= 2 {
                        let condition = parse_condition_suffix(&m[4..]);
                        let src = parse_single_operand(&operands[1], &versions);
                        let dst_base = dst_register(&operands[0]).unwrap_or(VarBase::RAX);
                        let dst = new_version(&mut versions, dst_base);
                        Opcode::Cmovcc { condition, dst, src }
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                // --- SetCC ---
                m if m.starts_with("set") => {
                    if operands.len() >= 1 {
                        let condition = parse_condition_suffix(&m[3..]);
                        let dst_base = dst_register(&operands[0]).unwrap_or(VarBase::RAX);
                        let dst = new_version(&mut versions, dst_base);
                        Opcode::Setcc { condition, dst }
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                // --- Conditional jumps ---
                m if is_conditional_jump(m) => {
                    let condition = parse_condition_suffix(m);
                    let target = if !operands.is_empty() {
                        parse_immediate(operands[0].trim())
                            .map(|v| v as u64)
                            .unwrap_or(0)
                    } else {
                        0
                    };
                    let fallthrough = insn.address + insn.size as u64;
                    Opcode::Jcc { condition, target, fallthrough }
                }

                // --- INC / DEC (sugar for add/sub 1) ---
                "inc" => {
                    if !operands.is_empty() {
                        let base = dst_register(&operands[0]).unwrap_or(VarBase::RAX);
                        let lhs = Operand::Var(current_var(&versions, base));
                        let dst = new_version(&mut versions, base);
                        Opcode::Add { dst, lhs, rhs: Operand::Imm(1) }
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                "dec" => {
                    if !operands.is_empty() {
                        let base = dst_register(&operands[0]).unwrap_or(VarBase::RAX);
                        let lhs = Operand::Var(current_var(&versions, base));
                        let dst = new_version(&mut versions, base);
                        Opcode::Sub { dst, lhs, rhs: Operand::Imm(1) }
                    } else {
                        Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                    }
                }

                // --- LEAVE = mov rsp, rbp ; pop rbp ---
                "leave" => {
                    let rbp_val = Operand::Var(current_var(&versions, VarBase::RBP));
                    let rsp_new = new_version(&mut versions, VarBase::RSP);
                    ir_instructions.push(IRInstruction {
                        addr: insn.address,
                        opcode: Opcode::Mov { dst: rsp_new, src: rbp_val },
                    });
                    let rbp_new = new_version(&mut versions, VarBase::RBP);
                    Opcode::Pop { dst: rbp_new }
                }

                // --- XCHG ---
                "xchg" => {
                    Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                }

                // --- Sign-extension ---
                "cdq" | "cdqe" | "cqo" | "cwd" | "cbw" | "cwde" => {
                    Opcode::Unknown { mnemonic: mnemonic.clone(), addr: insn.address }
                }

                // --- INT3 / UD2 / HLT / INT ---
                "int3" | "ud2" | "hlt" | "int" => Opcode::Ret,

                // --- SYSCALL ---
                "syscall" => Opcode::Call {
                    target: CallTarget::External("syscall".to_string()), fallthrough: insn.address + insn.size as u64,
                },

                // --- Default: unknown ---
                _ => {
                    log::warn!(
                        "Unknown instruction '{}' at 0x{:x}, emitting Unknown opcode",
                        mnemonic, insn.address
                    );
                    Opcode::Unknown {
                        mnemonic: mnemonic.clone(),
                        addr: insn.address,
                    }
                }
            };

            ir_instructions.push(IRInstruction {
                addr: insn.address,
                opcode,
            });
        }

        // Terminator handling is now done purely by the instruction lifter above.

        ir_blocks.insert(
            block_id,
            IRBlock {
                id: block_id,
                start_addr: basic_block.start_addr,
                instructions: ir_instructions,
            },
        );
    }

    log::info!(
        "Lifted function '{}' at 0x{:x}: {} blocks, {} total IR instructions",
        cfg.func_name,
        cfg.func_addr,
        ir_blocks.len(),
        ir_blocks.values().map(|b| b.instructions.len()).sum::<usize>()
    );

    IRFunction {
        name: cfg.func_name.clone(),
        addr: cfg.func_addr,
        blocks: ir_blocks,
        entry_block: cfg.entry_block,
        block_addrs,
    }
}

// ---------------------------------------------------------------------------
// Small lifting helpers (to keep the main match readable)
// ---------------------------------------------------------------------------

/// Lift a `mov` instruction. Decides between Mov / Load / Store based on
/// whether operands are memory references.
fn lift_mov(
    operands: &[String],
    mnemonic: &str,
    addr: u64,
    versions: &mut HashMap<VarBase, u32>,
) -> Opcode {
    if operands.len() < 2 {
        return Opcode::Unknown { mnemonic: mnemonic.to_string(), addr };
    }
    let dst_str = &operands[0];
    let src_str = &operands[1];
    let dst_is_mem = is_memory_operand(dst_str);
    let src_is_mem = is_memory_operand(src_str);

    if dst_is_mem && !src_is_mem {
        // Store
        let addr_op = parse_memory_operand(dst_str, versions);
        let src_op = parse_single_operand(src_str, versions);
        Opcode::Store { addr: addr_op, src: src_op }
    } else if !dst_is_mem && src_is_mem {
        // Load
        let dst_base = dst_register(dst_str).unwrap_or(VarBase::RAX);
        let dst = new_version(versions, dst_base);
        let addr_op = parse_memory_operand(src_str, versions);
        Opcode::Load { dst, addr: addr_op }
    } else {
        // Reg-to-reg (or imm-to-reg) mov
        let dst_base = dst_register(dst_str).unwrap_or(VarBase::RAX);
        let dst = new_version(versions, dst_base);
        let src_op = parse_single_operand(src_str, versions);
        Opcode::Mov { dst, src: src_op }
    }
}

/// Lift a unary register instruction (not / neg).
fn lift_unary_reg(
    kind: &str,
    operands: &[String],
    addr: u64,
    versions: &mut HashMap<VarBase, u32>,
) -> Opcode {
    if operands.is_empty() {
        return Opcode::Unknown { mnemonic: kind.to_string(), addr };
    }
    let op_str = &operands[0];
    if is_memory_operand(op_str) {
        return Opcode::Unknown { mnemonic: kind.to_string(), addr };
    }
    let base = dst_register(op_str).unwrap_or(VarBase::RAX);
    let src = Operand::Var(current_var(versions, base));
    let dst = new_version(versions, base);
    match kind {
        "not" => Opcode::Not { dst, src },
        "neg" => Opcode::Neg { dst, src },
        _     => Opcode::Unknown { mnemonic: kind.to_string(), addr },
    }
}

/// Lift a call instruction from a single operand string.
fn lift_call(target_str: &str, versions: &HashMap<VarBase, u32>, fallthrough: u64) -> Opcode {
    let target_str = target_str.trim();
    if is_memory_operand(target_str) {
        let op = parse_memory_operand(target_str, versions);
        Opcode::Call { target: CallTarget::Indirect(op), fallthrough }
    } else if let Some(vb) = parse_register(target_str) {
        let op = Operand::Var(current_var(versions, vb));
        Opcode::Call { target: CallTarget::Indirect(op), fallthrough: 0 }
    } else if let Some(addr) = parse_immediate(target_str) {
        Opcode::Call { target: CallTarget::Direct(addr as u64), fallthrough }
    } else {
        // Might be a symbol name
        Opcode::Call { target: CallTarget::External(target_str.to_string()), fallthrough }
    }
}

/// Lift a jmp instruction from a single operand string.
fn lift_jmp(target_str: &str, versions: &HashMap<VarBase, u32>) -> Opcode {
    let target_str = target_str.trim();
    if let Some(addr) = parse_immediate(target_str) {
        Opcode::Jmp { target: addr as u64 }
    } else if is_memory_operand(target_str) {
        // Indirect jump – model as indirect call for now
        let op = parse_memory_operand(target_str, versions);
        Opcode::Call { target: CallTarget::Indirect(op), fallthrough: 0 }
    } else if let Some(vb) = parse_register(target_str) {
        let op = Operand::Var(current_var(versions, vb));
        Opcode::Call { target: CallTarget::Indirect(op), fallthrough: 0 }
    } else {
        Opcode::Jmp { target: 0 }
    }
}
