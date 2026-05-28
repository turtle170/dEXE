//! C99 Code Generator
//!
//! Translates the SSA IR produced by `ir.rs` into a complete, compilable C99
//! source file.  The output models x86 semantics via a register-per-variable
//! approach with a simulated stack.

use std::collections::BTreeSet;
use std::fmt::Write as FmtWrite;

use crate::frontend::SymbolTable;
use crate::ir::*;

// ---------------------------------------------------------------------------
// Known libc function signatures
// ---------------------------------------------------------------------------

/// Subset of common libc / POSIX functions whose prototypes we can emit
/// instead of opaque `uint64_t stub_0x…(void);` stubs.
const KNOWN_LIBC: &[(&str, &str)] = &[
    ("printf",   "int printf(const char *fmt, ...)"),
    ("puts",     "int puts(const char *s)"),
    ("malloc",   "void *malloc(size_t size)"),
    ("free",     "void free(void *ptr)"),
    ("exit",     "void exit(int status)"),
    ("memcpy",   "void *memcpy(void *dst, const void *src, size_t n)"),
    ("memset",   "void *memset(void *s, int c, size_t n)"),
    ("strlen",   "size_t strlen(const char *s)"),
    ("strcmp",    "int strcmp(const char *s1, const char *s2)"),
    ("fprintf",  "int fprintf(void *stream, const char *fmt, ...)"),
    ("fopen",    "void *fopen(const char *path, const char *mode)"),
    ("fclose",   "int fclose(void *stream)"),
    ("read",     "long read(int fd, void *buf, unsigned long count)"),
    ("write",    "long write(int fd, const void *buf, unsigned long count)"),
    ("open",     "int open(const char *path, int flags, ...)"),
    ("close",    "int close(int fd)"),
    ("mmap",     "void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off)"),
    ("munmap",   "int munmap(void *addr, unsigned long len)"),
    ("brk",      "int brk(void *addr)"),
    ("syscall",  "long syscall(long number, ...)"),
    ("calloc",   "void *calloc(size_t nmemb, size_t size)"),
    ("realloc",  "void *realloc(void *ptr, size_t size)"),
    ("atoi",     "int atoi(const char *s)"),
    ("atol",     "long atol(const char *s)"),
    ("getenv",   "char *getenv(const char *name)"),
    ("abort",    "void abort(void)"),
    ("perror",   "void perror(const char *s)"),
    ("snprintf", "int snprintf(char *str, size_t size, const char *fmt, ...)"),
    ("sprintf",  "int sprintf(char *str, const char *fmt, ...)"),
    ("strncmp",  "int strncmp(const char *s1, const char *s2, size_t n)"),
    ("strcpy",   "char *strcpy(char *dst, const char *src)"),
    ("strncpy",  "char *strncpy(char *dst, const char *src, size_t n)"),
    ("strcat",   "char *strcat(char *dst, const char *src)"),
    ("strncat",  "char *strncat(char *dst, const char *src, size_t n)"),
];

// ---------------------------------------------------------------------------
// Top-level emitter
// ---------------------------------------------------------------------------

/// Emit a complete C99 source file for the given IR functions.
pub fn emit_c(functions: &[IRFunction], symbols: &SymbolTable) -> String {
    let mut out = String::with_capacity(64 * 1024);

    // ── File header ──────────────────────────────────────────────────────
    out.push_str("/* Decompiled by dEXE */\n");
    out.push_str("#include <stdint.h>\n");
    out.push_str("#include <string.h>\n");
    out.push_str("#include <stdlib.h>\n");
    out.push_str("#include <stddef.h>\n");
    out.push_str("#include <stdatomic.h>\n");
    out.push('\n');
    out.push_str("typedef struct {\n");
    out.push_str("    uint64_t rax, rbx, rcx, rdx;\n");
    out.push_str("    uint64_t rsi, rdi, rsp, rbp;\n");
    out.push_str("    uint64_t r8, r9, r10, r11;\n");
    out.push_str("    uint64_t r12, r13, r14, r15;\n");
    out.push_str("    uint64_t rflags;\n");
    out.push_str("} CPU_State;\n");
    out.push_str("CPU_State cpu = {0};\n");
    out.push_str("uint8_t process_memory[16 * 1024 * 1024]; // 16MB\n");
    out.push_str("void init_state(void) {\n");
    out.push_str("    cpu.rsp = (uintptr_t)&process_memory[sizeof(process_memory) - 8];\n");
    out.push_str("}\n");
    out.push('\n');

    // Build a set of addresses we are emitting as functions, for call resolution
    let emitted_addrs: BTreeSet<u64> = functions.iter().map(|f| f.addr).collect();

    // Build a name lookup (addr → name) that merges symbols and function names
    let func_name_map: std::collections::BTreeMap<u64, String> = functions
        .iter()
        .map(|f| (f.addr, sanitise_c_ident(&f.name)))
        .collect();

    // ── External stubs / declarations ────────────────────────────────────
    // Collect all direct call targets that are NOT in our emitted set
    let mut extern_targets: BTreeSet<u64> = BTreeSet::new();
    let mut extern_names: BTreeSet<String> = BTreeSet::new();

    for func in functions {
        for block in func.blocks.values() {
            for instr in &block.instructions {
                match &instr.opcode {
                    Opcode::Call { target: CallTarget::Direct(addr), .. } => {
                        if !emitted_addrs.contains(addr) {
                            extern_targets.insert(*addr);
                        }
                    }
                    Opcode::Call { target: CallTarget::External(name), .. } => {
                        extern_names.insert(name.clone());
                    }
                    _ => {}
                }
            }
        }
    }

    // Emit known libc externs
    let mut declared_names: BTreeSet<String> = BTreeSet::new();
    let libc_map: std::collections::HashMap<&str, &str> =
        KNOWN_LIBC.iter().copied().collect();

    for name in &extern_names {
        if let Some(proto) = libc_map.get(name.as_str()) {
            writeln!(out, "extern {};", proto).unwrap();
            declared_names.insert(name.clone());
        }
    }

    // Emit stubs for unknown extern names
    for name in &extern_names {
        if !declared_names.contains(name) {
            writeln!(out, "extern uint64_t {}(void);", sanitise_c_ident(name)).unwrap();
        }
    }

    // Emit stubs for unknown direct call addresses
    for &addr in &extern_targets {
        if let Some(sym_name) = symbols.get(&addr) {
            if let Some(proto) = libc_map.get(sym_name.as_str()) {
                if !declared_names.contains(sym_name) {
                    writeln!(out, "extern {};", proto).unwrap();
                    declared_names.insert(sym_name.clone());
                }
            } else if !declared_names.contains(sym_name) {
                writeln!(
                    out,
                    "extern uint64_t {}(void);",
                    sanitise_c_ident(sym_name)
                )
                .unwrap();
                declared_names.insert(sym_name.clone());
            }
        } else {
            writeln!(out, "extern uint64_t stub_0x{:x}(void);", addr).unwrap();
        }
    }

    if !extern_targets.is_empty() || !extern_names.is_empty() {
        out.push('\n');
    }

    // ── Forward declarations ─────────────────────────────────────────────
    out.push_str("/* Forward declarations */\n");
    for func in functions {
        let name = sanitise_c_ident(&func.name);
        writeln!(out, "uint64_t {}(void);", name).unwrap();
    }
    out.push('\n');

    // ── Function bodies ──────────────────────────────────────────────────
    for func in functions {
        emit_function(&mut out, func, symbols, &func_name_map, &emitted_addrs);
        out.push('\n');
    }

    log::info!("Generated {} bytes of C source", out.len());
    out
}

// ---------------------------------------------------------------------------
// Per-function emitter
// ---------------------------------------------------------------------------

fn emit_function(
    out: &mut String,
    func: &IRFunction,
    symbols: &SymbolTable,
    func_names: &std::collections::BTreeMap<u64, String>,
    emitted_addrs: &BTreeSet<u64>,
) {
    let fname = sanitise_c_ident(&func.name);

    writeln!(out, "uint64_t {}(void) {{", fname).unwrap();
    out.push_str("    uint64_t tmp = 0; (void)tmp;\n");



    // ── Blocks — emitted in address order ────────────────────────────────
    // Collect blocks and sort by start_addr
    let mut sorted_blocks: Vec<&IRBlock> = func.blocks.values().collect();
    sorted_blocks.sort_by_key(|b| b.start_addr);

    for block in &sorted_blocks {
        writeln!(out, "BLOCK_0x{:x}:", block.start_addr).unwrap();
        out.push_str("    {\n");

        for instr in &block.instructions {
            let line = emit_instruction(instr, symbols, func_names, emitted_addrs);
            if !line.is_empty() {
                writeln!(out, "        {}", line).unwrap();
            }
        }

        out.push_str("    }\n");
    }

    // ── Default return ───────────────────────────────────────────────────
    out.push_str("    return cpu.rax;\n");
    out.push_str("}\n");
}

// ---------------------------------------------------------------------------
// Instruction emitter
// ---------------------------------------------------------------------------

fn emit_instruction(
    instr: &IRInstruction,
    symbols: &SymbolTable,
    func_names: &std::collections::BTreeMap<u64, String>,
    emitted_addrs: &BTreeSet<u64>,
) -> String {
    match &instr.opcode {
        Opcode::Mov { dst, src } => {
            format!("{} = {};", var_name(dst), emit_operand(src))
        }
        Opcode::Load { dst, addr } => {
            format!(
                "{} = *(uint64_t*)({});",
                var_name(dst),
                emit_mem_addr(addr)
            )
        }
        Opcode::Store { addr, src } => {
            format!(
                "*(uint64_t*)({}) = {};",
                emit_mem_addr(addr),
                emit_operand(src)
            )
        }
        Opcode::Add { dst, lhs, rhs } => {
            format!("{} = {} + {};", var_name(dst), emit_operand(lhs), emit_operand(rhs))
        }
        Opcode::Sub { dst, lhs, rhs } => {
            format!("{} = {} - {};", var_name(dst), emit_operand(lhs), emit_operand(rhs))
        }
        Opcode::Mul { dst, lhs, rhs } => {
            format!("{} = {} * {};", var_name(dst), emit_operand(lhs), emit_operand(rhs))
        }
        Opcode::And { dst, lhs, rhs } => {
            format!("{} = {} & {};", var_name(dst), emit_operand(lhs), emit_operand(rhs))
        }
        Opcode::Or { dst, lhs, rhs } => {
            format!("{} = {} | {};", var_name(dst), emit_operand(lhs), emit_operand(rhs))
        }
        Opcode::Xor { dst, lhs, rhs } => {
            format!("{} = {} ^ {};", var_name(dst), emit_operand(lhs), emit_operand(rhs))
        }
        Opcode::Shl { dst, lhs, rhs } => {
            format!("{} = {} << {};", var_name(dst), emit_operand(lhs), emit_operand(rhs))
        }
        Opcode::Shr { dst, lhs, rhs } => {
            format!("{} = {} >> {};", var_name(dst), emit_operand(lhs), emit_operand(rhs))
        }
        Opcode::Not { dst, src } => {
            format!("{} = ~{};", var_name(dst), emit_operand(src))
        }
        Opcode::Neg { dst, src } => {
            format!(
                "{} = (uint64_t)(-(int64_t){});",
                var_name(dst),
                emit_operand(src)
            )
        }
        Opcode::Lea { dst, addr } => {
            format!(
                "{} = (uint64_t)({});",
                var_name(dst),
                emit_mem_addr(addr)
            )
        }
        Opcode::Cmp { lhs, rhs } => {
            let l = emit_operand(lhs);
            let r = emit_operand(rhs);
            format!(
                "cpu.rflags = ((uint64_t)({l}) == (uint64_t)({r})) | \
                 (((uint64_t)({l}) < (uint64_t)({r})) << 1) | \
                 (((int64_t)({l}) < (int64_t)({r})) << 2);"
            )
        }
        Opcode::Test { lhs, rhs } => {
            let l = emit_operand(lhs);
            let r = emit_operand(rhs);
            format!("cpu.rflags = (({l} & {r}) == 0) ? 1 : 0;")
        }
        Opcode::Jmp { target } => {
            format!("goto BLOCK_0x{:x};", target)
        }
        Opcode::Jcc { condition, target, fallthrough: _ } => {
            let cond_expr = get_cond_expr(condition);
            format!("if {} goto BLOCK_0x{:x};", cond_expr, target)
        }

        Opcode::Cmovcc { condition, dst, src } => {
            let cond_expr = get_cond_expr(condition);
            format!("{} = ({}) ? {} : {};", var_name(dst), cond_expr, emit_operand(src), var_name(dst))
        }
        Opcode::Setcc { condition, dst } => {
            let cond_expr = get_cond_expr(condition);
            format!("{} = ({}) ? 1 : 0;", var_name(dst), cond_expr)
        }
        Opcode::AtomicRMW { op, addr, src } => {
            let op_c = match op.as_str() {
                "add" => "__sync_fetch_and_add",
                "sub" => "__sync_fetch_and_sub",
                "and" => "__sync_fetch_and_and",
                "or"  => "__sync_fetch_and_or",
                "xor" => "__sync_fetch_and_xor",
                _     => "/* unknown lock */",
            };
            format!("{}((uint64_t*)({}), {});", op_c, emit_mem_addr(addr), emit_operand(src))
        }
        Opcode::Call { target, fallthrough } => {
            let mut s = String::new();
            s.push_str(&format!("cpu.rsp -= 8; *(uint64_t*)(uintptr_t)(cpu.rsp) = 0x{:x}; ", fallthrough));
            match target {
                CallTarget::Direct(addr) => {
                    let name = resolve_call_name(*addr, symbols, func_names, emitted_addrs);
                    s.push_str(&format!("cpu.rax = {}();", name));
                }
                CallTarget::External(name) => {
                    s.push_str(&format!("cpu.rax = {}(cpu.rdi, cpu.rsi, cpu.rdx, cpu.rcx, cpu.r8, cpu.r9);", sanitise_c_ident(name)));
                }
                CallTarget::Indirect(op) => {
                    s.push_str(&format!("cpu.rax = ((uint64_t(*)(void))({}))();", emit_operand(op)));
                }
            }
            s
        }

        Opcode::Ret => {
            "return cpu.rax;".to_string()
        }
        Opcode::Push { src } => {
            format!(
                "cpu.rsp -= 8; *(uint64_t*)(uintptr_t)(cpu.rsp) = {};",
                emit_operand(src)
            )
        }
        Opcode::Pop { dst } => {
            format!(
                "{} = *(uint64_t*)(uintptr_t)(cpu.rsp); cpu.rsp += 8;",
                var_name(dst)
            )
        }
        Opcode::Nop => {
            "/* nop */".to_string()
        }
        Opcode::Unknown { mnemonic, addr } => {
            format!("/* UNKNOWN: {} at 0x{:x} */", mnemonic, addr)
        }
    }
}

// ---------------------------------------------------------------------------
// Operand rendering helpers
// ---------------------------------------------------------------------------

/// Convert a VarId to the C variable name (ignoring SSA version).
fn var_name(v: &VarId) -> &'static str {
    match v.base {
        VarBase::RAX    => "cpu.rax",
        VarBase::RBX    => "cpu.rbx",
        VarBase::RCX    => "cpu.rcx",
        VarBase::RDX    => "cpu.rdx",
        VarBase::RSI    => "cpu.rsi",
        VarBase::RDI    => "cpu.rdi",
        VarBase::RSP    => "cpu.rsp",
        VarBase::RBP    => "cpu.rbp",
        VarBase::R8     => "cpu.r8",
        VarBase::R9     => "cpu.r9",
        VarBase::R10    => "cpu.r10",
        VarBase::R11    => "cpu.r11",
        VarBase::R12    => "cpu.r12",
        VarBase::R13    => "cpu.r13",
        VarBase::R14    => "cpu.r14",
        VarBase::R15    => "cpu.r15",
        VarBase::RFlags => "cpu.rflags",
        VarBase::Temp(_)=> "tmp",
    }
}

/// Render an Operand as a C expression (value, not address).
fn emit_operand(op: &Operand) -> String {
    match op {
        Operand::Var(v) => var_name(v).to_string(),
        Operand::Imm(n) => {
            if *n >= 0 {
                format!("0x{:x}ULL", *n as u64)
            } else {
                format!("(-0x{:x}LL)", n.unsigned_abs())
            }
        }
        Operand::Mem { base, index, scale, disp } => {
            // For a bare operand reference this dereferences the memory
            let addr = build_mem_addr_expr(base, index, *scale, *disp);
            format!("*(uint64_t*)({})", addr)
        }
    }
}

/// Compute a memory address expression (no dereference) for a Mem operand.
/// For non-Mem operands, just cast to `(uintptr_t)`.
fn emit_mem_addr(op: &Operand) -> String {
    match op {
        Operand::Mem { base, index, scale, disp } => {
            build_mem_addr_expr(base, index, *scale, *disp)
        }
        _ => {
            format!("(uintptr_t)({})", emit_operand(op))
        }
    }
}

/// Build the address computation string for `base + index*scale + disp`.
fn build_mem_addr_expr(
    base: &Option<VarId>,
    index: &Option<VarId>,
    scale: u8,
    disp: i64,
) -> String {
    let mut parts: Vec<String> = Vec::new();

    if let Some(b) = base {
        parts.push(format!("(uintptr_t){}", var_name(b)));
    }

    if let Some(idx) = index {
        if scale > 1 {
            parts.push(format!("(uintptr_t){} * {}", var_name(idx), scale));
        } else {
            parts.push(format!("(uintptr_t){}", var_name(idx)));
        }
    }

    if disp > 0 {
        parts.push(format!("0x{:x}", disp));
    } else if disp < 0 {
        // Emit as subtraction: we'll handle the sign in the join
        // Actually, push a negative literal and join with '+'
        parts.push(format!("(-0x{:x}LL)", disp.unsigned_abs()));
    }

    if parts.is_empty() {
        "0".to_string()
    } else {
        parts.join(" + ")
    }
}

// ---------------------------------------------------------------------------
// Name resolution helpers
// ---------------------------------------------------------------------------

/// Resolve a direct-call address to a C function name.
fn resolve_call_name(
    addr: u64,
    symbols: &SymbolTable,
    func_names: &std::collections::BTreeMap<u64, String>,
    _emitted_addrs: &BTreeSet<u64>,
) -> String {
    // 1. Is it one of the functions we're emitting?
    if let Some(name) = func_names.get(&addr) {
        return name.clone();
    }
    // 2. Is it in the symbol table?
    if let Some(name) = symbols.get(&addr) {
        return sanitise_c_ident(name);
    }
    // 3. Fallback to stub
    format!("stub_0x{:x}", addr)
}

/// Sanitise a symbol name so it is a valid C identifier.
/// Replaces characters that are not [A-Za-z0-9_] with underscores.
/// Prepends '_' if the result starts with a digit.
fn sanitise_c_ident(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    for (i, ch) in name.chars().enumerate() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            result.push(ch);
        } else if ch == '.' || ch == '@' || ch == '$' {
            result.push('_');
        } else {
            result.push('_');
        }
        let _ = i; // suppress unused warning
    }
    if result.is_empty() {
        return "_anon".to_string();
    }
    if result.chars().next().unwrap().is_ascii_digit() {
        result.insert(0, '_');
    }
    result
}

fn get_cond_expr(condition: &Condition) -> String {
    match condition {
        Condition::Equal        => "(cpu.rflags & 1)".to_string(),
        Condition::NotEqual     => "(!(cpu.rflags & 1))".to_string(),
        Condition::Less         => "(cpu.rflags & 4)".to_string(),
        Condition::GreaterEqual => "(!(cpu.rflags & 4))".to_string(),
        Condition::Below        => "(cpu.rflags & 2)".to_string(),
        Condition::AboveEqual   => "(!(cpu.rflags & 2))".to_string(),
        Condition::Greater      => "(!(cpu.rflags & 1) && !(cpu.rflags & 4))".to_string(),
        Condition::LessEqual    => "((cpu.rflags & 1) || (cpu.rflags & 4))".to_string(),
        Condition::Above        => "(!(cpu.rflags & 1) && !(cpu.rflags & 2))".to_string(),
        Condition::BelowEqual   => "((cpu.rflags & 1) || (cpu.rflags & 2))".to_string(),
        Condition::Sign         => "(cpu.rflags)".to_string(),
        Condition::NotSign      => "(!cpu.rflags)".to_string(),
        Condition::Overflow     => "(cpu.rflags)".to_string(),
        Condition::NotOverflow  => "(!cpu.rflags)".to_string(),
        Condition::Parity       => "(cpu.rflags)".to_string(),
        Condition::NotParity    => "(!cpu.rflags)".to_string(),
    }
}
