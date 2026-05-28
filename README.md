# dEXE

An agentic x86_64 ELF/PE binary decompiler that converts machine instructions into functional C99 code.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Crates.io](https://img.shields.io/crates/v/dexe.svg)](https://crates.io/crates/dexe)

`dEXE` accepts x86_64 ELF and PE binaries, disassembles them, lifts the assembly to an SSA-inspired intermediate representation, reconstructs control flow basic blocks, and outputs valid, compilable C99 source code.

## Key Features

- **Format Agnostic:** Supports both Linux ELF and Windows PE (portable executable) formats for x86_64 architectures using the `object` crate.
- **Robust Disassembly:** Equipped with Capstone for accurate instruction parsing.
- **Basic Block & CFG Extraction:** Rebuilds functions and their control flow graphs by analyzing jumps, calls, and returns.
- **SSA IR Lifter:** Maps assembly instructions into an intermediate representation (IR) format while versioning registers to mimic Single Static Assignment.
- **C99 Output Generator:** Translates IR logic into compilable C code preserving control flow structure using standard `goto` topologies and local register variables.

## Project Architecture

`dEXE` is constructed with modular separation of concerns:

- `frontend`: Parses the target binary, locates the `.text` section, and disassembles instructions.
- `cfg`: Identifies Basic Blocks and constructs the Control Flow Graph.
- `ir`: Parses operand variants, maps instructions to IR Opcodes, and manages register versions.
- `backend`: Formats registers and stack access, then emits C99 structure with helper definitions.

## Installation

### From Crates.io
```bash
cargo install dexe
```

### From Source
```bash
git clone https://github.com/turtle170/dEXE.git
cd dEXE
cargo build --release
```

## Usage

```bash
# Decompile a binary and output the C source
dexe -i <PATH_TO_BINARY> -o <PATH_TO_OUTPUT_C>

# Output with detailed logging
RUST_LOG=info dexe -i test.exe -o test.c
```

### Command Line Interface Options

```
Options:
  -i, --input <INPUT>    Path to the input binary (x86_64 ELF or PE)
  -o, --output <OUTPUT>  Path to write the decompiled C99 source file
  -h, --help             Print help
  -V, --version          Print version
```

## Testing and Verification

`dEXE` has been verified against a variety of test fixtures including optimized Rust binaries containing complex features such as recursive Ackerman computations, bitwise chaotic LCGs, and Collatz conjecturing nested loops. A generated C output includes standard stack simulation:

```c
BLOCK_0x140001120:
    {
        rsp = rsp - 0x48ULL;
        *(uint64_t*)((uintptr_t)rsp + 0x38) = rcx;
        rflags = ((uint64_t)(rcx) == (uint64_t)(0x1ULL)) | ...
        if ((rflags & 1) || (rflags & 2)) goto BLOCK_0x140001148;
    }
```

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
