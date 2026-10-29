# asc-abc-dec

Native Rust disassembly and JavaScript reconstruction for Ark `.abc` records.
The necessary xpanda-core pipeline is adapted from asmjmp0/xpanda revision
`3ffb7b476b17066dc8bed0914caeea1f529b1e51`, under Apache-2.0.

```rust
use asc_abc_dec::{Decompiler, OutputMode};

let bytes = std::fs::read("modules.abc")?;
let decompiler = Decompiler::new(&bytes)?;
let javascript = decompiler.render_class("Ldemo/App;", OutputMode::Source)?;
let assembly = decompiler.render_class("Ldemo/App;", OutputMode::Assembly)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The crate reads methods and their regional reference tables on demand. Its
checked-in instruction table contains all 332 definitions from xpanda's Ark
24.0.0.0 ISA, including packed registers, signed jumps, and prefixed instructions.
Source reconstruction covers ordinary and async functions, lexical closures,
classes, literal buffers, module imports/exports, property access, calls, loops,
branches, exception routing, and generator next/throw/return modes. Only reachable
function/class definitions are emitted from the module entry point.

Reducible graphs become `if`, `while`, and `try`/`catch` statements. A native Oxc
AST pipeline folds register copies, recovers lexical captures and function
expressions, promotes classes and their fields/accessors, reconstructs object
literals and method calls, and restores compiler-generated `finally` regions.
It recovers conditional expressions and short-circuit chains, simplifies negated
equality tests, and groups literal key mappings into `switch` statements.
It preserves getter/argument evaluation order and registers needed by loops or
exception handlers. Complex graphs use an explicit dispatcher; generators keep
their suspended frame in an iterator closure. Unsupported semantics return a typed error instead
of silently dropping instructions, while their assembly remains available.
Individual encoded strings are limited to 4 MiB. Metadata buffers, lowered
methods, literal expansion, and generated definitions have 64 MiB size budgets;
methods are limited to 65,536 registers and 4,096 basic blocks.

The optimizer uses Rust AST passes rather than xpanda's Babel implementation.
This port does not include UI, MCP, ZIP readers, resource
readers, or the TypeScript runtime. ASC supplies containers and resources through
`asc-hap`. The existing `asc-abc` metadata/query API remains available.

`cargo test -p asc-abc-dec` verifies the upstream class, MD5, and AES samples and
the real Ark 24 AppLog/GamePage records, every opcode definition, exception
boundaries, modules, async suspension, and generators. The two real records
recover class syntax without factory wrappers or dispatchers. Node, when
installed, is used only as an optional execution oracle, including mocked
HarmonyOS APIs for device failures, file cleanup, and UI constructor captures.
Branch regressions cover key mappings, scaling, logging, and failing window callbacks.
See `tests/fixtures/README.md` and the workspace `NOTICE` for attribution.
