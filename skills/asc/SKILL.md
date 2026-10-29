---
name: asc
description: Inspect a user-provided Android APK, AAB, bare DEX, HAP, or ABC with the asc command. Use to decompile one known class, list classes under a package prefix, decode AndroidManifest or a HAP module config, or find bytecode references to a string, type, method, or field. Do not use for whole-package export, package modification, signing, or installation unless the user explicitly asks to dump every class.
when-to-use: APK analysis, decompile one class, asc getclass, list classes, asc listclass, find references, asc findrefs, AndroidManifest, getmanifest, HAP module.json, ABC class
---

# ASC package analysis

Use `asc` as a focused, read-only query tool. It inflates a DEX or ABC member only
when a command needs it, and it decompiles a class only when that class was
named or a reference hit identified it.

## Route the request

- For a known Java class name or Dalvik descriptor, use `getclass`.
- For callers of a string, type, method, or field, use `findrefs` with the most
  specific kind: `string`, `type`, `method`, or `field`.
- For the package name, components, permissions, SDK levels, or application
  metadata, use `getmanifest`.
- To discover a class name without scanning references, use `listclass` with a
  narrow `--prefix`.
- If the user has a keyword but not a class name, run `findrefs` first, take
  the caller from the result line, then `getclass` that caller.
- Use `dump` only when the user explicitly asks to export every class. It
  writes a full tree and is not a substitute for a single query.
- If the user asks to modify, sign, install, or repackage the input, say that
  `asc` does not do that.

When composing or running a command, read [references/cli.md](references/cli.md)
for exact syntax and query semantics.

## Choose the decompiler deliberately

`--engine` applies to APK, AAB, and bare DEX `getclass` and `dump`. HAP and ABC
ignore it. A bare DEX or ABC does not resolve resource values unless the user
passes `--resources`. Do not invent a resource path.

For ABC and HAP, `--abc-output source` (default) reconstructs JavaScript through
the native Rust xpanda core. Choose `--abc-output asm` to inspect original Ark
instructions, jump labels, and exception tables. `dump` uses `.js` and `.pa`
respectively. Node is not required to run either mode.

- Keep `ddc` (the default) when readable Java with reconstructed control flow
  is enough.
- Use `smali` when the user wants baksmali, or when a `ddc` body looks wrong
  and the instruction stream is the evidence. Smali keeps opcodes and
  registers, and it does not rewrite resource references.
- Honor an explicitly requested engine. Do not silently switch, because the
  two outputs are not interchangeable.
- `listclass`, `findrefs`, and `getmanifest` never call the decompiler.

## Execute and report

Confirm the input path and the class or query from the conversation, then run
the narrowest command that answers it. Quote paths and query values. Write an
output file only when the user asks for one or the result has to be handed off.
`-o` writes that file and does not also print the payload on stdout. `dump`
is the exception: `-o` is the output directory, and the class count is printed
on stderr.

Treat decompiled Java as an analysis aid, not source that will build. Keep
tool output separate from conclusions drawn from it. Report the engine used
for `getclass` or `dump`, the caller lines or manifest facts that answer the
question, and any incomplete or failed decompilation. Use `--debug` only when
timings or per-entry diagnostics are needed; it writes to stderr.

Run `asc` from `PATH`. Do not build it from source, and do not invent an
executable path or an input path. If `asc` is not on `PATH`, stop and say so.
