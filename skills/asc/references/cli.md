# asc CLI reference

## Run asc

The command is `asc` on `PATH`. Quote every path or value that contains spaces
or shell metacharacters. Do not build `asc` from source, and do not substitute
another executable path. If `asc` is not on `PATH`, stop and say so.

Put `getclass`, `listclass`, `getmanifest`, and `dump` options before the input
path. For `findrefs`, put `--debug` and `--threads` before the input path;
`-o` belongs to the query and comes after `string`, `type`, `method`, or
`field`.

`<input>` is an APK, an Android App Bundle, a HAP, a bare `.dex` file, or a
bare `.abc` file whose first eight bytes are `PANDA\0\0\0`. `dump` accepts all
of those. `getmanifest` does not: a bare DEX or ABC has no manifest.

## Decompile one class

```text
asc getclass [--debug] [--threads N] [--engine ddc|smali] [--abc-output source|asm] [--resources FILE] [-o FILE] <input> CLASS
```

`CLASS` accepts `com.example.Main` or `Lcom/example/Main;`.

- `ddc` is the default for APK and AAB. It prints Java reconstructed by ddc.
  Resource ids, `R$type;->name` fields, and `@string/` tokens in that Java are
  replaced from the package resource table.
- `smali` prints baksmali for APK and AAB and leaves resource tokens as they
  are in the DEX.
- `--engine` applies to APK, AAB, and bare DEX. HAP and ABC use
  `--abc-output source` (default) for native Rust JavaScript reconstruction, or
  `--abc-output asm` for Ark instructions, labels, and exception tables.
- A bare DEX or ABC keeps resource tokens unless `--resources` is set. For a
  DEX that file is `resources.arsc`. For an ABC it is a `resources` directory
  or a HAP that contains one. APK, AAB, and HAP already carry their own
  resources, and `--resources` is rejected for them.
- `-o` writes the class text and does not also print it. Without `-o`, the
  text goes to stdout.
- `--threads` defaults to 8. `--thread` is the same flag. `0` is an error.
- The first class definition in load order wins when several DEX files define
  the same name: `classes.dex`, `classes2.dex`, `classes10.dex`, then other
  root DEX entries. In a bundle, `base` comes before other modules.

Examples:

```text
asc getclass app.apk 'Lcom/example/Main;'
asc getclass app.apk com.example.Main --threads 16
asc getclass --engine smali -o Main.smali app.apk com.example.Main
asc getclass app.hap com.example.Main
asc getclass classes.dex 'Lcom/example/Main;'
asc getclass classes.dex 'Lcom/example/Main;' --resources resources.arsc
asc getclass modules.abc 'Ldemo/App;' --resources resources
```

## Find bytecode references

```text
asc findrefs [--debug] [--threads N] [--resources FILE] <input> string [-o FILE] VALUE
asc findrefs [--debug] [--threads N] [--resources FILE] <input> type [-o FILE] VALUE
asc findrefs [--debug] [--threads N] [--resources FILE] <input> method [NAME] [--class CLASS] [--fuzzy-class] [-o FILE]
asc findrefs [--debug] [--threads N] [--resources FILE] <input> field [NAME] [--class CLASS] [--fuzzy-class] [-o FILE]
```

There is no batched string subcommand and no `--format` flag. Run one query
per command. Text on stdout is the whole result. An empty stdout with exit
code 0 means there were no hits.

Semantics for APK and AAB:

- `string` and `type` are regular expressions over each string, not anchored
  literals. `.` matches any byte, including `/` and newlines, so it can match
  inside a constant. Escape a literal dot as `\.`.
- `type` searches type-descriptor strings such as `Lcom/example/Main;`. Dotted
  Java names are not rewritten to slashes. Prefer a descriptor or a slash
  form, for example `Lcom/example/Main;` or `com/example/Main`.
- A `string` hit also counts when the resolved resource text matches, even if
  the raw constant did not. The printed match is the resolved text.
- Without `--class`, a method or field `NAME` is an anchored regular
  expression of the whole simple name. `NAME` is required in that form.
- With `--class` and without `--fuzzy-class`, the class is one exact type
  (`com.example.Main` or `Lcom/example/Main;`) and `NAME` is a literal simple
  name, not a regular expression. `NAME` may be omitted to list every member
  of that class that is referenced.
- `--fuzzy-class` matches `--class` as a literal substring. Dots become
  slashes only when the class text contains no slash. `$` is literal, so an
  inner class does not need escaping. `NAME`, when present, stays an anchored
  regular expression.
- A method or field query needs a name, `--class`, or both.
- Each APK result line has the shape
  `<dex> | <caller> | matched=(<target>; <target>)`.
  One line is one caller. Several targets for that caller sit inside
  `matched`, separated by `; `.

HAP and ABC use the same commands. `--fuzzy-class` is rejected there:
`--class` selects one class, and a member name stays an anchored regular
expression. String and type values are still regular expressions. Hits can
also come from resolved resource text when the input is a HAP, or a bare ABC
opened with `--resources`. A bare DEX resolves `@string/` and the other
resource tokens only when `--resources` names a `resources.arsc` file. Read
each printed line as one hit; do not assume the APK column layout for an
`.abc` result.

`--debug` writes counts and timings to stderr and leaves results on stdout.

Examples:

```text
asc findrefs app.apk string token -o string_refs.txt
asc findrefs app.apk type 'Lcom/example/Main;'
asc findrefs app.apk method onCreate --class com.example.Main
asc findrefs app.apk method notify --class MainActivity --fuzzy-class
asc findrefs app.apk field apiKey
```

## Decode the manifest

```text
asc getmanifest [--debug] [-o FILE] <input>
```

- APK and AAB: decoded manifest XML. `@string/`, `@mipmap/`, and `@0x7f......`
  references are replaced from `resources.arsc` or `res/`.
- HAP: `module.json`, or `config.json` when that module file is absent, plus
  `pack.info` when it is present. `$string:`, `$media:`, and `$profile:` are
  replaced from `resources/`.
- Bare DEX and bare ABC: the command fails. Those files have no manifest.

`-o` writes the text and does not also print it.

Examples:

```text
asc getmanifest app.apk -o AndroidManifest.xml
asc getmanifest app.hap
```

## List classes

```text
asc listclass [--debug] [--threads N] [--prefix PREFIX] [-o FILE] <input>
```

Prints Dalvik descriptors, one per line, in DEX entry and `class_def` order.
There is no DEX name column. `--prefix com.example` is normalized to
`Lcom/example`. `com/example` and `Lcom/example` are the same prefix. On ABC
and HAP, `.` and `/` are both package separators, so `com.example`,
`Lcom.example`, `com/example`, and `Lcom/example` all match.

Examples:

```text
asc listclass app.apk --prefix com.example -o classes.txt
asc listclass app.apk
```

## Export every class

```text
asc dump [--debug] [--threads N] [--engine ddc|smali] [--abc-output source|asm] [--resources FILE] -o DIR <input>
```

Use this only when the user explicitly wants the whole package. `-o` is
required and is a directory. APK and AAB output is a Java or smali tree plus
`AndroidManifest.xml`. HAP and bare ABC output a `.js` record tree by default,
or `.pa` assembly files with `--abc-output asm`. A bare DEX writes the class
tree without a manifest. HAP also exports its module/config metadata.
`--resources` follows the same rule as `getclass`.
The stderr summary is `dumped <classes> classes (<errors> errors) -> <dir>`.
Report both numbers. A per-class failure is counted in `errors` and does not
discard the rest of the tree.

## Failures and follow-up

- Exit code 0 with an empty `listclass` or `findrefs` payload means no match.
  Do not rerun the same query with a broader pattern unless the original
  pattern was wrong.
- `Class <descriptor> not found in APK.` means that descriptor is not defined
  in the package. Check the name with `listclass --prefix` before changing
  the query.
- A `ddc` body can still have the wrong types, names, or control flow. Prefer
  exact constants, calls, fields, and the `findrefs` caller line. Switch to
  `--engine smali` only when those details are not visible in the Java.
- Do not install JADX or any other decompiler because `ddc` was unsatisfying.
  `smali` is the built-in alternative.
