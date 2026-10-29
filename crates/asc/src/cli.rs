use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use clap::{Args, CommandFactory, Parser, Subcommand};

use asc_abc::{
    class_names, find_members, find_strings, find_strings_resolved, find_types, is_abc, MemberKind,
};
use asc_abc_dec::{Decompiler as AbcDecompiler, OutputMode as AbcOutputMode};
use asc_apk::{
    dump_apk, find_refs, get_class_source, is_dex, list_classes, manifest_xml, packaged_resources,
    Engine, Error, MemberSel, Options, RefQuery, Result,
};
use asc_hap::{self, Query};

#[derive(Parser)]
#[command(
    name = "asc",
    version,
    about = "ASC tooling entry.",
    after_help = "\
examples:
  asc getclass app.apk 'Lcom/poc/Main;' -o Main.java
  asc getclass app.apk com.poc.Main --threads 16
  asc getclass app.apk com.poc.Main --engine smali
  asc listclass app.apk -o classes.txt
  asc listclass app.apk --prefix com.poc
  asc getmanifest app.apk -o AndroidManifest.xml
  asc dump app.apk -o output
  asc findrefs app.apk string token -o string_refs.txt
  asc findrefs app.apk type com.poc.Main
  asc findrefs app.apk method onCreate --class com.poc.Main
  asc findrefs app.apk method notify --class MainActivity --fuzzy-class -o method_refs.txt
  asc findrefs app.apk field apiKey -o field_refs.txt
  asc getclass app.hap com.poc.Main
  asc getclass app.hap com.poc.Main --abc-output asm
  asc listclass app.hap --prefix com.poc -o classes.txt
  asc getmanifest app.hap -o module.json
  asc dump app.hap -o output
  asc findrefs app.hap string token
  asc findrefs app.hap method onCreate --class com.poc.Main
  asc getclass classes.dex 'Lcom/example/Main;'
  asc getclass classes.dex 'Lcom/example/Main;' --resources resources.arsc
  asc getclass modules.abc 'Ldemo/App;'
  asc getclass modules.abc 'Ldemo/App;' --abc-output source
  asc dump modules.abc -o output --abc-output asm
  asc getclass modules.abc 'Ldemo/App;' --resources resources
  asc findrefs modules.abc string token --resources app.hap

HAP commands read ets/modules.abc and other .abc members. getmanifest prints
module.json, or config.json when that file is absent, plus pack.info.
--engine applies to APK and bare DEX getclass and dump only.
--abc-output selects source (default) or asm for ABC and HAP getclass/dump.
A bare DEX or ABC file does not resolve resources unless --resources is set.
DEX uses a resources.arsc file. ABC uses a resources directory or a HAP.
findrefs exits 2 when a DEX entry could not be searched; other hits are still printed.
Inflated DEX entries are cached under ~/.cache/asc unless --no-cache is set.

  asc diff old.apk new.apk
  asc diff --prefix assets/ old.apk new.apk
  asc diff old.apk new.apk -o diff-out
  asc skills install

asc skills install writes:
  ~/.grok/skills/asc
  ~/.agents/skills/asc
  ~/.claude/skills/asc
  ~/.cursor/skills/asc"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum EngineArg {
    /// Structured Java via ddc.
    Ddc,
    /// Baksmali text.
    Smali,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum AbcOutputArg {
    /// JavaScript reconstructed by the native Rust xpanda core.
    Source,
    /// Ark instruction mnemonics, operands, labels, and exception tables.
    Asm,
}

impl From<AbcOutputArg> for AbcOutputMode {
    fn from(arg: AbcOutputArg) -> Self {
        match arg {
            AbcOutputArg::Source => Self::Source,
            AbcOutputArg::Asm => Self::Assembly,
        }
    }
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
}

fn engine_of(arg: EngineArg) -> Engine {
    match arg {
        EngineArg::Ddc => Engine::Ddc,
        EngineArg::Smali => Engine::Smali,
    }
}

fn apk_options(
    threads: usize,
    debug: bool,
    engine: Engine,
    resources: Option<PathBuf>,
    cache: &CacheArgs,
) -> Options {
    Options {
        threads,
        debug,
        engine,
        resources,
        cache_dir: cache.dir(),
    }
}

#[derive(Args, Clone)]
struct CacheArgs {
    /// Do not read or write the inflated-DEX cache.
    #[arg(long, global = true)]
    no_cache: bool,
    /// Cache directory. The default is $ASC_CACHE_DIR, $XDG_CACHE_HOME/asc, or ~/.cache/asc.
    #[arg(long, global = true, value_name = "DIR")]
    cache_dir: Option<PathBuf>,
}

impl CacheArgs {
    fn dir(&self) -> Option<PathBuf> {
        if self.no_cache {
            None
        } else {
            self.cache_dir
                .clone()
                .or_else(asc_apk::DiskCache::default_dir)
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Decompile one class from an APK, DEX, HAP, or ABC.
    Getclass {
        /// Output for ABC/HAP records: reconstructed JavaScript or Ark assembly.
        #[arg(long, value_enum, default_value = "source")]
        abc_output: AbcOutputArg,
        #[arg(long)]
        debug: bool,
        #[arg(long, alias = "thread", default_value_t = default_threads())]
        threads: usize,
        /// `ddc` writes Java. `smali` writes baksmali text.
        #[arg(long, value_enum, default_value = "ddc")]
        engine: EngineArg,
        #[arg(short, long)]
        output: Option<PathBuf>,
        apk_path: PathBuf,
        dalvik_class: String,
        /// resources.arsc for a bare DEX, or a resources directory or HAP for a bare ABC.
        #[arg(long, value_name = "FILE")]
        resources: Option<PathBuf>,
        #[command(flatten)]
        cache: CacheArgs,
    },
    /// List classes in an APK, DEX, HAP, or ABC.
    Listclass {
        #[arg(long)]
        debug: bool,
        #[arg(long, alias = "thread", default_value_t = default_threads())]
        threads: usize,
        /// Package or class prefix, for example com.poc or Lcom/poc.
        #[arg(long)]
        prefix: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        apk_path: PathBuf,
        #[command(flatten)]
        cache: CacheArgs,
    },
    /// Print an APK manifest or a HAP module config.
    Getmanifest {
        #[arg(long)]
        debug: bool,
        #[arg(short, long)]
        output: Option<PathBuf>,
        apk_path: PathBuf,
    },
    /// Decompile every class in an APK, DEX, HAP, or ABC.
    Dump {
        /// Output for ABC/HAP records: .js source files or .pa assembly files.
        #[arg(long, value_enum, default_value = "source")]
        abc_output: AbcOutputArg,
        #[arg(long)]
        debug: bool,
        #[arg(long, alias = "thread", default_value_t = default_threads())]
        threads: usize,
        /// Decompiler for method bodies. Defaults to ddc.
        #[arg(long, value_enum, default_value = "ddc")]
        engine: EngineArg,
        #[arg(short, long)]
        output: PathBuf,
        apk_path: PathBuf,
        /// resources.arsc for a bare DEX, or a resources directory or HAP for a bare ABC.
        #[arg(long, value_name = "FILE")]
        resources: Option<PathBuf>,
        #[command(flatten)]
        cache: CacheArgs,
    },
    /// Find references in an APK, DEX, HAP, or ABC.
    Findrefs {
        #[arg(long, global = true)]
        debug: bool,
        #[arg(long, global = true, alias = "thread", default_value_t = default_threads())]
        threads: usize,
        /// resources.arsc for a bare DEX, or a resources directory or HAP for a bare ABC.
        #[arg(long, global = true, value_name = "FILE")]
        resources: Option<PathBuf>,
        #[command(flatten)]
        cache: CacheArgs,
        apk_path: PathBuf,
        #[command(subcommand)]
        query: FindCmd,
    },
    /// Compare two APK, HAP, or HSP archives by file path and CRC.
    /// Changed native libraries also compare ELF symbols and disassemble
    /// x86, x86_64, and AArch64 code. Short `r/` paths are restored from
    /// resources.arsc before entries are matched, and `res` XML is compared
    /// as decoded text. `-o` writes changed files under each versionCode.
    Diff {
        /// Only entries whose path starts with this prefix, such as assets/.
        #[arg(long)]
        prefix: Option<String>,
        /// Directory for changed files. XML is decoded text with restored names.
        #[arg(short, long, value_name = "DIR")]
        output: Option<PathBuf>,
        /// The earlier archive.
        left: PathBuf,
        /// The later archive.
        right: PathBuf,
    },
    /// Install the ASC skill.
    Skills {
        #[command(subcommand)]
        action: SkillsCmd,
    },
}

#[derive(Subcommand)]
enum SkillsCmd {
    /// Install the ASC skill for Grok, Codex, Claude, and Cursor.
    #[command(long_about = "\
Install the ASC skill for Grok, Codex, Claude, and Cursor.

Writes:
  ~/.grok/skills/asc
  ~/.agents/skills/asc
  ~/.claude/skills/asc
  ~/.cursor/skills/asc")]
    Install,
}

#[derive(Subcommand)]
enum FindCmd {
    /// Find references to a string. The value is a regular expression.
    String {
        #[arg(short, long)]
        output: Option<PathBuf>,
        value: String,
    },
    /// Find references to a type descriptor or name.
    Type {
        #[arg(short, long)]
        output: Option<PathBuf>,
        value: String,
    },
    /// Find references to methods.
    Method {
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Member name. It is an anchored regular expression unless `--class`
        /// names one exact class, which switches it to an exact string.
        name: Option<String>,
        /// Class to look in: a full descriptor or a dotted name. With
        /// `--fuzzy-class` it is a literal substring of the class name.
        #[arg(long = "class")]
        class_name: Option<String>,
        /// Match `--class` anywhere in the class name instead of exactly.
        #[arg(long = "fuzzy-class")]
        fuzzy_class: bool,
    },
    /// Find references to fields.
    Field {
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Member name. It is an anchored regular expression unless `--class`
        /// names one exact class, which switches it to an exact string.
        name: Option<String>,
        /// Class to look in: a full descriptor or a dotted name. With
        /// `--fuzzy-class` it is a literal substring of the class name.
        #[arg(long = "class")]
        class_name: Option<String>,
        /// Match `--class` anywhere in the class name instead of exactly.
        #[arg(long = "fuzzy-class")]
        fuzzy_class: bool,
    },
}

pub fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        let mut cmd = Cli::command();
        let _ = cmd.print_help();
        println!();
        return 0;
    }
    let cli = match Cli::try_parse_from(std::iter::once(String::from("asc")).chain(args)) {
        Ok(cli) => cli,
        Err(err) => {
            let code = err.exit_code();
            let _ = err.print();
            return code;
        }
    };
    match execute(cli) {
        Ok(Exit::Done) => 0,
        Ok(Exit::Partial) => 2,
        Err(err) => {
            eprintln!("Error: {err}");
            1
        }
    }
}

enum Exit {
    Done,
    Partial,
}

fn execute(cli: Cli) -> Result<Exit> {
    match cli.command {
        Commands::Getclass {
            abc_output,
            debug,
            threads,
            engine,
            output,
            apk_path,
            dalvik_class,
            resources,
            cache,
        } => {
            let source = if let Some(data) = read_abc(&apk_path)? {
                let mode = AbcOutputMode::from(abc_output);
                let text = AbcDecompiler::new(&data)
                    .map_err(Error::external)?
                    .render_class(&dalvik_class, mode)
                    .map_err(Error::external)?;
                let table = abc_resources(resources.as_deref())?;
                if mode == AbcOutputMode::Assembly {
                    text
                } else {
                    table.annotate(&text).into_owned()
                }
            } else if hap_file(&apk_path)? {
                archive_resources(resources.as_deref())?;
                asc_hap::get_class_output(
                    &apk_path,
                    &dalvik_class,
                    &hap_options(threads, debug),
                    abc_output.into(),
                )
                .map_err(hap_err)?
            } else {
                get_class_source(
                    &apk_path,
                    &dalvik_class,
                    &apk_options(threads, debug, engine_of(engine), resources, &cache),
                )?
            };
            emit(&source, output.as_deref(), true)?;
        }
        Commands::Listclass {
            debug,
            threads,
            prefix,
            output,
            apk_path,
            cache,
        } => {
            let names = if let Some(data) = read_abc(&apk_path)? {
                class_names(&data, prefix.as_deref()).map_err(abc_err)?
            } else if hap_file(&apk_path)? {
                asc_hap::list_classes(&apk_path, prefix.as_deref(), &hap_options(threads, debug))
                    .map_err(hap_err)?
            } else {
                list_classes(
                    &apk_path,
                    prefix.as_deref(),
                    &apk_options(threads, debug, Engine::Ddc, None, &cache),
                )?
            };
            let text = if names.is_empty() {
                String::new()
            } else {
                format!("{}\n", names.join("\n"))
            };
            if let Some(path) = output {
                fs::write(path, text)?;
            } else {
                write_stdout(&text)?;
            }
        }
        Commands::Getmanifest {
            debug,
            output,
            apk_path,
        } => {
            if read_abc(&apk_path)?.is_some() {
                return Err(Error::new("ABC files have no AndroidManifest.xml"));
            }
            if is_dex(&apk_path)? {
                return Err(Error::new("DEX files have no manifest"));
            }
            if hap_file(&apk_path)? {
                let text = asc_hap::module_json(&apk_path).map_err(hap_err)?;
                emit(&text, output.as_deref(), true)?;
                return Ok(Exit::Done);
            }
            let started = std::time::Instant::now();
            let xml = manifest_xml(&apk_path)?;
            emit(&xml, output.as_deref(), true)?;
            if debug {
                eprintln!(
                    "[DEBUG] Total Execution Time: {:.2} us",
                    started.elapsed().as_secs_f64() * 1_000_000.0
                );
            }
        }
        Commands::Dump {
            abc_output,
            debug,
            threads,
            engine,
            output,
            apk_path,
            resources,
            cache,
        } => {
            if let Some(data) = read_abc(&apk_path)? {
                let table = abc_resources(resources.as_deref())?;
                let stats = asc_hap::dump_abc_with_mode(&data, &output, &table, abc_output.into())
                    .map_err(hap_err)?;
                eprintln!(
                    "dumped {} classes ({} errors) -> {}",
                    stats.classes,
                    stats.errors,
                    output.display()
                );
                return Ok(Exit::Done);
            }
            if hap_file(&apk_path)? {
                archive_resources(resources.as_deref())?;
                let stats = asc_hap::dump_hap_with_mode(
                    &apk_path,
                    &output,
                    &hap_options(threads, debug),
                    abc_output.into(),
                )
                .map_err(hap_err)?;
                eprintln!(
                    "dumped {} classes ({} errors) -> {}",
                    stats.classes,
                    stats.errors,
                    output.display()
                );
                return Ok(Exit::Done);
            }
            let started = std::time::Instant::now();
            let stats = dump_apk(
                &apk_path,
                &output,
                &apk_options(threads, debug, engine_of(engine), resources, &cache),
            )?;
            eprintln!(
                "dumped {} classes ({} errors) -> {}",
                stats.classes,
                stats.errors,
                output.display()
            );
            if debug {
                eprintln!(
                    "[DEBUG] Total Execution Time: {:.2} us",
                    started.elapsed().as_secs_f64() * 1_000_000.0
                );
            }
        }
        Commands::Findrefs {
            debug,
            threads,
            resources,
            cache,
            apk_path,
            query,
        } => {
            let (query, output) = match query {
                FindCmd::String { output, value } => (RefQuery::String(value), output),
                FindCmd::Type { output, value } => (RefQuery::Type(value), output),
                FindCmd::Method {
                    output,
                    name,
                    class_name,
                    fuzzy_class,
                } => (
                    RefQuery::Method(MemberSel {
                        class_name,
                        fuzzy_class,
                        name,
                    }),
                    output,
                ),
                FindCmd::Field {
                    output,
                    name,
                    class_name,
                    fuzzy_class,
                } => (
                    RefQuery::Field(MemberSel {
                        class_name,
                        fuzzy_class,
                        name,
                    }),
                    output,
                ),
            };
            let lines = if let Some(data) = read_abc(&apk_path)? {
                reject_fuzzy(&query)?;
                let table = abc_resources(resources.as_deref())?;
                abc_refs(&data, &apk_path, &query, &table)?
            } else if hap_file(&apk_path)? {
                reject_fuzzy(&query)?;
                archive_resources(resources.as_deref())?;
                asc_hap::find_refs(&apk_path, hap_query(&query), &hap_options(threads, debug))
                    .map_err(hap_err)?
            } else {
                let report = find_refs(
                    &apk_path,
                    &query,
                    &apk_options(threads, debug, Engine::Ddc, resources, &cache),
                )?;
                let text = if report.lines.is_empty() {
                    String::new()
                } else {
                    format!("{}\n", report.lines.join("\n"))
                };
                emit(&text, output.as_deref(), false)?;
                return Ok(if report.partial {
                    Exit::Partial
                } else {
                    Exit::Done
                });
            };
            let text = if lines.is_empty() {
                String::new()
            } else {
                format!("{}\n", lines.join("\n"))
            };
            emit(&text, output.as_deref(), false)?;
        }
        Commands::Diff {
            prefix,
            output,
            left,
            right,
        } => {
            let left_archive = asc_diff::Archive::open(&left).map_err(Error::external)?;
            let right_archive = asc_diff::Archive::open(&right).map_err(Error::external)?;
            let report = match prefix.as_deref() {
                Some(prefix) => {
                    asc_diff::ArchiveDiff::between_prefix(&left_archive, &right_archive, prefix)
                }
                None => asc_diff::ArchiveDiff::between(&left_archive, &right_archive),
            };
            print!("{report}");
            if let Some(dir) = output {
                report
                    .export(&left_archive, &right_archive, &dir)
                    .map_err(Error::external)?;
            }
        }
        Commands::Skills { action } => match action {
            SkillsCmd::Install => install_user_skills()?,
        },
    }
    Ok(Exit::Done)
}

fn install_user_skills() -> Result<()> {
    let home = skill_home()?;
    for skills_dir in crate::skills::user_skill_dirs(&home) {
        for installed in crate::skills::install_skills(&skills_dir)? {
            println!("installed {}", installed.display());
        }
    }
    Ok(())
}

fn skill_home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| Error::new("HOME is not set"))
}

fn read_abc(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut file = File::open(path).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    let mut magic = [0u8; 8];
    let read = file.read(&mut magic).map_err(|source| Error::IoPath {
        action: "open",
        path: path.display().to_string(),
        source,
    })?;
    if read < 8 || !is_abc(&magic) {
        return Ok(None);
    }
    let mut data = Vec::from(magic);
    file.read_to_end(&mut data)
        .map_err(|source| Error::IoPath {
            action: "open",
            path: path.display().to_string(),
            source,
        })?;
    Ok(Some(data))
}

fn abc_err(err: asc_abc::Error) -> Error {
    Error::external(err)
}

fn hap_err(err: asc_hap::Error) -> Error {
    Error::external(err)
}

fn hap_file(path: &Path) -> Result<bool> {
    asc_hap::is_hap(path).map_err(hap_err)
}

fn archive_resources(resources: Option<&Path>) -> Result<()> {
    packaged_resources(resources)
}

fn reject_fuzzy(query: &RefQuery) -> Result<()> {
    let fuzzy = match query {
        RefQuery::Method(sel) | RefQuery::Field(sel) => sel.fuzzy_class,
        RefQuery::String(_) | RefQuery::Type(_) => false,
    };
    if fuzzy {
        Err(Error::new("--fuzzy-class is not used for HAP or ABC"))
    } else {
        Ok(())
    }
}

fn abc_resources(path: Option<&Path>) -> Result<asc_hap::HapResources> {
    match path {
        None => Ok(asc_hap::HapResources::default()),
        Some(path) => asc_hap::load_resources(path).map_err(hap_err),
    }
}

fn hap_options(threads: usize, debug: bool) -> asc_hap::Options {
    asc_hap::Options { threads, debug }
}

fn hap_query(query: &RefQuery) -> Query<'_> {
    match query {
        RefQuery::String(pattern) => Query::String(pattern),
        RefQuery::Type(pattern) => Query::Type(pattern),
        RefQuery::Method(sel) => Query::Method {
            name: sel.name.as_deref(),
            class_name: sel.class_name.as_deref(),
        },
        RefQuery::Field(sel) => Query::Field {
            name: sel.name.as_deref(),
            class_name: sel.class_name.as_deref(),
        },
    }
}

fn abc_refs(
    data: &[u8],
    path: &Path,
    query: &RefQuery,
    resources: &asc_hap::HapResources,
) -> Result<Vec<String>> {
    let file = path.display().to_string();
    match query {
        RefQuery::String(pattern) if resources.is_empty() => {
            find_strings(data, &file, pattern).map_err(abc_err)
        }
        RefQuery::String(pattern) => {
            find_strings_resolved(data, &file, pattern, &|raw| resources.resolve_literal(raw))
                .map_err(abc_err)
        }
        RefQuery::Type(pattern) => find_types(data, &file, pattern).map_err(abc_err),
        RefQuery::Method(sel) => abc_members(data, &file, MemberKind::Method, sel),
        RefQuery::Field(sel) => abc_members(data, &file, MemberKind::Field, sel),
    }
}

fn abc_members(data: &[u8], file: &str, kind: MemberKind, sel: &MemberSel) -> Result<Vec<String>> {
    let pattern = sel.name.as_deref().unwrap_or(".*");
    find_members(data, file, kind, pattern, sel.class_name.as_deref()).map_err(abc_err)
}

fn emit(text: &str, output: Option<&std::path::Path>, ensure_newline: bool) -> Result<()> {
    let mut owned;
    let text = if ensure_newline && !text.is_empty() && !text.ends_with('\n') {
        owned = String::with_capacity(text.len() + 1);
        owned.push_str(text);
        owned.push('\n');
        owned.as_str()
    } else {
        text
    };
    // The file is written before the stream, so a closed pipe cannot swallow
    // `-o`, and `-o` silences the stream instead of duplicating it.
    if let Some(path) = output {
        fs::write(path, text)?;
    } else {
        write_stdout(text)?;
    }
    Ok(())
}

fn write_stdout(text: &str) -> Result<()> {
    match std::io::stdout().write_all(text.as_bytes()) {
        // The reader walked away: `asc ... | head` is a normal way to stop.
        Err(err) if err.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(err) => Err(err.into()),
        Ok(()) => Ok(()),
    }
}
