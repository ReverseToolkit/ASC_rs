use std::io::Write;
use std::process::{Command, Stdio};

use asc_abc_dec::{decode, Decompiler, OutputMode};

const CLASS: &[u8] = include_bytes!("fixtures/class.abc");
const MD5: &[u8] = include_bytes!("fixtures/md5.abc");
const AES: &[u8] = include_bytes!("fixtures/aes.abc");
const HX360E: &[u8] = include_bytes!("fixtures/hx360e.abc");

fn execute(source: &str) -> Option<String> {
    let mut child = match Command::new("node")
        .args(["-e", "const fs=require('fs'),vm=require('vm');const logs=[];const result=vm.runInNewContext(fs.readFileSync(0,'utf8'),{console:{log:(...xs)=>logs.push(xs.join(' '))}},{timeout:2000});Promise.resolve(result).then(()=>console.log(logs.join('\\n')),error=>{console.error(error);process.exitCode=1})"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()
    {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(err) => panic!("cannot start Node test oracle: {err}"),
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Some(String::from_utf8(result.stdout).unwrap())
}

#[test]
fn class_sample_restores_classes_methods_and_observable_behavior() {
    let source = Decompiler::new(CLASS)
        .unwrap()
        .render_class("L_GLOBAL;", OutputMode::Source)
        .unwrap();
    assert!(source.contains("class Test"), "{source}");
    assert!(source.contains("c = 10;"), "{source}");
    assert!(source.contains("console.log(\"123\")"), "{source}");
    assert!(!source.contains("__fn_"), "{source}");
    assert!(!source.contains("Object.defineProperty"), "{source}");
    if let Some(output) = execute(&source) {
        assert_eq!(output.trim(), "123");
    }
}

#[test]
fn md5_sample_preserves_closures_calls_and_loops() {
    let mut source = Decompiler::new(MD5)
        .unwrap()
        .render_class("L_GLOBAL;", OutputMode::Source)
        .unwrap();
    source.push_str("console.log(md5('')); console.log(md5('abc'));\n");
    if let Some(output) = execute(&source) {
        assert!(
            output.contains("21232f297a57a5a743894a0e4a801fc3"),
            "{output}"
        );
        assert!(
            output.contains("d41d8cd98f00b204e9800998ecf8427e"),
            "{output}"
        );
        assert!(
            output.contains("900150983cd24fb0d6963f7d28e17f72"),
            "{output}"
        );
    }
}

#[test]
fn aes_sample_preserves_numeric_literal_buffers() {
    let source = Decompiler::new(AES)
        .unwrap()
        .render_class("L_GLOBAL;", OutputMode::Source)
        .unwrap();
    assert!(
        source
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>()
            .contains("99,124,119,123"),
        "{source}"
    );
    execute(&source);
}

fn mock_module(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.starts_with("import ") && !line.starts_with("export {"))
        .map(|line| line.strip_prefix("export ").unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn real_v24_applog_restores_readable_classes_and_exception_boundaries() {
    let source = Decompiler::new(HX360E)
        .unwrap()
        .render_class("L&entry/src/main/ets/common/AppLog&;", OutputMode::Source)
        .unwrap();
    assert!(source.contains("export class AppLog"), "{source}");
    assert!(source.contains("static started = false"), "{source}");
    assert!(source.contains("finally"), "{source}");
    assert!(
        source.contains("hilog.info(local_0_0, local_0_1"),
        "{source}"
    );
    for scaffold in [
        "__fn_",
        "__class_",
        "__pc",
        "__hole",
        "Object.defineProperty",
    ] {
        assert!(!source.contains(scaffold), "{scaffold}\n{source}");
    }
    let setup = r#"
        let stage = 0, failWrite = false, fileSize = 0;
        const messages = [], operations = [];
        const deviceInfo = {};
        for (const [index, name, value] of [[1, 'sdkApiVersion', 24], [2, 'productModel', 'M'], [3, 'osFullName', 'OS'], [4, 'displayVersion', 'D']]) {
            Object.defineProperty(deviceInfo, name, {get() { if (stage === index) throw Error('device'); return value; }});
        }
        const hilog = {info(...args) { messages.push(args[4]); }};
        const fs = {
            OpenMode: {READ_WRITE: 1, CREATE: 2, APPEND: 4},
            accessSync() { return true; }, statSync() { return {size: fileSize}; },
            openSync(path, flags) { operations.push(['open', path, flags]); return {fd: 7}; },
            writeSync(fd, text) { operations.push(['write', fd, text]); if (failWrite) throw Error('write'); },
            closeSync(file) { operations.push(['close', file.fd]); },
            copyFileSync(from, to) { operations.push(['copy', from, to]); },
            truncateSync(file, size) { operations.push(['truncate', file, size]); }
        };
    "#;
    let actions = r#"
        const append = AppLog.append, rotate = AppLog.rotateIfNeeded;
        AppLog.append = () => {};
        AppLog.rotateIfNeeded = () => {};
        for (stage = 0; stage <= 4; stage++) { AppLog.started = false; AppLog.init('/data'); }
        console.log(messages.join('\n'));
        AppLog.append = append; AppLog.rotateIfNeeded = rotate;
        AppLog.now = () => 'time'; AppLog.file = 'log'; AppLog.prevFile = 'prev';
        AppLog.append('I', 'app', 'message'); console.log(JSON.stringify(operations));
        operations.length = 0; failWrite = true;
        AppLog.append('I', 'app', 'message'); console.log(JSON.stringify(operations));
        operations.length = 0; fileSize = 3 * 1024 * 1024;
        AppLog.rotateIfNeeded(); console.log(JSON.stringify(operations));
        operations.length = 0; fileSize = 1;
        AppLog.rotateIfNeeded(); console.log(JSON.stringify(operations));
    "#;
    if let Some(output) = execute(&format!("{setup}\n{}\n{actions}", mock_module(&source))) {
        assert_eq!(
            output.trim(),
            concat!(
                "=== HX360E start === api=24 model=M os=OS display=D\n",
                "=== HX360E start === api=0 model=? os=? display=?\n",
                "=== HX360E start === api=24 model=? os=? display=?\n",
                "=== HX360E start === api=24 model=M os=? display=?\n",
                "=== HX360E start === api=24 model=M os=OS display=?\n",
                "[[\"open\",\"log\",7],[\"write\",7,\"time I app: message\\n\"],[\"close\",7]]\n",
                "[[\"open\",\"log\",7],[\"write\",7,\"time I app: message\\n\"],[\"close\",7]]\n",
                "[[\"copy\",\"log\",\"prev\"],[\"truncate\",\"log\",0]]\n",
                "[]"
            ),
            "{source}"
        );
    }
}

#[test]
fn real_v24_gamepage_restores_super_accessors_and_captured_this() {
    let source = Decompiler::new(HX360E)
        .unwrap()
        .render_class("L&entry/src/main/ets/pages/GamePage&;", OutputMode::Source)
        .unwrap();
    assert!(source.contains("class GamePage extends ViewPU"), "{source}");
    assert!(source.contains("super(p0, p2, p3, p5)"), "{source}");
    assert!(source.contains("get promptKind()"), "{source}");
    assert!(source.contains("set promptKind(p0)"), "{source}");
    for scaffold in [
        "__fn_",
        "__class_",
        "__pc",
        "__this",
        "__hole",
        "Object.defineProperty",
    ] {
        assert!(!source.contains(scaffold), "{scaffold}\n{source}");
    }
    let setup = r#"
        const AppLog = {}, Orientation = {}, PadButton = {}, SettingsStore = {}, VirtualDpad = {}, VirtualStick = {}, XPadKey = {};
        const display = {}, fs = {}, gamePerformance = {}, gamePlayer = {}, inputDevice = {}, router = {}, testNapi = {}, window = {};
        const events = []; let superArgs, route;
        const hilog = {info() { events.push('log'); }};
        class ViewPU { constructor(...args) { superArgs = args; } finalizeConstruction() {} }
        class ObservedPropertySimplePU { constructor(value) { this.value = value; } get() { return this.value; } set(value) { this.value = value; } }
        const ObservedPropertyObjectPU = ObservedPropertySimplePU;
        class XComponentController {}
        function registerNamedRoute(factory) { route = factory; }
    "#;
    let actions = r#"
        const page = route();
        const initial = page.promptKind;
        page.promptKind = 'keyboard';
        page.rearmPhysicalPad = type => events.push(type);
        page.deviceWatcher.call({}, {type: 'connect', deviceId: 1});
        console.log(JSON.stringify([superArgs, initial, page.promptKind, page.showPad, events]));
    "#;
    if let Some(output) = execute(&format!("{setup}\n{}\n{actions}", mock_module(&source))) {
        assert_eq!(
            output.trim(),
            r#"[[null,null,-1,null],"","keyboard",true,["log","connect"]]"#,
            "{source}"
        );
    }
}

#[test]
fn real_v24_gamepage_branch_recovery_preserves_keys_scaling_and_failure_callbacks() {
    let source = Decompiler::new(HX360E)
        .unwrap()
        .render_class("L&entry/src/main/ets/pages/GamePage&;", OutputMode::Source)
        .unwrap();
    assert!(source.contains("switch (p0)"), "{source}");
    assert!(source.contains("p0 ? \"on\" : \"off\""), "{source}");
    assert!(source.contains("p0 === XPadKey.LThumbLeft ||"), "{source}");
    let setup = r#"
        class ViewPU {}
        function registerNamedRoute() {}
        function getContext() { return {}; }
        const events = [];
        const hilog = {
            info(...args) { events.push(['info', args[3], this === hilog]); },
            error(...args) { events.push(['error', args[3], this === hilog]); }
        };
        const XPadKey = {A: 1, Back: 2, LTrigger: 3, RTrigger: 4,
            LThumbLeft: 5, LThumbDown: 6, RThumbLeft: 7, RThumbDown: 8,
            LThumbRight: 9, LThumbUp: 10, RThumbRight: 11, RThumbUp: 12};
        const system = {
            setWindowSystemBarEnable(bars) {
                events.push(['bars', bars]);
                return {catch(cb) { cb({message: 'bars failure'}); }};
            },
            setSpecificSystemBarEnabled(name, enabled) {
                events.push(['indicator', name, enabled]);
                return {catch() {}};
            }
        };
        const window = {getLastWindow() { return {then(cb) { cb(system); return {catch() {}}; }}; }};
    "#;
    let actions = r#"
        const methods = GamePage.prototype;
        console.log(JSON.stringify([2301,2311,2313,0,'2301',NaN].map(key => methods.physicalPadKey(key))));
        console.log(JSON.stringify([3,4,5,6,7,8,9,10,11,12,99].map(key => methods.keyValue(key))));
        const overlay = {refreshDebugText() { events.push(['refresh']); }};
        methods.toggleDebugOverlay.call(overlay, true);
        methods.toggleDebugOverlay.call(overlay, false);
        console.log(JSON.stringify(events)); events.length = 0;
        const stretch = {letterbox: false}, fit = {letterbox: true};
        methods.updateFitScale.call(stretch, 1920, 720);
        methods.updateFitScale.call(fit, 1920, 720);
        methods.updateFitScale.call(fit, 0, 720);
        console.log(JSON.stringify([stretch.scaleX,stretch.scaleY,fit.scaleX,fit.scaleY]));
        methods.setImmersive.call({}, true);
        methods.setImmersive.call({}, false);
        console.log(JSON.stringify(events));
    "#;
    if let Some(output) = execute(&format!("{setup}\n{}\n{actions}", mock_module(&source))) {
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines[0], "[1,2,2,-1,-1,-1]", "{source}");
        assert_eq!(
            lines[1], "[255,255,-32767,-32767,-32767,-32767,32767,32767,32767,32767,0]",
            "{source}"
        );
        assert_eq!(
            lines[2], r#"[["refresh"],["info","on",true],["info","off",true]]"#,
            "{source}"
        );
        assert_eq!(lines[3], "[1.5,1,1,1]", "{source}");
        assert_eq!(
            lines[4],
            r#"[["bars",[]],["error","bars failure",true],["indicator","navigationIndicator",false],["bars",["status","navigation"]],["error","bars failure",true],["indicator","navigationIndicator",true]]"#,
            "{source}"
        );
    }
}

#[test]
fn assembly_resolves_ids_and_retains_instruction_locations() {
    let assembly = Decompiler::new(CLASS)
        .unwrap()
        .render_class("L_GLOBAL;", OutputMode::Assembly)
        .unwrap();
    assert!(assembly.contains("defineclasswithbuffer"), "{assembly}");
    assert!(assembly.contains("label_0000:"), "{assembly}");
    assert!(assembly.contains("\"123\""), "{assembly}");
}

#[test]
fn truncated_and_unknown_instructions_are_rejected() {
    for code in [&[0xfd][..], &[0x62, 1], &[0xfa]] {
        assert!(decode(code).is_err());
    }
}

#[test]
fn class_output_is_independent_of_query_order() {
    let decompiler = Decompiler::new(MD5).unwrap();
    let first = decompiler
        .render_class("L_GLOBAL;", OutputMode::Source)
        .unwrap();
    decompiler
        .render_class("L_ESTypeInfoRecord;", OutputMode::Assembly)
        .unwrap();
    assert_eq!(
        first,
        decompiler
            .render_class("L_GLOBAL;", OutputMode::Source)
            .unwrap()
    );
}

#[test]
fn every_upstream_opcode_decodes_with_its_declared_operand_width() {
    let table = include_str!("../resources/opcodes.tsv");
    let mut seen = std::collections::BTreeSet::new();
    for row in table.lines().filter(|row| !row.starts_with('#')) {
        let columns: Vec<_> = row.split('\t').collect();
        let opcode: u16 = columns[0].parse().unwrap();
        assert!(seen.insert(opcode), "duplicate opcode {opcode}");
        let format = columns[2].strip_prefix("PREF_").unwrap_or(columns[2]);
        let bits: usize = format
            .split('_')
            .filter(|part| *part != "NONE")
            .map(|part| {
                part.trim_start_matches(['I', 'M', 'D', 'V'])
                    .parse::<usize>()
                    .unwrap()
            })
            .sum();
        assert_eq!(bits % 8, 0);
        let mut code = vec![u8::try_from(opcode & 255).unwrap()];
        if opcode >= 251 {
            code.push(u8::try_from(opcode >> 8).unwrap());
        }
        code.resize(code.len() + bits / 8, 0);
        let instructions = decode(&code).unwrap();
        assert_eq!(instructions.len(), 1, "{}", columns[1]);
        assert_eq!(instructions[0].opcode.name, columns[1]);
        assert_eq!(
            usize::try_from(instructions[0].next_pc).unwrap(),
            code.len()
        );
    }
    assert_eq!(seen.len(), 332);
}

fn uleb(mut value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    while value >= 128 {
        bytes.push(u8::try_from(value & 127).unwrap() | 128);
        value >>= 7;
    }
    bytes.push(u8::try_from(value).unwrap());
    bytes
}

fn panda_string(value: &str) -> Vec<u8> {
    let mut bytes = uleb(u32::try_from(value.len()).unwrap() * 2 + 1);
    bytes.extend_from_slice(value.as_bytes());
    bytes.push(0);
    bytes
}

fn instruction(name: &str, format: &str, operands: &[u8]) -> Vec<u8> {
    let row = include_str!("../resources/opcodes.tsv")
        .lines()
        .find(|row| {
            let columns: Vec<_> = row.split('\t').collect();
            columns.len() == 4 && columns[1] == name && columns[2] == format
        })
        .unwrap();
    let code: u16 = row.split('\t').next().unwrap().parse().unwrap();
    let mut bytes = vec![u8::try_from(code & 255).unwrap()];
    if code >= 251 {
        bytes.push(u8::try_from(code >> 8).unwrap());
    }
    bytes.extend_from_slice(operands);
    bytes
}

fn method_fixture(code: &[u8], tries: &[u32]) -> (Vec<u8>, u32) {
    let mut bytes = vec![0; 60];
    bytes[..8].copy_from_slice(b"PANDA\0\0\0");
    bytes[12..16].copy_from_slice(&[24, 0, 0, 0]);
    let name = u32::try_from(bytes.len()).unwrap();
    bytes.extend(panda_string("test_entry"));
    let code_off = u32::try_from(bytes.len()).unwrap();
    bytes.extend([0, 3]);
    bytes.extend(uleb(u32::try_from(code.len()).unwrap()));
    bytes.extend(uleb(if tries.is_empty() { 0 } else { 1 }));
    bytes.extend_from_slice(code);
    for value in tries {
        bytes.extend(uleb(*value));
    }
    let class_off = u32::try_from(bytes.len()).unwrap();
    bytes.extend(panda_string("Ltest/Module;"));
    bytes.extend([0; 4]);
    bytes.extend([1, 0, 1, 0]);
    let method_off = u32::try_from(bytes.len()).unwrap();
    bytes.extend([0, 0, 255, 255]);
    bytes.extend(name.to_le_bytes());
    bytes.extend([8, 1]);
    bytes.extend(code_off.to_le_bytes());
    bytes.push(0);
    let index = u32::try_from(bytes.len()).unwrap();
    bytes.extend(class_off.to_le_bytes());
    let length = u32::try_from(bytes.len()).unwrap();
    bytes[16..20].copy_from_slice(&length.to_le_bytes());
    bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&index.to_le_bytes());
    (bytes, method_off)
}

fn string_reference_fixture(code: &[u8], text: &str) -> Vec<u8> {
    let (mut bytes, _) = method_fixture(code, &[]);
    let string = u32::try_from(bytes.len()).unwrap();
    bytes.extend(panda_string(text));
    let table = u32::try_from(bytes.len()).unwrap();
    bytes.extend(string.to_le_bytes());
    let region = u32::try_from(bytes.len()).unwrap();
    for value in [0, u32::MAX, 0, u32::MAX, 1, table, 0, u32::MAX, 0, u32::MAX] {
        bytes.extend(value.to_le_bytes());
    }
    let length = u32::try_from(bytes.len()).unwrap();
    bytes[16..20].copy_from_slice(&length.to_le_bytes());
    bytes[52..56].copy_from_slice(&1u32.to_le_bytes());
    bytes[56..60].copy_from_slice(&region.to_le_bytes());
    bytes
}

#[test]
fn repeated_string_references_cannot_expand_without_a_size_limit() {
    let mut code = instruction("lda.str", "ID16", &[0, 0]).repeat(70);
    code.extend(instruction("returnundefined", "NONE", &[]));
    let bytes = string_reference_fixture(&code, &"x".repeat(1024 * 1024));
    let error = Decompiler::new(&bytes)
        .unwrap()
        .render_class("Ltest/Module;", OutputMode::Source)
        .unwrap_err();
    assert!(
        error.to_string().contains("lowered method exceeds 64 MiB"),
        "{error}"
    );

    let bytes = string_reference_fixture(&code, &"x".repeat(4 * 1024 * 1024 + 1));
    let error = Decompiler::new(&bytes)
        .unwrap()
        .render_class("Ltest/Module;", OutputMode::Source)
        .unwrap_err();
    assert!(
        error.to_string().contains("MUTF-8 string exceeds 4 MiB"),
        "{error}"
    );
}

#[test]
fn exception_dispatch_tracks_throw_instructions_at_try_boundaries() {
    let mut code = instruction("ldai", "IMM32", &4i32.to_le_bytes());
    let try_start = u32::try_from(code.len()).unwrap();
    code.extend(instruction("throw", "PREF_NONE", &[]));
    let handler = u32::try_from(code.len()).unwrap();
    code.extend(instruction("ldai", "IMM32", &9i32.to_le_bytes()));
    code.extend(instruction("return", "NONE", &[]));
    let (bytes, offset) =
        method_fixture(&code, &[try_start, handler - try_start, 1, 0, handler, 6]);
    let mut source = Decompiler::new(&bytes)
        .unwrap()
        .render_class("Ltest/Module;", OutputMode::Source)
        .unwrap();
    assert!(source.contains("catch (__caught)"), "{source}");
    source.push_str(&format!("console.log(__fn_{offset}(null)());\n"));
    if let Some(output) = execute(&source) {
        assert_eq!(output.trim(), "9");
    }
}

#[test]
fn control_flow_cannot_jump_into_an_operand() {
    let mut code = instruction("jmp", "IMM8", &[1]);
    code.extend(instruction("returnundefined", "NONE", &[]));
    let (bytes, _) = method_fixture(&code, &[]);
    let err = Decompiler::new(&bytes)
        .unwrap()
        .render_class("Ltest/Module;", OutputMode::Source)
        .unwrap_err();
    assert!(
        err.to_string().contains("middle of an instruction"),
        "{err}"
    );
}

#[test]
fn unsupported_semantics_report_an_error_and_remain_available_in_assembly() {
    let code = instruction("getresumemode", "NONE", &[]);
    let (bytes, _) = method_fixture(&code, &[]);
    let decompiler = Decompiler::new(&bytes).unwrap();
    assert!(decompiler
        .render_class("Ltest/Module;", OutputMode::Source)
        .unwrap_err()
        .to_string()
        .contains("getresumemode"));
    assert!(decompiler
        .render_class("Ltest/Module;", OutputMode::Assembly)
        .unwrap()
        .contains("getresumemode"));
}

#[test]
fn async_await_suspension_restores_the_resolved_value() {
    let mut code = instruction("asyncfunctionenter", "NONE", &[]);
    code.extend(instruction("sta", "V8", &[0]));
    code.extend(instruction("ldai", "IMM32", &42i32.to_le_bytes()));
    code.extend(instruction("asyncfunctionawaituncaught", "V8", &[0]));
    code.extend(instruction("sta", "V8", &[1]));
    code.extend(instruction("suspendgenerator", "V8", &[0]));
    code.extend(instruction("resumegenerator", "NONE", &[]));
    code.extend(instruction("sta", "V8", &[1]));
    code.extend(instruction("getresumemode", "NONE", &[]));
    code.extend(instruction("lda", "V8", &[1]));
    code.extend(instruction("asyncfunctionresolve", "V8", &[0]));
    code.extend(instruction("return", "NONE", &[]));
    let (mut bytes, offset) = method_fixture(&code, &[]);
    let code_off = 60 + panda_string("func_main_0").len();
    bytes[code_off] = 2;
    let mut source = Decompiler::new(&bytes)
        .unwrap()
        .render_class("Ltest/Module;", OutputMode::Source)
        .unwrap();
    source.push_str(&format!(
        "__fn_{offset}(null)().then(value => console.log(value));\n"
    ));
    if let Some(output) = execute(&source) {
        assert_eq!(output.trim(), "42");
    }
}

#[test]
fn generators_preserve_suspended_frames_and_next_throw_return_modes() {
    let mut code = instruction("creategeneratorobj", "V8", &[3]);
    code.extend(instruction("sta", "V8", &[0]));
    code.extend(instruction("suspendgenerator", "V8", &[0]));
    code.extend(instruction("resumegenerator", "NONE", &[]));
    code.extend(instruction("ldai", "IMM32", &7i32.to_le_bytes()));
    code.extend(instruction("sta", "V8", &[1]));
    code.extend(instruction("ldfalse", "NONE", &[]));
    code.extend(instruction("sta", "V8", &[2]));
    code.extend(instruction("createiterresultobj", "V8_V8", &[1, 2]));
    code.extend(instruction("suspendgenerator", "V8", &[0]));
    code.extend(instruction("resumegenerator", "NONE", &[]));
    code.extend(instruction("sta", "V8", &[1]));
    code.extend(instruction("getresumemode", "NONE", &[]));
    code.extend(instruction("sta", "V8", &[2]));
    code.extend(instruction("ldai", "IMM32", &1i32.to_le_bytes()));
    code.extend(instruction("stricteq", "IMM8_V8", &[0, 2]));
    let jump = code.len();
    code.extend(instruction("jeqz", "IMM8", &[0]));
    code.extend(instruction("lda", "V8", &[1]));
    code.extend(instruction("throw", "PREF_NONE", &[]));
    let target = code.len();
    code[jump + 1] = i8::try_from(target - jump).unwrap().to_le_bytes()[0];
    code.extend(instruction("lda", "V8", &[1]));
    code.extend(instruction("return", "NONE", &[]));
    let (mut bytes, offset) = method_fixture(&code, &[]);
    let code_off = 60 + panda_string("func_main_0").len();
    bytes[code_off] = 3;
    let mut source = Decompiler::new(&bytes)
        .unwrap()
        .render_class("Ltest/Module;", OutputMode::Source)
        .unwrap();
    source.push_str(&format!("const g = __fn_{offset}(null)(); console.log(JSON.stringify(g.next())); console.log(JSON.stringify(g.next(42))); console.log(JSON.stringify(g.next()));\nconst h = __fn_{offset}(null)(); h.next(); try {{ h.throw('bad'); }} catch (e) {{ console.log(e); }} console.log(JSON.stringify(h.next()));\nconst r = __fn_{offset}(null)(); r.next(); console.log(JSON.stringify(r.return(99)));\n"));
    if let Some(output) = execute(&source) {
        assert_eq!(output.trim(), "{\"value\":7,\"done\":false}\n{\"value\":42,\"done\":true}\n{\"done\":true}\nbad\n{\"done\":true}\n{\"value\":99,\"done\":true}");
    }
}

#[test]
fn module_metadata_and_live_export_slots_survive_reconstruction() {
    let mut bytes = vec![0; 60];
    bytes[..8].copy_from_slice(b"PANDA\0\0\0");
    bytes[12..16].copy_from_slice(&[24, 0, 0, 0]);
    let mut strings = Vec::new();
    for name in [
        "func_main_0",
        "moduleRecordIdx",
        "data:text/javascript,export const value=7",
        "input",
        "value",
        "output",
        "answer",
    ] {
        strings.push(u32::try_from(bytes.len()).unwrap());
        bytes.extend(panda_string(name));
    }
    let module = u32::try_from(bytes.len()).unwrap();
    for value in [0, 1, strings[2], 1, strings[3], strings[4]] {
        bytes.extend(value.to_le_bytes());
    }
    bytes.extend(0u16.to_le_bytes());
    for value in [0, 1, strings[5], strings[6], 0, 0] {
        bytes.extend(value.to_le_bytes());
    }
    let mut code = instruction("ldexternalmodulevar", "IMM8", &[0]);
    code.extend(instruction("sta", "V8", &[0]));
    code.extend(instruction("ldai", "IMM32", &42i32.to_le_bytes()));
    code.extend(instruction("add2", "IMM8_V8", &[0, 0]));
    let store_offset = code.len();
    code.extend(instruction("stmodulevar", "IMM8", &[0]));
    code.extend(instruction("returnundefined", "NONE", &[]));
    let code_off = u32::try_from(bytes.len()).unwrap();
    bytes.extend([1, 3]);
    bytes.extend(uleb(u32::try_from(code.len()).unwrap()));
    bytes.push(0);
    bytes.extend(code);
    let class_off = u32::try_from(bytes.len()).unwrap();
    bytes.extend(panda_string("Ltest/Module;"));
    bytes.extend([0; 4]);
    bytes.extend([1, 1, 1, 0]);
    bytes.extend([0; 4]);
    bytes.extend(strings[1].to_le_bytes());
    bytes.extend([8, 2]);
    bytes.extend(module.to_le_bytes());
    bytes.push(0);
    bytes.extend([0, 0, 255, 255]);
    bytes.extend(strings[0].to_le_bytes());
    bytes.extend([8, 1]);
    bytes.extend(code_off.to_le_bytes());
    bytes.push(0);
    let index = u32::try_from(bytes.len()).unwrap();
    bytes.extend(class_off.to_le_bytes());
    let length = u32::try_from(bytes.len()).unwrap();
    bytes[16..20].copy_from_slice(&length.to_le_bytes());
    bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&index.to_le_bytes());
    check_module(&bytes, "input", "output", "49");

    let local_name = usize::try_from(module).unwrap() + 34;
    bytes[local_name..local_name + 4].copy_from_slice(&strings[3].to_le_bytes());
    check_module(&bytes, "__import_0", "input", "49");

    let store_offset = usize::try_from(code_off).unwrap() + 4 + store_offset;
    bytes[store_offset..store_offset + 2]
        .copy_from_slice(&instruction("nop", "NONE", &[]).repeat(2));
    check_module(&bytes, "__import_0", "__import_0", "7");
}

fn check_module(bytes: &[u8], imported: &str, exported: &str, expected: &str) {
    let mut source = Decompiler::new(bytes)
        .unwrap()
        .render_class("Ltest/Module;", OutputMode::Source)
        .unwrap();
    assert!(
        source.contains(&format!("import {{ value as {imported} }}")),
        "{source}"
    );
    assert!(
        source.contains(&format!("export {{ {exported} as answer }}")),
        "{source}"
    );
    source.push_str(&format!("console.log({exported});\n"));
    match Command::new("node")
        .args(["--input-type=module", "-e", &source])
        .output()
    {
        Ok(result) => {
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(String::from_utf8(result.stdout).unwrap().trim(), expected);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => panic!("cannot execute module test: {err}"),
    }
}
