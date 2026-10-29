use std::io::Write;
use std::process::{Command, Stdio};

use super::source;

pub(crate) fn execute(source: &str) -> Option<String> {
    let mut child = match Command::new("node")
        .args(["-e", "const fs=require('fs'),vm=require('vm');const context={};vm.runInNewContext(fs.readFileSync(0,'utf8'),context,{timeout:2000});console.log(JSON.stringify(context.result))"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(child) => child,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        Err(error) => panic!("cannot start Node test oracle: {error}"),
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
        "{}\n{source}",
        String::from_utf8_lossy(&result.stderr)
    );
    Some(String::from_utf8(result.stdout).unwrap().trim().to_string())
}

fn check(input: &str, expected: &str) -> String {
    let output = source(input, false).unwrap();
    if let Some(original) = execute(input) {
        assert_eq!(original, expected, "original input");
    }
    if let Some(optimized) = execute(&output) {
        assert_eq!(optimized, expected, "{output}");
    }
    output
}

#[test]
fn loops_and_partial_branch_stores_remain_live() {
    check("function run(p0) { let v0, acc; v0 = 0; while (v0 < 3) { acc = v0 + 1; v0 = acc; } if (p0) v0 = 7; return v0; } globalThis.result = [run(false), run(true)];", "[3,7]");
}

#[test]
fn closures_keep_read_and_write_only_captures() {
    check("function run() { let v0, v1; v0 = 1; v1 = function () { v0 = 5; }; v1(); return v0; } globalThis.result = run();", "5");
    check("function run() { let v0, v1; v0 = 1; v1 = function (v0) { v0 = 7; return v0; }; return [v1(2), v0]; } globalThis.result = run();", "[7,1]");
}

#[test]
fn getters_and_arguments_keep_their_evaluation_order() {
    check(
        r#"function run() {
        let events = [], obj = { name: 'old', get method() { events.push('getter'); return function (value) { events.push(this.name, value); }; } };
        let v0, v1, v2;
        v1 = obj; v0 = v1.method;
        v2 = (events.push('argument'), 3);
        v0.call(v1, v2);
        return events;
    } globalThis.result = run();"#,
        r#"["getter","argument","old",3]"#,
    );
    check(
        r#"function run() {
        let v0, v1;
        v1 = { name: 'old', get method() { v1 = {name: 'new'}; return function () { return this.name; }; } };
        v0 = v1.method;
        return v0.call(v1);
    } globalThis.result = run();"#,
        r#""new""#,
    );
}

#[test]
fn method_call_recovery_preserves_callback_scopes_and_conditional_reads() {
    check(
        "function run(){let events=[],obj={catch(cb){cb();},error(){events.push('error');}};let v0,v1;v0=obj;v1=v0.catch;v1.call(v0,function(){let v0,v1;v0=obj;v1=v0.error;v1.call(v0);});return events;}globalThis.result=run();",
        "[\"error\"]",
    );
    check(
        "function run(){let events=[],obj={catch(cb){cb();},error(){events.push('error');}};let v0,v1;v0=obj;v1=v0.catch;v1.call(v0,()=>{let v0,v1;v0=obj;v1=v0.error;v1.call(v0);});return events;}globalThis.result=run();",
        "[\"error\"]",
    );
    check(
        "function run(p0){let events=[],obj={get method(){events.push('get');return ()=>events.push('call');}};let v0;v0=obj.method;if(p0)v0.call(obj);return events;}globalThis.result=[run(false),run(true)];",
        "[[\"get\"],[\"get\",\"call\"]]",
    );
    check(
        "function run(){let events=[],obj={get method(){events.push('get');return ()=>events.push('call');}};let v0;v0=obj.method;return [events.push('before'),v0.call(obj),events];}globalThis.result=run();",
        "[2,3,[\"get\",\"before\",\"call\"]]",
    );
    check(
        "function run(){let obj={get method(){throw Error('get');}};let v0;v0=obj.method;try{v0.call(obj);}catch(e){return 'inner';}}try{run();}catch(e){globalThis.result=e.message;}",
        "\"get\"",
    );
}

#[test]
fn calls_cannot_change_a_captured_input_before_its_read() {
    check("function run(p0) { let v0; function mutate() { p0 = 9; return 1; } v0 = p0; return mutate() + v0; } globalThis.result = run(3);", "4");
}

#[test]
fn exceptional_paths_observe_the_last_completed_store() {
    check("function run(p0) { let v0, acc; v0 = 7; try { v0 = 1; if (p0) throw Error('stop'); acc = 2; v0 = acc; } catch (e) {} return v0; } globalThis.result = [run(false), run(true)];", "[2,1]");
    check(
        "function run(){let v0;try{v0=7;v0=(()=>{throw 1;})();}finally{return v0;}}globalThis.result=run();",
        "7",
    );
    check(
        "function run(){let v0;try{throw 1;}catch(e){v0=7;v0=(()=>{throw 2;})();}finally{return v0;}}globalThis.result=run();",
        "7",
    );
}

#[test]
fn boolean_facts_are_invalidated_by_branches_and_closure_calls() {
    check("function run(p0) { let v0; v0 = true; if (p0) v0 = 3; return v0 !== 0 && v0 !== false; } globalThis.result = [run(false), run(true)];", "[true,true]");
    check("function run() { let v0; v0 = true; function mutate() { v0 = 3; } mutate(); return v0 !== 0 && v0 !== false; } globalThis.result = run();", "true");
    check("function run(p0) { let v0; v0 = 3; try { if (p0) throw Error('stop'); v0 = true; } catch(e) {} return v0 !== 0 && v0 !== false; } globalThis.result = [run(false), run(true)];", "[true,true]");
    check("function run() { let v0, v1; v0 = 0; v1 = function () { v0++; }; v1(); return v0; } globalThis.result = run();", "1");
}

#[test]
fn inlined_factories_capture_distinct_lexical_frames() {
    check("function __fn_1(__parentEnv) { return function () { return __parentEnv.slots[0]; }; } function run() { let __env = __parentEnv, v0, v1; __env = {parent: __env, slots: []}; __env.slots[0] = 3; v0 = __fn_1(__env); __env = {parent: __env, slots: []}; __env.slots[0] = 5; v1 = __fn_1(__env); return [v0(), v1()]; } const __parentEnv = null; globalThis.result = run();", "[3,5]");
}

#[test]
fn explicit_global_object_properties_remain_distinct_from_records() {
    let output = source("__abc_record_store('Test', class Test {}); globalThis.Test = 'property'; globalThis.result = [__abc_global('Test').name, globalThis.Test];", false).unwrap();
    if let Some(result) = execute(&output) {
        assert_eq!(result, r#"["Test","property"]"#, "{output}");
    }
}

#[test]
fn string_named_imports_print_as_valid_identifiers() {
    let output = source(
        "import { 'AppLog' as AppLog } from 'example'; export { AppLog as 'AppLog' };",
        false,
    )
    .unwrap();
    assert!(output.contains("import { AppLog }"), "{output}");
    assert!(output.contains("export { AppLog }"), "{output}");
}

#[test]
fn compiled_finally_closes_on_both_normal_and_throwing_paths() {
    let output = check(
        r#"const __hole = Symbol('hole');
        function run(p0) {
            let events = [], v0, v1;
            v0 = undefined;
            try {
                events.push('body');
                if (p0) throw Error('failure');
                v1 = __hole;
            } catch (caught) { v1 = caught; }
            if (v0 == undefined) events.push('close');
            if (__hole != v1) throw v1;
            return events;
        }
        let failed;
        try { run(true); } catch(e) { failed = e.message; }
        globalThis.result = [run(false), failed];"#,
        r#"[["body","close"],"failure"]"#,
    );
    assert!(output.contains("finally"), "{output}");
}

#[test]
fn variable_initialization_preserves_declaration_order() {
    check("function run() { let v0, v1, v2; v1 = Array; v2 = 4; v0 = new v1(v2); return v0.length; } globalThis.result = run();", "4");
    check(
        "function run() { let v0, v1 = 3; v0 = v1 + 2; return v0; } globalThis.result = run();",
        "5",
    );
}

#[test]
fn private_sentinel_checks_are_removed_only_when_the_value_cannot_escape() {
    let output = check("const __hole = Symbol('hole'); function run(p0) { let v0; v0 = p0; if (v0 === __hole) throw Error('uninitialized'); return v0; } globalThis.result = run('label');", "\"label\"");
    assert!(!output.contains("__hole"), "{output}");
    check("const __hole = Symbol('hole'); function run(p0) { let v0; v0 = p0; if (v0 === __hole) throw Error('uninitialized'); return v0; } try { run(__hole); } catch(e) { globalThis.result = e.message; }", "\"uninitialized\"");
}

#[test]
fn object_literals_preserve_property_order_and_value_evaluation() {
    let output = check(
        r#"function run() {
        let events = [], v0;
        v0 = {a: null, b: 2, c: null};
        Object.defineProperty(v0, 'a', {value: (events.push('a'), 1), writable: true, enumerable: true, configurable: true});
        Object.defineProperty(v0, 'c', {value: (events.push('c'), 3), writable: true, enumerable: true, configurable: true});
        return [Object.keys(v0), v0.a, v0.c, events];
    } globalThis.result = run();"#,
        r#"[["a","b","c"],1,3,["a","c"]]"#,
    );
    assert!(!output.contains("Object.defineProperty"), "{output}");
    check(
        r#"function run() {
        let events = [], v0;
        v0 = {a: null, b: (events.push('b'), 2)};
        Object.defineProperty(v0, 'a', {value: (events.push('a'), 1), writable: true, enumerable: true, configurable: true});
        Object.defineProperty(v0, '__proto__', {value: 7, writable: true, enumerable: true, configurable: true});
        return [Object.keys(v0), v0.a, v0.__proto__, events];
    } globalThis.result = run();"#,
        r#"[["a","b","__proto__"],1,7,["b","a"]]"#,
    );
}

#[test]
fn equality_negation_preserves_coercion_and_nan_behavior() {
    let output = check(
        r#"let events=[]; const obj={valueOf(){events.push('coerce');return 2;}};
        function run(p0){return !(p0<0);}
        globalThis.result=[!(obj==2),!(obj===2),run(NaN),events];"#,
        r#"[false,true,true,["coerce"]]"#,
    );
    assert!(output.contains("obj !== 2"), "{output}");
    assert!(output.contains("!(p0 < 0)"), "{output}");
}

#[test]
fn branch_tests_can_inline_values_without_replacing_branch_stores() {
    let output = check(
        "function run(p0){let acc;acc=!p0;if(acc){return 'off';}else{acc=Math.min(3,5);return acc+1;}}globalThis.result=[run(false),run(true)];",
        "[\"off\",4]",
    );
    assert!(!output.contains("acc = !p0"), "{output}");
    check(
        "function run(p0){let acc;acc=!p0;if(acc){try{acc=(()=>{throw 1;})();}catch(e){return acc;}}else{return 2;}}globalThis.result=[run(false),run(true)];",
        "[true,2]",
    );
    check(
        "function run(p0){let acc;acc=!p0;if(acc){try{acc=(()=>{throw 1;})();}finally{return acc;}}else{return 2;}}globalThis.result=[run(false),run(true)];",
        "[true,2]",
    );
}

#[test]
fn stable_aliases_before_try_preserve_values_on_failed_overwrites() {
    let output = check(
        "class Log{static nameOf(){return 'Log';}}function run(){let v0;v0=Log;let name=v0.nameOf();try{v0=()=>1;}catch(e){}return [name,v0()];}globalThis.result=run();",
        "[\"Log\",1]",
    );
    assert!(output.contains("Log.nameOf()"), "{output}");
    check(
        "class Log{}function run(p0){let v0;v0=Log;let snapshot=v0;try{v0=(()=>{if(p0)throw 1;return 2;})();}catch(e){}return [snapshot===Log,v0===Log];}globalThis.result=[run(false),run(true)];",
        "[[true,false],[true,true]]",
    );
    check(
        "class Log{}function run(){let v0;v0=Log;let snapshot=v0;try{v0=(()=>{throw 1;})();}catch(e){return [snapshot===Log,v0===Log];}}globalThis.result=run();",
        "[true,true]",
    );
    check(
        "class Log{}function run(){let v0;v0=Log;let snapshot=v0;try{v0=(()=>{throw 1;})();}finally{return [snapshot===Log,v0===Log];}}globalThis.result=run();",
        "[true,true]",
    );
}

#[test]
fn branch_assignments_preserve_conditional_effects_and_function_names() {
    let output = check(
        r#"function run(p0) {
        let events=[],v0; function yes(){events.push('yes');return 1;} function no(){events.push('no');return 2;}
        if(p0) v0=yes(); else v0=no(); return [v0,events];
    } globalThis.result=[run(true),run(false)];"#,
        r#"[[1,["yes"]],[2,["no"]]]"#,
    );
    assert!(output.contains("? yes() : no()"), "{output}");
    check("function run(p0){let v0;if(p0)v0=function(){};else v0=()=>{};return v0.name;} globalThis.result=[run(true),run(false)];", "[\"v0\",\"v0\"]");
    check("function run(){const v0=1;try{if(v0)v0=2;}catch(e){return e.name;}} globalThis.result=run();", "\"TypeError\"");
}

#[test]
fn short_circuit_recovery_preserves_values_and_skipped_operands() {
    let output = check(
        r#"function run(p0,p1,p2) {
        let events=[],v0; v0=p0;
        if(!v0) v0=(events.push('b'),p1);
        if(!v0) v0=(events.push('c'),p2);
        return [v0,events];
    } globalThis.result=[run(5,2,3),run(0,2,3),run(0,0,3)];"#,
        r#"[[5,[]],[2,["b"]],[3,["b","c"]]]"#,
    );
    assert!(!output.contains("if ("), "{output}");
    check("let v0=7;const run=()=>{const v0=1;try{if(v0)v0=2;}catch(e){return e.name;}};globalThis.result=[run(),v0];", "[\"TypeError\",7]");
}

#[test]
fn switch_recovery_preserves_case_matching_and_global_getter_reads() {
    let output = check("function run(p0){if(p0===1)return 'a';if(p0===2)return 'b';if(p0===3)return 'a';if(p0===4)return 'b';return 'z';} globalThis.result=[run(1),run(2),run(3),run(4),run('1'),run(NaN)];", "[\"a\",\"b\",\"a\",\"b\",\"z\",\"z\"]");
    assert!(output.contains("switch (p0)"), "{output}");
    check("let count=0;Object.defineProperty(globalThis,'flag',{get(){count++;return 0;}});function run(){if(flag===1)return 'a';if(flag===2)return 'b';if(flag===3)return 'c';if(flag===4)return 'd';return 'z';}globalThis.result=[run(),count];", "[\"z\",4]");
    check("function run(p0){if(p0===1)return 'a';if(p0===2)return 'b';if(p0===2)return 'c';if(p0===3)return 'd';if(p0===4)return 'e';return 'z';}globalThis.result=[run(2),run(4)];", "[\"b\",\"e\"]");
}
