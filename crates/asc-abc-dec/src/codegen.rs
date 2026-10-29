use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::cfg::{line, Catch, Graph};
use crate::decode::{decode, Operand, FIELD_ID, TYPE_ID};
use crate::file::{Class, File, Literal, Method, Module, Reader};
use crate::lower::{binding_name, identifier, quote, ClassDefinition, Lower, Request, Scope};
use crate::{Error, OutputMode, Result, SizeBudget};

pub struct Decompiler<'a> {
    file: File<'a>,
}

impl<'a> Decompiler<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        Ok(Self {
            file: File::parse(data)?,
        })
    }

    pub fn render_class(&self, query: &str, mode: OutputMode) -> Result<String> {
        self.render_class_optional(query, mode)?
            .ok_or_else(|| Error::ClassNotFound(query.into()))
    }

    pub fn render_class_optional(&self, query: &str, mode: OutputMode) -> Result<Option<String>> {
        let Some(class) = self.file.class(query)? else {
            return Ok(None);
        };
        let output = match mode {
            OutputMode::Source => crate::optimize::source(
                &self.source(&class)?,
                class
                    .methods
                    .iter()
                    .any(|method| method.name == "func_main_0"),
            )?,
            OutputMode::Assembly => self.assembly(&class)?,
        };
        Ok(Some(output))
    }

    fn assembly(&self, class: &Class<'a>) -> Result<String> {
        let mut out = format!(".record {} {{\n", class.name);
        let mut budget = SizeBudget::new("record assembly");
        budget.charge(out.len())?;
        for method in &class.methods {
            budget.charge(method.name.len() + 32)?;
            line(&mut out, 1, &format!(".method {} {{", method.name));
            if let Some(code) = &method.code {
                line(&mut out, 2, &format!(".registers {}", code.registers));
                line(&mut out, 2, &format!(".arguments {}", code.arguments));
                for ins in decode(code.bytes)? {
                    let mut operands = Vec::new();
                    let mut id_count = 0;
                    for operand in &ins.operands {
                        let value = match operand {
                            Operand::Register(index) => format!("v{index}"),
                            Operand::Immediate(value) => value.to_string(),
                            Operand::Float(value) => crate::file::number(*value),
                            Operand::Id(index) => {
                                let offset = self.file.reference(
                                    method.offset,
                                    *index,
                                    ins.opcode.flags & (TYPE_ID | FIELD_ID),
                                )?;
                                let kind = if ins.opcode.flags & 2 != 0 && id_count == 0 {
                                    "method"
                                } else if ins.opcode.flags & 8 != 0 {
                                    "literal"
                                } else if ins.opcode.flags & 4 != 0 {
                                    "string"
                                } else if ins.opcode.flags & FIELD_ID != 0 {
                                    "field"
                                } else {
                                    "type"
                                };
                                id_count += 1;
                                match kind {
                                    "string" => format!(
                                        "string@{offset:#x} {}",
                                        quote(&self.file.string(offset)?)
                                    ),
                                    "method" | "field" => {
                                        let name_off = offset.checked_add(4).ok_or_else(|| {
                                            Error::invalid("member offset overflow")
                                        })?;
                                        let name = self.file.string(
                                            Reader::new(self.file.data(), name_off)?.u32()?,
                                        )?;
                                        format!("{kind}@{offset:#x} {}", quote(&name))
                                    }
                                    _ => format!("{kind}@{offset:#x}"),
                                }
                            }
                        };
                        operands.push(value);
                    }
                    let target = ins
                        .jump_target()?
                        .map(|pc| format!(" -> label_{pc:04x}"))
                        .unwrap_or_default();
                    let text = format!(
                        "label_{:04x}: {} {}{target}",
                        ins.pc,
                        ins.opcode.name,
                        operands.join(", ")
                    );
                    budget.charge(text.len() + 9)?;
                    line(&mut out, 2, &text);
                }
                for block in &code.tries {
                    for handler in &block.handlers {
                        budget.charge(128)?;
                        line(&mut out, 2, &format!(".catch type#{} label_{:04x}..label_{:04x} -> label_{:04x}..label_{:04x}", handler.type_index, block.start, block.end, handler.pc, handler.end));
                    }
                }
            } else {
                line(&mut out, 2, ".external");
            }
            line(&mut out, 1, "}");
        }
        line(&mut out, 0, "}");
        Ok(out)
    }

    fn source(&self, class: &Class<'a>) -> Result<String> {
        let mut out = format!(
            "// ABC record: {}\n// Adapted from xpanda-core by jmp0 (Apache-2.0).\n",
            class.name.replace(['\n', '\r'], " ")
        );
        out.push_str(&self.module(&class.module));
        out.push_str("const __hole = Symbol(\"ABC uninitialized binding\");\n");
        let entry = class
            .methods
            .iter()
            .find(|method| method.name == "func_main_0" && method.code.is_some());
        let mut pending: VecDeque<_> = class
            .methods
            .iter()
            .filter(|method| {
                method.code.is_some() && entry.is_none_or(|entry| entry.offset == method.offset)
            })
            .map(|method| Request::Method(method.offset))
            .collect();
        let mut methods = BTreeMap::new();
        let mut classes = BTreeMap::new();
        let mut stored_exports = BTreeSet::new();
        let mut budget = SizeBudget::new("record source");
        budget.charge(out.len())?;
        while let Some(request) = pending.pop_front() {
            match request {
                Request::Method(offset) => {
                    if methods.contains_key(&offset) {
                        continue;
                    }
                    let method = self.file.method(offset)?;
                    let name = function_name(&method);
                    let (body, requests, async_prefix) =
                        self.body(&method, &class.module, Scope::Function, &name)?;
                    let parameters = parameters(&method)?;
                    let mut source = format!("function __fn_{offset}(__parentEnv, __home) {{\n    return {async_prefix}function {name}({parameters}) {{\n");
                    line(&mut source, 2, &body);
                    source.push_str("    };\n}\n");
                    budget.charge(source.len())?;
                    methods.insert(offset, source);
                    pending.extend(requests);
                }
                Request::Class(definition) => {
                    if classes.contains_key(&definition) {
                        continue;
                    }
                    let (source, requests) = self.class_factory(definition, &class.module)?;
                    budget.charge(source.len())?;
                    classes.insert(definition, source);
                    pending.extend(requests);
                }
                Request::ModuleStore(index) => {
                    stored_exports.insert(index);
                }
            }
            if methods.len() + classes.len() > 65536 {
                return Err(Error::invalid("class exceeds 65536 definitions"));
            }
        }
        if methods
            .values()
            .chain(classes.values())
            .any(|source| source.contains("__result("))
        {
            out.push_str("function __result(value, done) {\n    return value && typeof value === 'object' && typeof value.done === 'boolean' ? value : {value, done};\n}\n");
        }
        if methods
            .values()
            .chain(classes.values())
            .any(|source| source.contains("__exclude("))
        {
            out.push_str("function __exclude(source, keys) {\n    const excluded = keys.map(key => typeof key === 'symbol' ? key : String(key));\n    const result = {};\n    for (const key of Reflect.ownKeys(source)) {\n        if (!excluded.includes(key) && Object.prototype.propertyIsEnumerable.call(source, key))\n            Object.defineProperty(result, key, {value: source[key], writable: true, enumerable: true, configurable: true});\n    }\n    return result;\n}\n");
        }
        for source in methods.values().chain(classes.values()) {
            out.push_str(source);
        }
        if let Some(main) = entry {
            out.push_str(&format!("__fn_{}(null)();\n", main.offset));
        }
        for (slot, export) in class.module.exports.iter().enumerate() {
            match (&export.path, &export.local, &export.exported) {
                (None, Some(local), Some(name)) => {
                    let forwarded = class
                        .module
                        .imports
                        .iter()
                        .enumerate()
                        .find(|(_, import)| import.local == *local);
                    let binding = if !stored_exports.contains(&slot) {
                        forwarded
                            .map(|(index, import)| {
                                class.module.import_binding(index, &import.local)
                            })
                            .unwrap_or_else(|| binding_name(local))
                    } else {
                        binding_name(local)
                    };
                    out.push_str(&format!("export {{ {binding} as {} }};\n", quote(name)));
                }
                (Some(path), Some(local), Some(name)) => out.push_str(&format!(
                    "export {{ {} as {} }} from {};\n",
                    quote(local),
                    quote(name),
                    quote(path)
                )),
                (Some(path), None, None) => {
                    out.push_str(&format!("export * from {};\n", quote(path)))
                }
                _ => return Err(Error::invalid("invalid module export entry")),
            }
        }
        if class.methods.is_empty() {
            out.push_str("// No runtime methods in this record.\n");
        }
        Ok(out)
    }

    fn module(&self, module: &Module) -> String {
        let mut out = String::new();
        for (index, path) in module.requests.iter().enumerate() {
            out.push_str(&format!(
                "import * as __namespace_{index} from {};\n",
                quote(path)
            ));
        }
        for (index, import) in module.imports.iter().enumerate() {
            let local = module.import_binding(index, &import.local);
            let specifier = match import.imported.as_deref() {
                None => format!("* as {local}"),
                Some("default") => local,
                Some(name) => format!("{{ {} as {local} }}", quote(name)),
            };
            out.push_str(&format!(
                "import {specifier} from {};\n",
                quote(&import.path)
            ));
        }
        let locals: BTreeSet<_> = module
            .exports
            .iter()
            .filter(|export| export.path.is_none())
            .filter_map(|export| export.local.as_deref())
            .map(binding_name)
            .collect();
        if !locals.is_empty() {
            out.push_str(&format!(
                "let {};\n",
                locals.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
        out
    }

    fn body(
        &self,
        method: &Method<'a>,
        module: &Module,
        scope: Scope,
        self_name: &str,
    ) -> Result<(String, Vec<Request>, &'static str)> {
        let Some(code) = &method.code else {
            return Ok((
                "throw new Error(\"External ABC method has no code\");\n".into(),
                Vec::new(),
                "",
            ));
        };
        let instructions = decode(code.bytes)?;
        let async_prefix = if instructions
            .iter()
            .any(|ins| ins.opcode.name == "asyncfunctionenter")
        {
            "async "
        } else {
            ""
        };
        let mut lower = Lower {
            file: &self.file,
            module,
            method,
            requests: Vec::new(),
            scope,
            async_function: !async_prefix.is_empty(),
            generator_function: async_prefix.is_empty()
                && instructions
                    .iter()
                    .any(|ins| ins.opcode.name.ends_with("creategeneratorobj")),
        };
        let mut budget = SizeBudget::new("lowered method");
        let lowered = instructions
            .iter()
            .map(|ins| {
                let instruction = lower.instruction(ins)?;
                instruction.charge(&mut budget)?;
                Ok(instruction)
            })
            .collect::<Result<Vec<_>>>()?;
        let boundaries: Vec<_> = code
            .tries
            .iter()
            .flat_map(|block| {
                [block.start, block.end].into_iter().chain(
                    block
                        .handlers
                        .iter()
                        .flat_map(|handler| [handler.pc, handler.end]),
                )
            })
            .collect();
        let graph = Graph::build(
            lowered,
            u32::try_from(code.bytes.len())
                .map_err(|_| Error::invalid("code length exceeds u32"))?,
            &boundaries,
        )?;
        let mut catches = Vec::new();
        for block in &code.tries {
            for handler in &block.handlers {
                let test = if handler.type_index == 0 {
                    None
                } else {
                    let offset =
                        self.file
                            .reference(method.offset, handler.type_index - 1, TYPE_ID)?;
                    let descriptor = self.file.string(offset)?;
                    let name = descriptor
                        .trim_start_matches('L')
                        .trim_end_matches(';')
                        .rsplit('/')
                        .next()
                        .unwrap_or(&descriptor);
                    Some(format!("__caught instanceof globalThis[{}]", quote(name)))
                };
                catches.push(Catch {
                    start: block.start,
                    end: block.end,
                    handler: handler.pc,
                    test,
                });
            }
        }
        let this_init = if matches!(scope, Scope::Constructor { derived: true }) {
            "undefined"
        } else {
            "this"
        };
        let mut out = format!("let __fnObject = {self_name}, __newTarget = new.target, __this = {this_init};\nlet __env = __parentEnv, __resume;\n");
        let registers: Vec<_> = (0..code.registers)
            .map(|index| format!("v{index}"))
            .chain(["acc".into()])
            .collect();
        out.push_str(&format!("let {};\n", registers.join(", ")));
        if lower.generator_function {
            out.push_str(&graph.emit_generator(&catches));
        } else {
            out.push_str(&graph.emit(&catches));
        }
        Ok((out, lower.requests, async_prefix))
    }

    fn class_factory(
        &self,
        definition: ClassDefinition,
        module: &Module,
    ) -> Result<(String, Vec<Request>)> {
        let constructor = self.file.method(definition.constructor)?;
        let name = function_name(&constructor);
        let literals = self.file.literals(definition.literals)?;
        let trailer = if definition.sendable { 2 } else { 1 };
        if literals.len() < trailer {
            return Err(Error::invalid("class literal buffer is empty"));
        }
        let count_index = literals.len() - trailer;
        let Literal::Value(count) = &literals[count_index] else {
            return Err(Error::invalid("class literal has no instance method count"));
        };
        let instance_count: usize = count
            .parse()
            .map_err(|_| Error::invalid("invalid class instance method count"))?;
        if count_index % 3 != 0 || instance_count > count_index / 3 {
            return Err(Error::invalid("invalid class method buffer"));
        }
        let mut fields = Vec::new();
        if definition.sendable {
            let Some(Literal::Array(offset)) = literals.last() else {
                return Err(Error::invalid("sendable class has no field buffer"));
            };
            let descriptions = self.file.literals(*offset)?;
            let Some(Literal::Value(count)) = descriptions.last() else {
                return Err(Error::invalid("sendable class has no field count"));
            };
            let count: usize = count
                .parse()
                .map_err(|_| Error::invalid("invalid sendable field count"))?;
            if count.checked_mul(2).and_then(|count| count.checked_add(1))
                != Some(descriptions.len())
            {
                return Err(Error::invalid("invalid sendable field buffer"));
            }
            for field in descriptions[..descriptions.len() - 1].as_chunks::<2>().0 {
                let Literal::String(name) = &field[0] else {
                    return Err(Error::invalid("sendable field has no name"));
                };
                // The second value is a SharedFieldType mask, not an initializer.
                fields.push(name.clone());
            }
        }
        let mut requests = Vec::new();
        let mut budget = SizeBudget::new("class source");
        let mut out = format!(
            "function __class_{}_{}(__parentEnv, __proto) {{\n",
            definition.constructor, definition.literals
        );
        for derived in [false, true] {
            if !derived {
                line(
                    &mut out,
                    1,
                    "if (__proto === __hole || __proto === undefined || __proto === null) {",
                );
            }
            let indent = if derived { 1 } else { 2 };
            let extends = if derived { " extends __proto" } else { "" };
            line(
                &mut out,
                indent,
                &format!("return class {name}{extends} {{"),
            );
            if definition.sendable {
                line(&mut out, indent + 1, "// @Sendable");
            }
            for field in &fields {
                line(&mut out, indent + 1, &format!("[{}];", quote(field)));
            }
            let (body, nested, async_prefix) =
                self.body(&constructor, module, Scope::Constructor { derived }, &name)?;
            budget.charge(body.len())?;
            if !async_prefix.is_empty() {
                return Err(Error::invalid("class constructor cannot be async"));
            }
            requests.extend(nested);
            line(
                &mut out,
                indent + 1,
                &format!("constructor({}) {{", parameters(&constructor)?),
            );
            line(&mut out, indent + 2, &body);
            line(&mut out, indent + 1, "}");
            for (index, group) in literals[..count_index]
                .as_chunks::<3>()
                .0
                .iter()
                .enumerate()
            {
                let Literal::String(key) = &group[0] else {
                    return Err(Error::invalid("class member name is not a string"));
                };
                let Literal::Method { offset, tag } = group[1] else {
                    return Err(Error::invalid("class member is not a method"));
                };
                let method = self.file.method(offset)?;
                let home = if index < instance_count {
                    format!("{name}.prototype")
                } else {
                    name.clone()
                };
                let self_name = match tag {
                    0x1a => format!(
                        "Object.getOwnPropertyDescriptor({home}, {}).get",
                        quote(key)
                    ),
                    0x1b => format!(
                        "Object.getOwnPropertyDescriptor({home}, {}).set",
                        quote(key)
                    ),
                    _ => format!("{home}[{}]", quote(key)),
                };
                let (body, nested, async_prefix) =
                    self.body(&method, module, Scope::ClassMethod, &self_name)?;
                budget.charge(body.len())?;
                requests.extend(nested);
                let static_prefix = if index >= instance_count {
                    "static "
                } else {
                    ""
                };
                let accessor = match tag {
                    0x1a => "get ",
                    0x1b => "set ",
                    _ => "",
                };
                line(
                    &mut out,
                    indent + 1,
                    &format!(
                        "{static_prefix}{async_prefix}{accessor}[{}]({}) {{",
                        quote(key),
                        parameters(&method)?
                    ),
                );
                line(&mut out, indent + 2, &body);
                line(&mut out, indent + 1, "}");
            }
            line(&mut out, indent, "};");
            if !derived {
                line(&mut out, 1, "}");
            }
        }
        out.push_str("}\n");
        Ok((out, requests))
    }
}

fn parameters(method: &Method<'_>) -> Result<String> {
    let count = method
        .code
        .as_ref()
        .map(|code| {
            if code.arguments >= 3 {
                code.arguments - 3
            } else {
                code.arguments
            }
        })
        .unwrap_or(0);
    if count > 65536 {
        return Err(Error::invalid("method argument count exceeds 65536"));
    }
    Ok((0..count)
        .map(|index| format!("p{index}"))
        .collect::<Vec<_>>()
        .join(", "))
}

fn function_name(method: &Method<'_>) -> String {
    let name = identifier(method.name.rsplit('#').next().unwrap_or(&method.name));
    let register_name = name
        .strip_prefix(['v', 'p'])
        .is_some_and(|tail| !tail.is_empty() && tail.bytes().all(|byte| byte.is_ascii_digit()));
    if name == "acc" || name.starts_with("__") || register_name {
        format!("__function_{}", method.offset)
    } else {
        name
    }
}
