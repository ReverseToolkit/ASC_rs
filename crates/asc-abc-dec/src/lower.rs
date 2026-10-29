use crate::cfg::{Exit, Lowered};
use crate::decode::{Instruction, Operand, CONDITIONAL};
use crate::file::{number, File, Literal, Method, Module};
use crate::{Error, Result, SizeBudget};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ClassDefinition {
    pub constructor: u32,
    pub literals: u32,
    pub sendable: bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Request {
    Method(u32),
    Class(ClassDefinition),
    ModuleStore(usize),
}

#[derive(Clone, Copy)]
pub(crate) enum Scope {
    Function,
    Constructor { derived: bool },
    ClassMethod,
}

pub(crate) struct Lower<'a, 'b> {
    pub file: &'b File<'a>,
    pub module: &'b Module,
    pub method: &'b Method<'a>,
    pub requests: Vec<Request>,
    pub scope: Scope,
    pub async_function: bool,
    pub generator_function: bool,
}

impl Lower<'_, '_> {
    pub fn register(&self, index: u32) -> Result<String> {
        let code = self
            .method
            .code
            .as_ref()
            .ok_or_else(|| Error::invalid("method has no code"))?;
        if index < code.registers {
            return Ok(format!("v{index}"));
        }
        let index = index - code.registers;
        if index >= code.arguments {
            return Err(Error::invalid("register index exceeds frame"));
        }
        Ok(if code.arguments >= 3 {
            match index {
                0 => "__fnObject".into(),
                1 => "__newTarget".into(),
                2 => "__this".into(),
                index => format!("p{}", index - 3),
            }
        } else {
            format!("p{index}")
        })
    }

    fn operand(&self, ins: &Instruction, index: usize) -> Result<String> {
        match ins.operands.get(index) {
            Some(Operand::Register(index)) => self.register(*index),
            Some(Operand::Immediate(value)) => Ok(value.to_string()),
            Some(Operand::Float(value)) => Ok(number(*value)),
            Some(Operand::Id(_)) => Ok(quote(&self.string_id(ins, index)?)),
            None => Err(Error::invalid("missing operand")),
        }
    }

    fn reference(&self, ins: &Instruction, index: usize) -> Result<u32> {
        self.file.reference(self.method.offset, ins.id(index)?, 0)
    }

    fn string_id(&self, ins: &Instruction, index: usize) -> Result<String> {
        self.file.string(self.reference(ins, index)?)
    }

    fn range(&self, base: u32, count: i64) -> Result<Vec<String>> {
        let count = u32::try_from(count).map_err(|_| Error::invalid("negative register range"))?;
        if count > 65536 {
            return Err(Error::invalid("register range exceeds frame"));
        }
        (0..count)
            .map(|index| {
                self.register(
                    base.checked_add(index)
                        .ok_or_else(|| Error::invalid("register range overflow"))?,
                )
            })
            .collect()
    }

    fn literal(
        &mut self,
        literal: &Literal,
        depth: usize,
        budget: &mut SizeBudget,
    ) -> Result<String> {
        if depth > 64 {
            return Err(Error::invalid("literal nesting exceeds 64"));
        }
        let text = match literal {
            Literal::Value(value) => Ok(value.clone()),
            Literal::String(value) => Ok(quote(value)),
            Literal::Method { offset, .. } => {
                self.requests.push(Request::Method(*offset));
                Ok(format!("__fn_{offset}(__env)"))
            }
            Literal::Affiliate(_) => Err(Error::invalid("method affiliate is not a value")),
            Literal::Array(offset) => {
                let values = self.file.literals(*offset)?;
                let expressions = values
                    .iter()
                    .map(|value| self.literal(value, depth + 1, budget))
                    .collect::<Result<Vec<_>>>()?;
                Ok(format!("[{}]", expressions.join(", ")))
            }
        }?;
        budget.charge(text.len())?;
        Ok(text)
    }

    fn array(&mut self, offset: u32) -> Result<String> {
        self.literal(
            &Literal::Array(offset),
            0,
            &mut SizeBudget::new("literal expansion"),
        )
    }

    fn object(&mut self, offset: u32) -> Result<String> {
        let literals = self.file.literals(offset)?;
        let mut props = Vec::new();
        let mut budget = SizeBudget::new("literal expansion");
        let mut index = 0;
        while index < literals.len() {
            let Literal::String(key) = &literals[index] else {
                return Err(Error::invalid("object key is not a string"));
            };
            let value = literals
                .get(index + 1)
                .ok_or_else(|| Error::invalid("object buffer has no value"))?;
            let mut expression = self.literal(value, 0, &mut budget)?;
            index += 2;
            if matches!(value, Literal::Method { .. }) {
                let Some(Literal::Affiliate(length)) = literals.get(index) else {
                    return Err(Error::invalid("method has no affiliate"));
                };
                expression = format!("Object.defineProperty({expression}, \"length\", {{value: {length}, configurable: true}})");
                index += 1;
            }
            let property = format!("{}: {expression}", quote(key));
            budget.charge(property.len())?;
            props.push(property);
        }
        Ok(format!("{{{}}}", props.join(", ")))
    }

    pub fn instruction(&mut self, ins: &Instruction) -> Result<Lowered> {
        let mut statements = Vec::new();
        let mut exit = None;
        let mut expression = None;
        let name = ins.opcode.name;
        let base = name
            .strip_prefix("wide.")
            .or_else(|| name.strip_prefix("deprecated."))
            .unwrap_or(name);
        let regs: Vec<_> = ins
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Register(index) => Some(*index),
                _ => None,
            })
            .collect();
        let imms: Vec<_> = ins
            .operands
            .iter()
            .filter_map(|operand| match operand {
                Operand::Immediate(value) => Some(*value),
                _ => None,
            })
            .collect();
        let reg = |index: usize| -> Result<String> {
            self.register(
                *regs
                    .get(index)
                    .ok_or_else(|| Error::invalid("missing register operand"))?,
            )
        };
        let binary = match base {
            "add2" => Some("+"),
            "sub2" => Some("-"),
            "mul2" => Some("*"),
            "div2" => Some("/"),
            "mod2" => Some("%"),
            "eq" => Some("=="),
            "noteq" => Some("!="),
            "less" => Some("<"),
            "lesseq" => Some("<="),
            "greater" => Some(">"),
            "greatereq" => Some(">="),
            "shl2" => Some("<<"),
            "shr2" => Some(">>>"),
            "ashr2" => Some(">>"),
            "and2" => Some("&"),
            "or2" => Some("|"),
            "xor2" => Some("^"),
            "exp" => Some("**"),
            "isin" => Some("in"),
            "instanceof" => Some("instanceof"),
            "stricteq" => Some("==="),
            "strictnoteq" => Some("!=="),
            _ => None,
        };
        if let Some(target) = ins.jump_target()? {
            exit = Some(if ins.opcode.flags & CONDITIONAL == 0 {
                Exit::Goto(target)
            } else {
                let test = match base {
                    "jeqz" => "acc === 0 || acc === false".into(),
                    "jnez" => "acc !== 0 && acc !== false".into(),
                    "jstricteqz" => "acc === 0".into(),
                    "jnstricteqz" => "acc !== 0".into(),
                    "jeqnull" => "acc === null".into(),
                    "jnenull" => "acc !== null".into(),
                    "jequndefined" => "acc === undefined".into(),
                    "jneundefined" => "acc !== undefined".into(),
                    "jeq" => format!("acc == {}", reg(0)?),
                    "jne" => format!("acc != {}", reg(0)?),
                    "jstricteq" => format!("acc === {}", reg(0)?),
                    "jnstricteq" => format!("acc !== {}", reg(0)?),
                    _ => return Err(unsupported(ins)),
                };
                Exit::Branch {
                    test,
                    yes: target,
                    no: ins.next_pc,
                }
            });
        } else if let Some(op) = binary {
            expression = Some(format!("({}) {op} acc", reg(0)?));
        } else {
            match base {
                "lda" => expression = Some(reg(0)?),
                "ldai" | "fldai" => expression = Some(self.operand(ins, 0)?),
                "lda.str" => expression = Some(quote(&self.string_id(ins, 0)?)),
                "ldbigint" => expression = Some(format!("BigInt({})", quote(&self.string_id(ins, 0)?))),
                "ldtrue" => expression = Some("true".into()), "ldfalse" => expression = Some("false".into()),
                "ldnull" => expression = Some("null".into()), "ldundefined" => expression = Some("undefined".into()),
                "ldhole" => expression = Some("__hole".into()), "ldnan" => expression = Some("NaN".into()),
                "ldinfinity" => expression = Some("Infinity".into()), "ldthis" => expression = Some("__this".into()),
                "ldglobal" => expression = Some("globalThis".into()), "ldnewtarget" => expression = Some("__newTarget".into()),
                "ldfunction" => expression = Some("__fnObject".into()), "ldsymbol" => expression = Some("Symbol".into()),
                "getunmappedargs" => expression = Some("arguments".into()),
                "sta" => statements.push(format!("{} = acc;", reg(0)?)),
                "mov" => statements.push(format!("{} = {};", reg(0)?, reg(1)?)),
                "return" => exit = Some(Exit::Return("acc".into())),
                "returnundefined" => exit = Some(Exit::Return(String::new())),
                "throw" => exit = Some(Exit::Throw("acc".into())),
                "typeof" => expression = Some("typeof acc".into()),
                "tonumber" | "tonumeric" => expression = Some("+acc".into()),
                "neg" => expression = Some("-acc".into()), "not" => expression = Some("~acc".into()),
                "inc" => expression = Some("(+acc) + 1".into()), "dec" => expression = Some("(+acc) - 1".into()),
                "istrue" | "callruntime.istrue" => expression = Some("!!acc".into()),
                "isfalse" | "callruntime.isfalse" => expression = Some("!acc".into()),
                "callarg0" => expression = Some("acc()".into()),
                "callarg1" | "callargs1" | "callargs2" | "callargs3" => {
                    let args = regs.iter().map(|index| self.register(*index)).collect::<Result<Vec<_>>>()?;
                    expression = Some(format!("acc({})", args.join(", ")));
                }
                "callrange" => {
                    let count = *imms.last().ok_or_else(|| Error::invalid("missing range count"))?;
                    let args = self.range(ins.reg(ins.operands.len() - 1)?, count)?;
                    expression = Some(format!("acc({})", args.join(", ")));
                }
                "callthis0" | "callthis1" | "callthis2" | "callthis3" | "callthis0withname" | "callthis1withname" | "callthis2withname" | "callthis3withname" => {
                    let args = regs.iter().map(|index| self.register(*index)).collect::<Result<Vec<_>>>()?;
                    expression = Some(format!("acc.call({})", args.join(", ")));
                }
                "callthisrange" | "callthisrangewithname" => {
                    let this = *regs.first().ok_or_else(|| Error::invalid("missing this register"))?;
                    let count = *imms.last().ok_or_else(|| Error::invalid("missing argument count"))?;
                    let mut args = vec![self.register(this)?];
                    args.extend(self.range(this.checked_add(1).ok_or_else(|| Error::invalid("argument overflow"))?, count)?);
                    expression = Some(format!("acc.call({})", args.join(", ")));
                }
                "apply" => expression = Some(format!("acc.apply({}, {})", reg(0)?, reg(1)?)),
                "supercallthisrange" | "supercallarrowrange" | "supercallspread" | "callruntime.supercallforwardallargs" => {
                    let args = if base == "supercallspread" { format!("...{}", reg(0)?) }
                        else if base == "callruntime.supercallforwardallargs" { "...arguments".into() }
                        else { self.range(*regs.first().ok_or_else(|| Error::invalid("missing super arguments"))?, *imms.last().ok_or_else(|| Error::invalid("missing super count"))?)?.join(", ") };
                    expression = Some(match self.scope {
                        Scope::Constructor { derived: true } => format!("(__this = super({args}))"),
                        Scope::Constructor { derived: false } => format!("Reflect.construct(__proto, [{args}], __newTarget)"),
                        Scope::Function | Scope::ClassMethod => format!("Reflect.construct(Object.getPrototypeOf(__newTarget), [{args}], __newTarget)"),
                    });
                }
                "callruntime.callinit" => statements.push("acc.call(this);".into()),
                "definefunc" | "definemethod" => {
                    let offset = self.reference(ins, 1)?;
                    self.requests.push(Request::Method(offset));
                    expression = Some(if base == "definemethod" { format!("__fn_{offset}(__env, Object.getPrototypeOf(acc))") } else { format!("__fn_{offset}(__env)") });
                }
                "defineclasswithbuffer" | "callruntime.definesendableclass" => {
                    let definition = ClassDefinition { constructor: self.reference(ins, 1)?, literals: self.reference(ins, 2)?, sendable: base.starts_with("callruntime") };
                    let prototype = reg(0)?;
                    self.requests.push(Request::Class(definition));
                    expression = Some(format!("__class_{}_{}(__env, {prototype})", definition.constructor, definition.literals));
                }
                "definegettersetterbyvalue" => statements.push(format!("Object.defineProperty({}, {}, {{get: {}, set: {}, enumerable: true, configurable: true}});", reg(0)?, reg(1)?, reg(2)?, reg(3)?)),
                "createemptyobject" => expression = Some("{}".into()),
                "createobjectwithbuffer" => expression = Some(self.object(self.reference(ins, 1)?)?),
                "createobjectwithexcludedkeys" => {
                    let count = imms.first().ok_or_else(|| Error::invalid("missing excluded key count"))?.checked_add(1).ok_or_else(|| Error::invalid("excluded key count overflow"))?;
                    let keys = self.range(*regs.get(1).ok_or_else(|| Error::invalid("missing excluded key registers"))?, count)?;
                    expression = Some(format!("__exclude({}, [{}])", reg(0)?, keys.join(", ")));
                }
                "createemptyarray" => expression = Some("[]".into()),
                "createarraywithbuffer" => expression = Some(self.array(self.reference(ins, 1)?)?),
                "createregexpwithliteral" => expression = Some(format!("new RegExp({}, {})", quote(&self.string_id(ins, 1)?), quote(&regexp_flags(ins.imm(2)?)))),
                "newobjrange" => {
                    let base = *regs.first().ok_or_else(|| Error::invalid("missing constructor register"))?;
                    let count = *imms.last().ok_or_else(|| Error::invalid("missing constructor argument count"))?;
                    let args = self.range(base.checked_add(1).ok_or_else(|| Error::invalid("argument overflow"))?, count - 1)?;
                    expression = Some(format!("new ({})({})", self.register(base)?, args.join(", ")));
                }
                "newobjapply" => expression = Some(format!("new ({}) (...acc)", reg(0)?)),
                "ldobjbyname" => expression = Some(format!("acc[{}]", quote(&self.string_id(ins, 1)?))),
                "ldobjbyvalue" => expression = Some(format!("{}[acc]", reg(0)?)),
                "ldobjbyindex" => expression = Some(format!("acc[{}]", imms.last().ok_or_else(|| Error::invalid("missing property index"))?)),
                "tryldglobalbyname" | "ldglobalvar" => expression = Some(format!("__abc_global({})", quote(&self.string_id(ins, 1)?))),
                "dynamicimport" => expression = Some("import(acc)".into()),
                "stobjbyname" => {
                    let object = reg(0)?;
                    let key = quote(&self.string_id(ins, 1)?);
                    // Ark constructor field initializers must create own properties,
                    // even when the prototype contains an accessor with that name.
                    if matches!(self.scope, Scope::Constructor { .. }) && object == "__this" {
                        statements.push(own_property(&object, &key));
                    } else { statements.push(format!("{object}[{key}] = acc;")); }
                }
                "stobjbyvalue" => statements.push(format!("{}[{}] = acc;", reg(0)?, reg(1)?)),
                "stobjbyindex" => statements.push(format!("{}[{}] = acc;", reg(0)?, imms.last().ok_or_else(|| Error::invalid("missing property index"))?)),
                "stownbyname" | "definefieldbyname" | "definepropertybyname" | "definefieldname" => statements.push(own_property(&reg(0)?, &quote(&self.string_id(ins, 1)?))),
                "stownbyvalue" | "stownbyvaluewithnameset" | "callruntime.definefieldbyvalue" => statements.push(own_property(&reg(0)?, &reg(1)?)),
                "stownbyindex" | "callruntime.definefieldbyindex" => statements.push(own_property(&reg(0)?, &imms.last().ok_or_else(|| Error::invalid("missing property index"))?.to_string())),
                "stglobalvar" => statements.push(format!("globalThis[{}] = acc;", quote(&self.string_id(ins, 1)?))),
                "trystglobalbyname" => statements.push(format!("__abc_global_store({}, acc);", quote(&self.string_id(ins, 1)?))),
                "sttoglobalrecord" | "stconsttoglobalrecord" => statements.push(format!("__abc_record_store({}, acc);", quote(&self.string_id(ins, 1)?))),
                "starrayspread" => expression = Some(format!("({}.splice({}, 0, ...acc), {} + acc.length)", reg(0)?, reg(1)?, reg(1)?)),
                "delobjprop" => expression = Some(format!("delete {}[acc]", reg(0)?)),
                "ldsuperbyname" => {
                    let key = quote(&self.string_id(ins, 1)?);
                    expression = Some(if matches!(self.scope, Scope::Function) { format!("Reflect.get(__home, {key}, this)") } else { format!("super[{key}]") });
                }
                "ldsuperbyvalue" => expression = Some(if matches!(self.scope, Scope::Function) { "Reflect.get(__home, acc, this)".into() } else { "super[acc]".into() }),
                "stsuperbyname" => {
                    let key = quote(&self.string_id(ins, 1)?);
                    statements.push(if matches!(self.scope, Scope::Function) { format!("Reflect.set(__home, {key}, acc, this);") } else { format!("super[{key}] = acc;") });
                }
                "stsuperbyvalue" => {
                    let key = reg(1)?;
                    statements.push(if matches!(self.scope, Scope::Function) { format!("Reflect.set(__home, {key}, acc, this);") } else { format!("super[{key}] = acc;") });
                }
                "setobjectwithproto" => statements.push(format!("Object.setPrototypeOf(acc, {});", reg(0)?)),
                "copydataproperties" => statements.push(format!("Object.assign({}, acc);", reg(0)?)),
                "copyrestargs" => expression = Some(format!("Array.prototype.slice.call(arguments, {})", imms.first().ok_or_else(|| Error::invalid("missing rest argument index"))?.saturating_sub(3))),
                "newlexenv" | "newlexenvwithname" | "callruntime.newsendableenv" | "callruntime.widenewsendableenv" => statements.push("__env = {parent: __env, slots: []};".into()),
                "poplexenv" => statements.push("__env = __env.parent;".into()),
                "ldlexvar" | "stlexvar" | "callruntime.ldsendablevar" | "callruntime.wideldsendablevar" | "callruntime.stsendablevar" | "callruntime.widestsendablevar" => {
                    let level = *imms.first().ok_or_else(|| Error::invalid("missing lexical level"))?;
                    if !(0..=64).contains(&level) { return Err(Error::invalid("lexical depth exceeds 64")); }
                    let slot = imms.get(1).ok_or_else(|| Error::invalid("missing lexical slot"))?;
                    let binding = format!("__env{}.slots[{slot}]", ".parent".repeat(usize::try_from(level).map_err(|_| Error::invalid("invalid lexical level"))?));
                    if base.starts_with("st") || base.contains("stsendable") { statements.push(format!("{binding} = acc;")); }
                    else { expression = Some(binding); }
                }
                "stmodulevar" | "ldlocalmodulevar" => {
                    let index = usize::try_from(ins.imm(0)?).map_err(|_| Error::invalid("invalid module slot"))?;
                    let local = self.module.exports.get(index).and_then(|entry| entry.local.as_deref()).ok_or_else(|| Error::invalid("module export slot missing"))?;
                    let local = binding_name(local);
                    if base == "stmodulevar" { self.requests.push(Request::ModuleStore(index)); statements.push(format!("{local} = acc;")); } else { expression = Some(local); }
                }
                "ldexternalmodulevar" | "callruntime.ldlazymodulevar" | "callruntime.wideldlazymodulevar" | "callruntime.ldsendableexternalmodulevar" | "callruntime.wideldsendableexternalmodulevar" | "callruntime.ldlazysendablemodulevar" | "callruntime.wideldlazysendablemodulevar" => {
                    let index = usize::try_from(ins.imm(0)?).map_err(|_| Error::invalid("invalid import slot"))?;
                    let import = self.module.imports.get(index).ok_or_else(|| Error::invalid("module import slot missing"))?;
                    expression = Some(self.module.import_binding(index, &import.local));
                }
                "getmodulenamespace" => {
                    let index = usize::try_from(ins.imm(0)?).map_err(|_| Error::invalid("invalid namespace slot"))?;
                    if index >= self.module.requests.len() { return Err(Error::invalid("namespace request missing")); }
                    expression = Some(format!("__namespace_{index}"));
                }
                "getiterator" => expression = Some("acc[Symbol.iterator]()".into()),
                "getpropiterator" => expression = Some("Object.keys(acc)[Symbol.iterator]()".into()),
                "getasynciterator" => expression = Some("(acc[Symbol.asyncIterator] || acc[Symbol.iterator]).call(acc)".into()),
                "getnextpropname" => expression = Some(format!("{}.next().value", reg(0)?)),
                "closeiterator" => statements.push(format!("if ({}.return) {}.return();", reg(0)?, reg(0)?)),
                "asyncfunctionenter" => expression = Some("undefined".into()),
                "asyncfunctionawaituncaught" => expression = Some(format!("(__resume = await {})", if name.starts_with("deprecated.") { reg(1)? } else { "acc".into() })),
                "asyncfunctionresolve" => exit = Some(Exit::Return(if name.starts_with("deprecated.") { reg(1)? } else { "acc".into() })),
                "asyncfunctionreject" => exit = Some(Exit::Throw(if name.starts_with("deprecated.") { reg(1)? } else { "acc".into() })),
                "suspendgenerator" if self.async_function => {}
                "resumegenerator" if self.async_function => expression = Some("__resume".into()),
                "getresumemode" if self.async_function => expression = Some("0".into()),
                "creategeneratorobj" if self.generator_function => expression = Some("__generator".into()),
                "createiterresultobj" => expression = Some(format!("{{value: {}, done: {}}}", reg(0)?, reg(1)?)),
                "suspendgenerator" if self.generator_function => exit = Some(Exit::Suspend { value: if name.starts_with("deprecated.") { reg(1)? } else { "acc".into() }, next: ins.next_pc }),
                "resumegenerator" if self.generator_function => expression = Some("__resume".into()),
                "getresumemode" if self.generator_function => expression = Some("__resumeMode".into()),
                "callruntime.ldsendableclass" => expression = Some("this".into()),
                "callruntime.topropertykey" => expression = Some("typeof acc === \"symbol\" ? acc : String(acc)".into()),
                "throw.undefinedifholewithname" => statements.push(format!("if (acc === __hole) throw new ReferenceError({});", quote(&self.string_id(ins, 0)?))),
                "throw.undefinedifhole" => statements.push(format!("if ({} === __hole) throw new ReferenceError(\"Uninitialized binding\");", reg(0)?)),
                "throw.ifnotobject" => statements.push("if (acc === null || (typeof acc !== \"object\" && typeof acc !== \"function\")) throw new TypeError(\"Expected object\");".into()),
                "throw.constassignment" => exit = Some(Exit::Throw("new TypeError(\"Assignment to constant binding\")".into())),
                "throw.patternnoncoercible" => statements.push("if (acc == null) throw new TypeError(\"Cannot destructure null or undefined\");".into()),
                "throw.notexists" => exit = Some(Exit::Throw("new TypeError(\"Iterator method is missing\")".into())),
                "throw.deletesuperproperty" => exit = Some(Exit::Throw("new ReferenceError(\"Cannot delete super property\")".into())),
                "throw.ifsupernotcorrectcall" | "throw.ifthsupernotcorrectcall" => {}
                "nop" | "callruntime.notifyconcurrentresult" => {}
                "debugger" => statements.push("debugger;".into()),
                _ => return Err(unsupported(ins)),
            }
        }
        if let Some(expression) = expression {
            statements.push(format!("acc = {expression};"));
        }
        Ok(Lowered {
            pc: ins.pc,
            next: ins.next_pc,
            statements,
            exit,
        })
    }
}

fn unsupported(ins: &Instruction) -> Error {
    Error::UnsupportedInstruction {
        name: ins.opcode.name.into(),
        pc: ins.pc,
    }
}

fn own_property(object: &str, key: &str) -> String {
    format!("Object.defineProperty({object}, {key}, {{value: acc, writable: true, enumerable: true, configurable: true}});")
}

pub(crate) fn quote(text: &str) -> String {
    format!(
        "\"{}\"",
        text.chars()
            .flat_map(char::escape_default)
            .collect::<String>()
    )
}

pub(crate) fn identifier(text: &str) -> String {
    const KEYWORDS: &[&str] = &[
        "await",
        "arguments",
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "enum",
        "eval",
        "export",
        "extends",
        "false",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "let",
        "new",
        "null",
        "return",
        "static",
        "super",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "typeof",
        "var",
        "void",
        "while",
        "with",
        "yield",
    ];
    let valid = !text.is_empty()
        && text.chars().enumerate().all(|(index, ch)| {
            ch == '_' || ch == '$' || ch.is_ascii_alphabetic() || (index > 0 && ch.is_ascii_digit())
        });
    if valid && !KEYWORDS.contains(&text) {
        text.to_string()
    } else {
        format!(
            "__name_{}",
            text.as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    }
}

pub(crate) fn binding_name(text: &str) -> String {
    let name = identifier(text);
    let register = name
        .strip_prefix(['v', 'p'])
        .is_some_and(|tail| !tail.is_empty() && tail.bytes().all(|byte| byte.is_ascii_digit()));
    if name == "acc" || name.starts_with("__") || register {
        format!(
            "__binding_{}",
            text.as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )
    } else {
        name
    }
}

fn regexp_flags(flags: i64) -> String {
    [(1, 'g'), (2, 'i'), (4, 'm'), (8, 's'), (16, 'u'), (32, 'y')]
        .into_iter()
        .filter_map(|(flag, ch)| (flags & flag != 0).then_some(ch))
        .collect()
}

impl Module {
    pub(crate) fn import_binding(&self, index: usize, local: &str) -> String {
        let name = binding_name(local);
        if self.exports.iter().any(|export| {
            export.path.is_none()
                && export
                    .local
                    .as_deref()
                    .is_some_and(|local| binding_name(local) == name)
        }) {
            format!("__import_{index}")
        } else {
            name
        }
    }
}
