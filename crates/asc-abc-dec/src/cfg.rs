use std::collections::{BTreeMap, BTreeSet};

use crate::{Error, Result, SizeBudget};

#[derive(Clone, Debug)]
pub(crate) enum Exit {
    Goto(u32),
    Branch { test: String, yes: u32, no: u32 },
    Return(String),
    Throw(String),
    Suspend { value: String, next: u32 },
    End,
}

#[derive(Clone, Debug)]
pub(crate) struct Lowered {
    pub pc: u32,
    pub next: u32,
    pub statements: Vec<String>,
    pub exit: Option<Exit>,
}

impl Lowered {
    pub fn charge(&self, budget: &mut SizeBudget) -> Result<()> {
        budget.charge(std::mem::size_of::<Self>())?;
        for statement in &self.statements {
            budget.charge(std::mem::size_of::<String>())?;
            budget.charge(statement.len())?;
        }
        if let Some(exit) = &self.exit {
            let text = match exit {
                Exit::Branch { test, .. } => test,
                Exit::Return(text) | Exit::Throw(text) => text,
                Exit::Suspend { value, .. } => value,
                Exit::Goto(_) | Exit::End => return Ok(()),
            };
            budget.charge(text.len())?;
        }
        Ok(())
    }
}

struct Block {
    pc: u32,
    exit_pc: u32,
    statements: Vec<(u32, String)>,
    exit: Exit,
}

pub(crate) struct Catch {
    pub start: u32,
    pub end: u32,
    pub handler: u32,
    pub test: Option<String>,
}

pub(crate) struct Graph {
    blocks: Vec<Block>,
    indices: BTreeMap<u32, usize>,
}

impl Graph {
    pub fn build(instructions: Vec<Lowered>, size: u32, boundaries: &[u32]) -> Result<Self> {
        let valid: BTreeSet<_> = instructions
            .iter()
            .map(|instruction| instruction.pc)
            .chain([size])
            .collect();
        let mut leaders = BTreeSet::from([0, size]);
        leaders.extend(boundaries.iter().copied());
        for instruction in &instructions {
            if let Some(exit) = &instruction.exit {
                leaders.insert(instruction.next);
                match exit {
                    Exit::Goto(pc) => {
                        leaders.insert(*pc);
                    }
                    Exit::Branch { yes, no, .. } => {
                        leaders.extend([*yes, *no]);
                    }
                    Exit::Suspend { next, .. } => {
                        leaders.insert(*next);
                    }
                    Exit::Return(_) | Exit::Throw(_) | Exit::End => {}
                }
            }
        }
        if !leaders.is_subset(&valid) {
            return Err(Error::invalid(
                "control flow targets the middle of an instruction",
            ));
        }
        if leaders.len() > 4096 {
            return Err(Error::invalid("method exceeds 4096 basic blocks"));
        }
        let mut blocks = Vec::new();
        let mut pending: Option<Block> = None;
        for instruction in instructions {
            if leaders.contains(&instruction.pc) {
                if let Some(mut previous) = pending.take() {
                    if matches!(previous.exit, Exit::End) {
                        previous.exit = Exit::Goto(instruction.pc);
                    }
                    blocks.push(previous);
                }
                pending = Some(Block {
                    pc: instruction.pc,
                    exit_pc: instruction.pc,
                    statements: Vec::new(),
                    exit: Exit::End,
                });
            }
            let block = pending
                .as_mut()
                .ok_or_else(|| Error::invalid("missing entry block"))?;
            block.statements.extend(
                instruction
                    .statements
                    .into_iter()
                    .map(|statement| (instruction.pc, statement)),
            );
            block.exit_pc = instruction.pc;
            if let Some(exit) = instruction.exit {
                block.exit = exit;
            }
        }
        if let Some(mut block) = pending {
            if matches!(block.exit, Exit::End) {
                block.exit = Exit::Goto(size);
            }
            blocks.push(block);
        }
        blocks.push(Block {
            pc: size,
            exit_pc: size,
            statements: Vec::new(),
            exit: Exit::End,
        });
        let indices = blocks
            .iter()
            .enumerate()
            .map(|(index, block)| (block.pc, index))
            .collect();
        Ok(Self { blocks, indices })
    }

    fn successors(&self, index: usize) -> Vec<usize> {
        let exit = self.blocks.len() - 1;
        match &self.blocks[index].exit {
            Exit::Goto(pc) | Exit::Suspend { next: pc, .. } => vec![self.indices[pc]],
            Exit::Branch { yes, no, .. } => vec![self.indices[yes], self.indices[no]],
            Exit::Return(_) | Exit::Throw(_) if index != exit => vec![exit],
            Exit::Return(_) | Exit::Throw(_) | Exit::End => Vec::new(),
        }
    }

    fn reachable(&self, start: usize, target: usize) -> bool {
        let mut pending = vec![start];
        let mut visited = BTreeSet::new();
        while let Some(index) = pending.pop() {
            if index == target {
                return true;
            }
            if visited.insert(index) {
                pending.extend(self.successors(index));
            }
        }
        false
    }

    fn copy_tail(&self, mut start: usize, stop: usize) -> bool {
        let mut visited = BTreeSet::new();
        while start != stop {
            if !visited.insert(start)
                || !self.blocks[start]
                    .statements
                    .iter()
                    .all(|(_, statement)| copy_statement(statement))
            {
                return false;
            }
            let Exit::Goto(pc) = self.blocks[start].exit else {
                return false;
            };
            start = self.indices[&pc];
        }
        true
    }

    fn terminal_path(&self, mut start: usize) -> bool {
        let mut visited = BTreeSet::new();
        while visited.insert(start) {
            match &self.blocks[start].exit {
                Exit::Goto(pc) => start = self.indices[pc],
                Exit::Return(_) | Exit::Throw(_) => return true,
                Exit::Branch { .. } | Exit::Suspend { .. } | Exit::End => return false,
            }
        }
        false
    }

    pub fn emit(&self, catches: &[Catch]) -> String {
        if let Some(structured) = self.structured(catches) {
            return structured;
        }
        format!(
            "// Control flow retained as a dispatcher.\nlet __pc = 0, __at = 0;\n{}",
            self.dispatcher(catches, Flow::Function)
        )
    }

    pub fn emit_generator(&self, catches: &[Catch]) -> String {
        let mut out = String::from("let __pc = 0, __at = 0, __resumeMode = 0, __done = false, __running = false;\nconst __generator = {\n    [Symbol.iterator]() { return this; },\n    next(value) { return __step(0, value); },\n    throw(value) { return __step(1, value); },\n    return(value) { return __step(2, value); }\n};\nfunction __step(mode, value) {\n    if (__running) throw new TypeError('Generator is already running');\n    if (__done) {\n        if (mode === 1) throw value;\n        return {value: mode === 2 ? value : undefined, done: true};\n    }\n    __resumeMode = mode; __resume = value; __running = true;\n    try {\n");
        line(&mut out, 2, &self.dispatcher(catches, Flow::Generator));
        out.push_str(
            "    } finally { __running = false; }\n}\n__step(0, undefined);\nreturn __generator;\n",
        );
        out
    }

    fn structured(&self, catches: &[Catch]) -> Option<String> {
        let count = self.blocks.len();
        let all = Bits::full(count);
        let mut post = vec![all.clone(); count];
        post[count - 1] = Bits::single(count, count - 1);
        for round in 0..=256 {
            if round == 256 {
                return None;
            }
            let mut changed = false;
            for index in (0..count - 1).rev() {
                let successors = self.successors(index);
                let mut next = all.clone();
                for successor in successors {
                    next.intersect(&post[successor]);
                }
                next.insert(index);
                if next != post[index] {
                    post[index] = next;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let mut predecessors = vec![Vec::new(); count];
        for index in 0..count {
            for successor in self.successors(index) {
                predecessors[successor].push(index);
            }
        }
        let mut dominators = vec![all.clone(); count];
        dominators[0] = Bits::single(count, 0);
        for round in 0..=256 {
            if round == 256 {
                return None;
            }
            let mut changed = false;
            for index in 1..count {
                let mut next = all.clone();
                if predecessors[index].is_empty() {
                    next.clear();
                }
                for &predecessor in &predecessors[index] {
                    next.intersect(&dominators[predecessor]);
                }
                next.insert(index);
                if next != dominators[index] {
                    dominators[index] = next;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let mut loops: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for (tail, dominated) in dominators.iter().enumerate() {
            for head in self.successors(tail) {
                if !dominated.contains(head) {
                    continue;
                }
                let nodes = loops.entry(head).or_insert_with(|| BTreeSet::from([head]));
                let mut pending = vec![tail];
                while let Some(node) = pending.pop() {
                    if nodes.insert(node) {
                        pending.extend(predecessors[node].iter().copied());
                    }
                }
            }
        }
        let mut loop_exits = BTreeMap::new();
        for (&head, nodes) in &loops {
            let exits: BTreeSet<_> = nodes
                .iter()
                .flat_map(|node| self.successors(*node))
                .filter(|successor| !nodes.contains(successor))
                .collect();
            if exits.len() > 1 {
                return None;
            }
            loop_exits.insert(head, exits.first().copied().unwrap_or(count - 1));
        }
        let mut writer = Structured {
            graph: self,
            post,
            loop_exits,
            visited: BTreeSet::new(),
            out: String::new(),
            budget: count * 4,
            catches,
            active_tries: BTreeSet::new(),
            emitted_tries: BTreeSet::new(),
        };
        writer.region(0, count - 1, None, 0, 0).ok()?;
        Some(writer.out)
    }

    fn dispatcher(&self, catches: &[Catch], mode: Flow) -> String {
        let mut out = String::from("while (true) {\n");
        let guarded = !catches.is_empty() || mode == Flow::Generator;
        let base = if !guarded {
            1
        } else {
            line(&mut out, 1, "try {");
            2
        };
        line(&mut out, base, "switch (__pc) {");
        for block in &self.blocks {
            line(&mut out, base + 1, &format!("case {}:", block.pc));
            for (pc, statement) in &block.statements {
                if guarded {
                    line(&mut out, base + 2, &format!("__at = {pc};"));
                }
                line(&mut out, base + 2, statement);
            }
            let statement = match &block.exit {
                Exit::Goto(pc) => format!("__pc = {pc}; continue;"),
                Exit::Branch { test, yes, no } => {
                    format!("__pc = ({test}) ? {yes} : {no}; continue;")
                }
                Exit::Return(value) if mode == Flow::Generator => format!(
                    "__done = true; return __result({}, true);",
                    if value.is_empty() { "undefined" } else { value }
                ),
                Exit::Return(value) => format!("return {value};"),
                Exit::Throw(value) => format!("throw {value};"),
                Exit::Suspend { value, next } => {
                    format!("__pc = {next}; return __result({value}, false);")
                }
                Exit::End if mode == Flow::Generator => {
                    "__done = true; return {value: undefined, done: true};".into()
                }
                Exit::End => "return;".into(),
            };
            if guarded {
                line(&mut out, base + 2, &format!("__at = {};", block.exit_pc));
            }
            line(&mut out, base + 2, &statement);
        }
        line(
            &mut out,
            base + 1,
            "default: throw new Error(\"Invalid bytecode pc\");",
        );
        line(&mut out, base, "}");
        if guarded {
            line(&mut out, 1, "} catch (__caught) {");
            let mut ordered: Vec<_> = catches.iter().collect();
            ordered.sort_by_key(|catch| catch.end - catch.start);
            for catch in ordered {
                let guard = catch
                    .test
                    .as_ref()
                    .map(|test| format!(" && ({test})"))
                    .unwrap_or_default();
                line(&mut out, 2, &format!("if (__at >= {} && __at < {}{guard}) {{ acc = __caught; __pc = {}; continue; }}", catch.start, catch.end, catch.handler));
            }
            if mode == Flow::Generator {
                line(&mut out, 2, "__done = true;");
            }
            line(&mut out, 2, "throw __caught;");
            line(&mut out, 1, "}");
        }
        line(&mut out, 0, "}");
        out
    }
}

struct Structured<'a> {
    graph: &'a Graph,
    post: Vec<Bits>,
    loop_exits: BTreeMap<usize, usize>,
    visited: BTreeSet<usize>,
    out: String,
    budget: usize,
    catches: &'a [Catch],
    active_tries: BTreeSet<usize>,
    emitted_tries: BTreeSet<usize>,
}

impl Structured<'_> {
    fn region(
        &mut self,
        mut index: usize,
        stop: usize,
        current_loop: Option<usize>,
        indent: usize,
        depth: usize,
    ) -> std::result::Result<(), ()> {
        if depth > 64 {
            return Err(());
        }
        while index != stop {
            if let Some((handler, _)) = self
                .catches
                .iter()
                .enumerate()
                .filter(|(handler, catch)| {
                    catch.start == self.graph.blocks[index].pc
                        && !self.active_tries.contains(handler)
                        && !self.emitted_tries.contains(handler)
                })
                .max_by_key(|(_, catch)| catch.end - catch.start)
            {
                index = self.try_region(handler, current_loop, indent, depth + 1)?;
                continue;
            }
            if let Some(head) = current_loop {
                if index == head && self.visited.contains(&index) {
                    return Ok(());
                }
                if index == self.loop_exits[&head] {
                    line(&mut self.out, indent, "break;");
                    return Ok(());
                }
            }
            if self.budget == 0 {
                return Err(());
            }
            self.budget -= 1;
            if let Some(&exit) = self.loop_exits.get(&index) {
                if current_loop != Some(index) {
                    line(&mut self.out, indent, "while (true) {");
                    self.region(index, exit, Some(index), indent + 1, depth + 1)?;
                    line(&mut self.out, indent, "}");
                    index = exit;
                    continue;
                }
            }
            if !self.visited.insert(index) && !self.graph.terminal_path(index) {
                return Err(());
            }
            let block = &self.graph.blocks[index];
            for (_, statement) in &block.statements {
                line(&mut self.out, indent, statement);
            }
            match &block.exit {
                Exit::Goto(pc) => {
                    index = self.graph.indices[pc];
                }
                Exit::Branch { test, yes, no } => {
                    let yes = self.graph.indices[yes];
                    let no = self.graph.indices[no];
                    let join = self.post[yes]
                        .iter()
                        .filter(|join| *join != index && self.post[no].contains(*join))
                        .max_by_key(|join| self.post[*join].len())
                        .ok_or(())?;
                    let terminal = |mut arm: usize| {
                        let mut seen = BTreeSet::new();
                        while arm != stop && arm != join && seen.insert(arm) {
                            match &self.graph.blocks[arm].exit {
                                Exit::Goto(pc) => arm = self.graph.indices[pc],
                                Exit::Return(_) | Exit::Throw(_) => return true,
                                Exit::Branch { .. } | Exit::Suspend { .. } | Exit::End => {
                                    return false
                                }
                            }
                        }
                        false
                    };
                    if terminal(yes) || terminal(no) {
                        let (arm, next, test) = if terminal(yes) {
                            (yes, no, test.clone())
                        } else {
                            (no, yes, format!("!({test})"))
                        };
                        line(&mut self.out, indent, &format!("if ({test}) {{"));
                        self.region(arm, stop, current_loop, indent + 1, depth + 1)?;
                        line(&mut self.out, indent, "}");
                        index = next;
                        continue;
                    }
                    if let Some(head) = current_loop {
                        let exit = self.loop_exits[&head];
                        if yes == exit || no == exit {
                            let guard = if yes == exit {
                                test.clone()
                            } else {
                                format!("!({test})")
                            };
                            line(&mut self.out, indent, &format!("if ({guard}) break;"));
                            index = if yes == exit { no } else { yes };
                            continue;
                        }
                    }
                    line(&mut self.out, indent, &format!("if ({test}) {{"));
                    self.region(yes, join, current_loop, indent + 1, depth + 1)?;
                    if no != join {
                        line(&mut self.out, indent, "} else {");
                        self.region(no, join, current_loop, indent + 1, depth + 1)?;
                    }
                    line(&mut self.out, indent, "}");
                    index = join;
                }
                Exit::Return(value) => {
                    line(&mut self.out, indent, &format!("return {value};"));
                    return Ok(());
                }
                Exit::Throw(value) => {
                    line(&mut self.out, indent, &format!("throw {value};"));
                    return Ok(());
                }
                Exit::Suspend { .. } => return Err(()),
                Exit::End => return Ok(()),
            }
        }
        Ok(())
    }

    fn try_region(
        &mut self,
        handler: usize,
        current_loop: Option<usize>,
        indent: usize,
        depth: usize,
    ) -> std::result::Result<usize, ()> {
        let catch = &self.catches[handler];
        let start = self.graph.indices[&catch.start];
        let mut end = self.graph.indices[&catch.end];
        if !self.graph.reachable(start, end) {
            end = self.graph.blocks.len() - 1;
        } else {
            let mut visited = BTreeSet::new();
            while visited.insert(end) && self.graph.blocks[end].statements.is_empty() {
                let Exit::Goto(pc) = self.graph.blocks[end].exit else {
                    break;
                };
                end = self.graph.indices[&pc];
            }
        }
        let handlers: Vec<_> = self
            .catches
            .iter()
            .enumerate()
            .filter(|(_, other)| other.start == catch.start && other.end == catch.end)
            .map(|(index, _)| index)
            .collect();
        let mut common = self.post[end].clone();
        for &handler in &handlers {
            let arm = self.graph.indices[&self.catches[handler].handler];
            common.intersect(&self.post[arm]);
        }
        let mut join = common
            .iter()
            .max_by_key(|join| self.post[*join].len())
            .ok_or(())?;
        if join == self.graph.blocks.len() - 1
            && handlers.iter().all(|handler| {
                self.graph
                    .terminal_path(self.graph.indices[&self.catches[*handler].handler])
            })
        {
            join = end;
        }
        // Compiler phi copies belong to the successful path. Emitting them
        // after catch would overwrite values preserved by the exceptional path.
        // Move only nonthrowing copies across the bytecode's protected boundary.
        if !self.graph.copy_tail(end, join) {
            return Err(());
        }
        self.active_tries.extend(handlers.iter().copied());
        line(&mut self.out, indent, "try {");
        self.region(start, end, current_loop, indent + 1, depth)?;
        self.region(end, join, current_loop, indent + 1, depth)?;
        line(&mut self.out, indent, "} catch (__caught) {");
        let mut catch_all = false;
        let mut conditional = false;
        for &handler in &handlers {
            if catch_all {
                break;
            }
            let catch = &self.catches[handler];
            let arm = self.graph.indices[&catch.handler];
            let nested = if let Some(test) = &catch.test {
                let branch = if conditional { "else if" } else { "if" };
                line(&mut self.out, indent + 1, &format!("{branch} ({test}) {{"));
                conditional = true;
                1
            } else {
                catch_all = true;
                if conditional {
                    line(&mut self.out, indent + 1, "else {");
                    1
                } else {
                    0
                }
            };
            line(&mut self.out, indent + 1 + nested, "acc = __caught;");
            self.region(arm, join, current_loop, indent + 1 + nested, depth)?;
            if nested != 0 {
                line(&mut self.out, indent + 1, "}");
            }
        }
        if !catch_all {
            if conditional {
                line(&mut self.out, indent + 1, "else { throw __caught; }");
            } else {
                line(&mut self.out, indent + 1, "throw __caught;");
            }
        }
        line(&mut self.out, indent, "}");
        for handler in handlers {
            self.active_tries.remove(&handler);
            self.emitted_tries.insert(handler);
        }
        Ok(join)
    }
}

fn copy_statement(statement: &str) -> bool {
    let Some((target, value)) = statement
        .strip_suffix(';')
        .and_then(|statement| statement.split_once(" = "))
    else {
        return false;
    };
    let register = |name: &str| {
        name == "acc"
            || name.strip_prefix('v').is_some_and(|tail| {
                !tail.is_empty() && tail.bytes().all(|byte| byte.is_ascii_digit())
            })
    };
    register(target)
        && (register(value)
            || matches!(value, "__hole" | "undefined" | "null" | "true" | "false")
            || value.parse::<f64>().is_ok())
}

pub(crate) fn line(out: &mut String, indent: usize, text: &str) {
    for text in text.lines() {
        out.push_str(&"    ".repeat(indent));
        out.push_str(text);
        out.push('\n');
    }
}

/// Compact sets keep dominance analysis bounded even on thousands of blocks.
#[derive(Clone, PartialEq, Eq)]
struct Bits {
    words: Vec<u64>,
    size: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    Function,
    Generator,
}

impl Bits {
    fn full(size: usize) -> Self {
        Self {
            words: vec![u64::MAX; size.div_ceil(64)],
            size,
        }
    }
    fn single(size: usize, index: usize) -> Self {
        let mut set = Self {
            words: vec![0; size.div_ceil(64)],
            size,
        };
        set.insert(index);
        set
    }
    fn insert(&mut self, index: usize) {
        self.words[index / 64] |= 1 << (index % 64);
    }
    fn contains(&self, index: usize) -> bool {
        self.words[index / 64] & (1 << (index % 64)) != 0
    }
    fn clear(&mut self) {
        self.words.fill(0);
    }
    fn intersect(&mut self, other: &Self) {
        for (word, other) in self.words.iter_mut().zip(&other.words) {
            *word &= other;
        }
    }
    fn len(&self) -> usize {
        self.iter().count()
    }
    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.size).filter(|index| self.contains(*index))
    }
}

#[cfg(test)]
mod tests {
    use super::{Catch, Exit, Graph, Lowered};

    #[test]
    fn typed_handlers_select_the_first_match_and_rethrow_unmatched_values() {
        let instructions = [
            Exit::Throw("p0".into()),
            Exit::Return("'normal'".into()),
            Exit::Return("'type'".into()),
            Exit::Return("'error'".into()),
        ]
        .into_iter()
        .enumerate()
        .map(|(pc, exit)| Lowered {
            pc: u32::try_from(pc).unwrap(),
            next: u32::try_from(pc + 1).unwrap(),
            statements: Vec::new(),
            exit: Some(exit),
        })
        .collect();
        let catches = [
            Catch {
                start: 0,
                end: 1,
                handler: 2,
                test: Some("__caught instanceof TypeError".into()),
            },
            Catch {
                start: 0,
                end: 1,
                handler: 3,
                test: Some("__caught instanceof Error".into()),
            },
        ];
        let graph = Graph::build(instructions, 4, &[0, 1, 2, 3]).unwrap();
        let body = graph.emit(&catches);
        assert!(!body.contains("__pc"), "{body}");
        let source = format!("function run(p0) {{ let acc; {body} }} let unmatched; try {{ run({{}}); }} catch(e) {{ unmatched='unmatched'; }} globalThis.result=[run(new TypeError()),run(new Error()),unmatched];");
        if let Some(output) = crate::optimize::tests::execute(&source) {
            assert_eq!(output, r#"["type","error","unmatched"]"#, "{body}");
        }
    }
}
