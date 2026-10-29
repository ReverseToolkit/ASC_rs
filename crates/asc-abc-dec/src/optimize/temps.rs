use std::collections::BTreeSet;

use oxc::allocator::{Allocator, CloneIn, Vec};
use oxc::ast::{ast::*, AstBuilder};
use oxc::ast_visit::{walk, walk_mut, Visit, VisitMut};
use oxc::span::SPAN;
use oxc::syntax::{operator::AssignmentOperator, scope::ScopeFlags};

use super::analysis::{first_effect_is_use, pure, temporary, Locals, Usage};

pub(super) struct Temps<'a> {
    ast: AstBuilder<'a>,
    usage: Usage,
    loop_live: BTreeSet<String>,
    classes: BTreeSet<String>,
    constants: BTreeSet<String>,
    owned: BTreeSet<String>,
    outgoing: BTreeSet<String>,
    exception_live: BTreeSet<String>,
    pub changed: bool,
}

impl<'a> Temps<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            usage: Usage::default(),
            loop_live: BTreeSet::new(),
            classes: BTreeSet::new(),
            constants: BTreeSet::new(),
            owned: BTreeSet::new(),
            outgoing: BTreeSet::new(),
            exception_live: BTreeSet::new(),
            changed: false,
        }
    }

    fn simplify(&mut self, body: &mut Vec<'a, Statement<'a>>) {
        let mut live_out = self.outgoing.clone();
        live_out.extend(self.loop_live.iter().cloned());
        let mut index = body.len();
        while index != 0 {
            index -= 1;
            let Some((target, value)) = assignment(&body[index]) else {
                continue;
            };
            if temporary(target)
                && self.owned.contains(target)
                && matches!(value, Expression::Identifier(identifier) if identifier.name == target)
            {
                body[index] = self.ast.statement_empty(SPAN);
                self.changed = true;
                continue;
            }
            if !temporary(target)
                || !self.owned.contains(target)
                || self.usage.captured.contains(target)
                || self.exception_live.contains(target)
            {
                continue;
            }
            let target = target.to_string();
            let value = value.clone_in(self.ast.allocator);
            if let Some(Statement::IfStatement(branch)) = body.get(index + 1) {
                let after = before_list(&body[index + 2..], live_out.clone());
                let yes = before(&branch.consequent, after.clone());
                let no = branch
                    .alternate
                    .as_ref()
                    .map_or(after.clone(), |alternate| before(alternate, after));
                if Usage::expression(&branch.test).count(&target) == 1
                    && !yes.contains(&target)
                    && !no.contains(&target)
                    && first_effect_is_use(&body[index + 1], &target)
                {
                    if let Statement::IfStatement(branch) = &mut body[index + 1] {
                        Replace {
                            ast: self.ast,
                            name: &target,
                            value: &value,
                        }
                        .visit_expression(&mut branch.test);
                    }
                    body[index] = self.ast.statement_empty(SPAN);
                    self.changed = true;
                    continue;
                }
            }
            if self.stable(&value) {
                let dependencies = Usage::eager_expression(&value);
                let mut consumers = std::vec::Vec::new();
                let mut overwritten = false;
                let mut valid = true;
                for (offset, statement) in body[index + 1..].iter().enumerate() {
                    let usage = Usage::statement(statement);
                    if usage.writes.contains(&target)
                        && !assignment(statement).is_some_and(|(name, _)| name == target)
                    {
                        let outgoing = before_list(&body[index + offset + 2..], live_out.clone());
                        if overwrite_before_use(statement, &target, outgoing) {
                            overwritten = true;
                            break;
                        }
                        valid = false;
                        break;
                    }
                    if usage
                        .writes
                        .iter()
                        .any(|name| dependencies.count(name) != 0)
                    {
                        valid = false;
                        break;
                    }
                    if usage.count(&target) != 0 {
                        consumers.push(index + 1 + offset);
                    }
                    if assignment(statement).is_some_and(|(name, _)| name == target) {
                        overwritten = true;
                        break;
                    }
                }
                if valid && (overwritten || !live_out.contains(&target)) && !consumers.is_empty() {
                    for consumer in consumers {
                        Replace {
                            ast: self.ast,
                            name: &target,
                            value: &value,
                        }
                        .visit_statement(&mut body[consumer]);
                    }
                    body[index] = self.ast.statement_empty(SPAN);
                    self.changed = true;
                    continue;
                }
            }
            if index + 1 < body.len() {
                if let Some((next, Expression::Identifier(copy))) = assignment(&body[index + 1]) {
                    if next.starts_with('v')
                        && temporary(next)
                        && next != target
                        && copy.name == target
                        && (target == "acc" || !self.pure(&value))
                    {
                        let next = next.to_string();
                        body[index] = self.assign(&next, value);
                        body[index + 1] = self.assign(
                            &target,
                            self.ast.expression_identifier(SPAN, self.ast.atom(&next)),
                        );
                        self.changed = true;
                        continue;
                    }
                }
            }
            let mut reads = 0;
            let mut consumer = None;
            let mut overwritten = false;
            let mut blocked = false;
            let mut uncertain_write = false;
            let dependencies = Usage::eager_expression(&value);
            for (offset, statement) in body[index + 1..].iter().enumerate() {
                let usage = Usage::statement(statement);
                if usage.writes.contains(&target)
                    && !assignment(statement).is_some_and(|(name, _)| name == target)
                {
                    uncertain_write = true;
                    break;
                }
                let count = usage.count(&target);
                if count != 0 {
                    reads += count;
                    consumer = Some(index + 1 + offset);
                }
                if assignment(statement).is_some_and(|(name, _)| name == target) {
                    overwritten = true;
                    break;
                }
                if count == 0 && reads == 0 {
                    let harmless = assignment(statement)
                        .is_some_and(|(name, value)| temporary(name) && self.pure(value));
                    let independent = self.pure(&value)
                        && dependencies.reads.keys().all(|name| {
                            self.constants.contains(name)
                                || (self.owned.contains(name)
                                    && !self.usage.captured.contains(name))
                        });
                    if (!harmless && !independent)
                        || usage
                            .writes
                            .iter()
                            .any(|name| dependencies.count(name) != 0)
                    {
                        blocked = true;
                    }
                }
                if reads > 1 {
                    break;
                }
            }
            if uncertain_write || (!overwritten && live_out.contains(&target)) {
                continue;
            }
            if reads == 0 {
                body[index] = if self.pure(&value) {
                    self.ast.statement_empty(SPAN)
                } else {
                    self.ast.statement_expression(SPAN, value)
                };
                self.changed = true;
            } else if reads == 1 && !blocked {
                let consumer = consumer.expect("one read has a consuming statement");
                // A statement's final store happens after evaluating its RHS.
                // Only writes inside that RHS can invalidate a copied input.
                let consumer_usage = assignment(&body[consumer]).map_or_else(
                    || Usage::statement(&body[consumer]),
                    |(_, value)| Usage::expression(value),
                );
                if consumer_usage
                    .writes
                    .iter()
                    .any(|name| name != &target && dependencies.count(name) != 0)
                    && !first_effect_is_use(&body[consumer], &target)
                {
                    continue;
                }
                let ordered = !self.pure(&value)
                    || dependencies.reads.keys().any(|name| {
                        self.usage.captured.contains(name) && !self.constants.contains(name)
                    });
                if ordered && !first_effect_is_use(&body[consumer], &target) {
                    continue;
                }
                Replace {
                    ast: self.ast,
                    name: &target,
                    value: &value,
                }
                .visit_statement(&mut body[consumer]);
                body[index] = self.ast.statement_empty(SPAN);
                self.changed = true;
            }
        }
        body.retain(|statement| !matches!(statement, Statement::EmptyStatement(_)));
    }

    fn assign(&self, name: &str, value: Expression<'a>) -> Statement<'a> {
        self.ast.statement_expression(
            SPAN,
            self.ast.expression_assignment(
                SPAN,
                AssignmentOperator::Assign,
                AssignmentTarget::AssignmentTargetIdentifier(
                    self.ast
                        .alloc_identifier_reference(SPAN, self.ast.atom(name)),
                ),
                value,
            ),
        )
    }

    fn pure(&self, value: &Expression<'_>) -> bool {
        pure(value) || matches!(value, Expression::Identifier(identifier) if self.classes.contains(identifier.name.as_str()) || self.constants.contains(identifier.name.as_str()))
            || value.get_member_expr().is_some_and(|member| member.static_property_name() == Some("prototype") && matches!(member.object(), Expression::Identifier(identifier) if self.classes.contains(identifier.name.as_str())))
    }

    fn stable(&self, value: &Expression<'_>) -> bool {
        match value {
            Expression::BooleanLiteral(_) | Expression::NullLiteral(_) | Expression::NumericLiteral(_) | Expression::BigIntLiteral(_) | Expression::StringLiteral(_) => true,
            Expression::Identifier(identifier) => {
                let name = identifier.name.as_str();
                if self.loop_live.contains(name) { return false; }
                (self.classes.contains(name) && !self.usage.assigned.contains(name))
                    || self.constants.contains(name)
                    || (temporary(name) && self.usage.assignments.get(name).is_some_and(|count| *count == 1))
                    || (name.starts_with("__scope_") && !self.usage.assigned.contains(name))
            }
            _ => value.get_member_expr().is_some_and(|member| member.static_property_name() == Some("prototype")
                && matches!(member.object(), Expression::Identifier(identifier) if self.classes.contains(identifier.name.as_str()) && !self.usage.assigned.contains(identifier.name.as_str()))),
        }
    }
}

impl<'a> VisitMut<'a> for Temps<'a> {
    fn visit_program(&mut self, program: &mut Program<'a>) {
        let mut classes = ClassNames::default();
        classes.visit_program(program);
        self.classes = classes.0;
        let mut constants = Constants::default();
        constants.visit_program(program);
        self.constants = constants.0;
        let mut locals = Locals::default();
        locals.visit_program(program);
        self.owned = locals.0;
        self.usage = Usage::statements(&program.body);
        walk_mut::walk_program(self, program);
    }

    fn visit_function(&mut self, function: &mut Function<'a>, flags: ScopeFlags) {
        let outer_constants = self.constants.clone();
        let mut locals = Locals::default();
        locals.visit_formal_parameters(&function.params);
        let mut constants = Constants::default();
        if let Some(body) = &function.body {
            locals.visit_function_body(body);
            constants.visit_function_body(body);
        }
        self.constants.retain(|name| !locals.0.contains(name));
        self.constants.extend(constants.0);
        let outer_owned = std::mem::replace(&mut self.owned, locals.0);
        let usage = function
            .body
            .as_ref()
            .map(|body| Usage::statements(&body.statements))
            .unwrap_or_default();
        if !usage.assigned.contains("__this") && !usage.captured.contains("__this") {
            if let Some(body) = &mut function.body {
                let value = self.ast.expression_this(SPAN);
                let initialized = body.statements.iter().any(|statement| matches!(statement,
                    Statement::VariableDeclaration(declaration) if declaration.declarations.iter().any(|declarator|
                    matches!(&declarator.id.kind, BindingPatternKind::BindingIdentifier(identifier) if identifier.name == "__this")
                    && matches!(declarator.init, Some(Expression::ThisExpression(_))))));
                if initialized {
                    for statement in &mut body.statements {
                        Replace {
                            ast: self.ast,
                            name: "__this",
                            value: &value,
                        }
                        .visit_statement(statement);
                    }
                    self.changed = true;
                }
            }
        }
        let usage = function
            .body
            .as_ref()
            .map(|body| Usage::statements(&body.statements))
            .unwrap_or_default();
        let outer = std::mem::replace(&mut self.usage, usage);
        let outer_loop = std::mem::take(&mut self.loop_live);
        let outer_outgoing = std::mem::take(&mut self.outgoing);
        let outer_exception = std::mem::take(&mut self.exception_live);
        walk_mut::walk_function(self, function, flags);
        self.usage = outer;
        self.loop_live = outer_loop;
        self.outgoing = outer_outgoing;
        self.exception_live = outer_exception;
        self.constants = outer_constants;
        self.owned = outer_owned;
    }

    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        self.simplify(statements);
        let outer = self.outgoing.clone();
        let mut live = outer.clone();
        let mut suffix = std::vec::Vec::with_capacity(statements.len());
        for statement in statements.iter().rev() {
            suffix.push(live.clone());
            live = before(statement, live);
        }
        suffix.reverse();
        for (statement, outgoing) in statements.iter_mut().zip(suffix) {
            self.outgoing = outgoing;
            self.visit_statement(statement);
        }
        self.outgoing = outer;
        statements.retain(|statement| !matches!(statement, Statement::VariableDeclaration(declaration) if declaration.declarations.is_empty()));
    }

    fn visit_try_statement(&mut self, statement: &mut TryStatement<'a>) {
        let outer = self.outgoing.clone();
        let outer_exception = self.exception_live.clone();
        let mut normal = outer.clone();
        if let Some(finalizer) = &statement.finalizer {
            normal = before_list(&finalizer.body, normal);
        }
        let mut exceptional = normal.clone();
        if let Some(handler) = &statement.handler {
            exceptional = before_list(&handler.body.body, normal.clone());
            if let Some(parameter) = &handler.param {
                if let BindingPatternKind::BindingIdentifier(identifier) = &parameter.pattern.kind {
                    exceptional.remove(identifier.name.as_str());
                }
            }
        }
        self.outgoing = normal.union(&exceptional).cloned().collect();
        self.exception_live.extend(exceptional);
        self.visit_block_statement(&mut statement.block);
        self.exception_live = outer_exception.clone();
        if statement.finalizer.is_some() {
            self.exception_live.extend(normal.iter().cloned());
        }
        self.outgoing = normal;
        if let Some(handler) = &mut statement.handler {
            self.visit_catch_clause(handler);
        }
        self.exception_live = outer_exception;
        self.outgoing = outer;
        if let Some(finalizer) = &mut statement.finalizer {
            self.visit_block_statement(finalizer);
        }
    }

    fn visit_while_statement(&mut self, statement: &mut WhileStatement<'a>) {
        let mut usage = Usage::statement(&statement.body);
        for name in Usage::expression(&statement.test).reads.into_keys() {
            usage.reads.entry(name).or_default();
        }
        let outer = self.loop_live.clone();
        self.loop_live.extend(usage.reads.into_keys());
        walk_mut::walk_while_statement(self, statement);
        self.loop_live = outer;
    }

    fn visit_variable_declaration(&mut self, declaration: &mut VariableDeclaration<'a>) {
        walk_mut::walk_variable_declaration(self, declaration);
        declaration.declarations.retain(|declarator| {
            let BindingPatternKind::BindingIdentifier(identifier) = &declarator.id.kind else {
                return true;
            };
            let name = identifier.name.as_str();
            let internal = temporary(name)
                || matches!(name, "__env" | "__parentEnv" | "__home" | "__hole")
                || name.starts_with("__scope_");
            let unused = internal
                && self.usage.count(name) == 0
                && !self.usage.captured.contains(name)
                && !self.usage.assigned.contains(name);
            let removable = matches!(name, "__fnObject" | "__hole")
                || declarator.init.as_ref().is_none_or(pure);
            if unused && removable {
                self.changed = true;
                false
            } else {
                true
            }
        });
    }
}

#[derive(Default)]
struct Constants(BTreeSet<String>);
impl<'a> Visit<'a> for Constants {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if declarator.kind == VariableDeclarationKind::Const {
            if let BindingPatternKind::BindingIdentifier(identifier) = &declarator.id.kind {
                self.0.insert(identifier.name.to_string());
            }
        }
        walk::walk_variable_declarator(self, declarator);
    }
    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        let _ = (function, flags);
    }
    fn visit_arrow_function_expression(&mut self, function: &ArrowFunctionExpression<'a>) {
        let _ = function;
    }
    fn visit_class(&mut self, class: &Class<'a>) {
        let _ = class;
    }
}

#[derive(Default)]
struct ClassNames(BTreeSet<String>);
impl<'a> Visit<'a> for ClassNames {
    fn visit_class(&mut self, class: &Class<'a>) {
        if class.r#type == ClassType::ClassDeclaration {
            if let Some(name) = &class.id {
                self.0.insert(name.name.to_string());
            }
        }
        walk::walk_class(self, class);
    }
}

fn before_list(statements: &[Statement<'_>], mut live: BTreeSet<String>) -> BTreeSet<String> {
    for statement in statements.iter().rev() {
        live = before(statement, live);
    }
    live
}

fn before(statement: &Statement<'_>, mut live: BTreeSet<String>) -> BTreeSet<String> {
    match statement {
        Statement::ReturnStatement(_) | Statement::ThrowStatement(_) => live.clear(),
        Statement::BlockStatement(block) => return before_list(&block.body, live),
        Statement::IfStatement(branch) => {
            let mut arms = before(&branch.consequent, live.clone());
            arms.extend(
                branch
                    .alternate
                    .as_ref()
                    .map_or(live.clone(), |alternate| before(alternate, live)),
            );
            arms.extend(Usage::expression(&branch.test).reads.into_keys());
            return arms;
        }
        Statement::WhileStatement(statement) => {
            let after = live.clone();
            let test: BTreeSet<_> = Usage::expression(&statement.test)
                .reads
                .into_keys()
                .collect();
            live.extend(test.iter().cloned());
            for _ in 0..32 {
                let mut next = before(&statement.body, live.clone());
                next.extend(after.iter().cloned());
                next.extend(test.iter().cloned());
                if next == live {
                    break;
                }
                live = next;
            }
            return live;
        }
        Statement::TryStatement(statement) => {
            if let Some(finalizer) = &statement.finalizer {
                live = before_list(&finalizer.body, live);
            }
            let mut exceptional = if let Some(handler) = &statement.handler {
                before_list(&handler.body.body, live.clone())
            } else {
                live.clone()
            };
            if let Some(parameter) = statement
                .handler
                .as_ref()
                .and_then(|handler| handler.param.as_ref())
            {
                if let BindingPatternKind::BindingIdentifier(identifier) = &parameter.pattern.kind {
                    exceptional.remove(identifier.name.as_str());
                }
            }
            for statement in statement.block.body.iter().rev() {
                live = before(statement, live);
                // A throwing RHS has not completed its final binding store.
                // The handler/finalizer can still observe the preceding value.
                if !nonthrowing(statement) {
                    live.extend(exceptional.iter().cloned());
                }
            }
            return live;
        }
        Statement::VariableDeclaration(declaration) => {
            for declarator in &declaration.declarations {
                if let BindingPatternKind::BindingIdentifier(identifier) = &declarator.id.kind {
                    live.remove(identifier.name.as_str());
                }
            }
        }
        _ => {
            if let Some((target, _)) = assignment(statement) {
                live.remove(target);
            }
        }
    }
    live.extend(Usage::statement(statement).reads.into_keys());
    live
}

fn overwrite_before_use(statement: &Statement<'_>, name: &str, outgoing: BTreeSet<String>) -> bool {
    let Statement::TryStatement(guard) = statement else {
        return false;
    };
    if guard
        .handler
        .as_ref()
        .is_some_and(|handler| Usage::statements(&handler.body.body).count(name) != 0)
        || guard
            .finalizer
            .as_ref()
            .is_some_and(|body| Usage::statements(&body.body).count(name) != 0)
    {
        return false;
    }
    guard
        .block
        .body
        .first()
        .and_then(assignment)
        .is_some_and(|(target, value)| target == name && Usage::expression(value).count(name) == 0)
        && !before(statement, outgoing).contains(name)
}

fn nonthrowing(statement: &Statement<'_>) -> bool {
    if let Some((_, value)) = assignment(statement) {
        return pure(value);
    }
    match statement {
        Statement::EmptyStatement(_) => true,
        Statement::VariableDeclaration(declaration) => declaration
            .declarations
            .iter()
            .all(|declarator| declarator.init.as_ref().is_none_or(pure)),
        Statement::ReturnStatement(statement) => statement.argument.as_ref().is_none_or(pure),
        Statement::ExpressionStatement(statement) => pure(&statement.expression),
        _ => false,
    }
}

pub(super) fn assignment<'n, 'a>(
    statement: &'n Statement<'a>,
) -> Option<(&'n str, &'n Expression<'a>)> {
    let Statement::ExpressionStatement(statement) = statement else {
        return None;
    };
    let Expression::AssignmentExpression(expression) = &statement.expression else {
        return None;
    };
    if expression.operator != AssignmentOperator::Assign {
        return None;
    }
    let AssignmentTarget::AssignmentTargetIdentifier(identifier) = &expression.left else {
        return None;
    };
    Some((identifier.name.as_str(), &expression.right))
}

struct Replace<'a, 'n> {
    ast: AstBuilder<'a>,
    name: &'n str,
    value: &'n Expression<'a>,
}

impl<'a> VisitMut<'a> for Replace<'a, '_> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        if matches!(expression, Expression::Identifier(identifier) if identifier.name == self.name)
        {
            *expression = self.value.clone_in(self.ast.allocator);
        } else {
            walk_mut::walk_expression(self, expression);
        }
    }

    fn visit_function(&mut self, function: &mut Function<'a>, flags: ScopeFlags) {
        let _ = (function, flags);
    }

    fn visit_arrow_function_expression(&mut self, function: &mut ArrowFunctionExpression<'a>) {
        let _ = function;
    }
}
