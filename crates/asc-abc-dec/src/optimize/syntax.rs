use std::collections::BTreeSet;

use oxc::allocator::{Allocator, CloneIn, Vec};
use oxc::ast::{ast::*, AstBuilder};
use oxc::ast_visit::{walk, walk_mut, Visit, VisitMut};
use oxc::span::{ContentEq, SPAN};
use oxc::syntax::operator::{AssignmentOperator, BinaryOperator, UnaryOperator};
use oxc::syntax::scope::ScopeFlags;

use super::analysis::{first_effect_is_use, pure, temporary, Locals, Usage};
use super::temps::assignment;

pub(super) struct Syntax<'a> {
    ast: AstBuilder<'a>,
    bindings: BTreeSet<String>,
    usage: Usage,
    booleans: BTreeSet<String>,
    owned: BTreeSet<String>,
    pub changed: bool,
}

impl<'a> Syntax<'a> {
    pub fn new(allocator: &'a Allocator, program: &Program<'a>) -> Self {
        let mut bindings = Bindings::default();
        bindings.visit_program(program);
        let mut locals = Locals::default();
        locals.visit_program(program);
        Self {
            ast: AstBuilder::new(allocator),
            bindings: bindings.0,
            usage: Usage::statements(&program.body),
            booleans: BTreeSet::new(),
            owned: locals.0,
            changed: false,
        }
    }

    fn calls(&mut self, body: &mut Vec<'a, Statement<'a>>) {
        for index in 0..body.len() {
            let Some((target, value)) = assignment(&body[index]) else {
                continue;
            };
            let Some(member) = value.get_member_expr() else {
                continue;
            };
            if !temporary(target)
                || !self.owned.contains(target)
                || !stable_receiver(member.object())
            {
                continue;
            }
            if matches!(member.object(), Expression::Identifier(identifier) if self.usage.captured.contains(identifier.name.as_str()))
            {
                continue;
            }
            let target = target.to_string();
            if self.usage.count(&target) != 1 || self.usage.captured.contains(&target) {
                continue;
            }
            let value = value.clone_in(self.ast.allocator);
            let receiver = member.object().clone_in(self.ast.allocator);
            let dependency = Usage::expression(&value);
            let mut found = None;
            for (offset, statement) in body[index + 1..].iter().enumerate() {
                let usage = Usage::statement(statement);
                if usage.count(&target) != 0 {
                    if usage.count(&target) == 1 {
                        let mut matcher = CallMatch {
                            name: &target,
                            receiver: &receiver,
                            found: false,
                        };
                        matcher.visit_statement(statement);
                        if matcher.found
                            && matches!(
                                statement,
                                Statement::ExpressionStatement(_)
                                    | Statement::ReturnStatement(_)
                                    | Statement::VariableDeclaration(_)
                            )
                            && first_effect_is_use(statement, &target)
                        {
                            found = Some(index + 1 + offset);
                        }
                    }
                    break;
                }
                if usage.writes.contains(&target)
                    || usage.writes.iter().any(|name| dependency.count(name) != 0)
                    || !assignment(statement)
                        .is_some_and(|(name, value)| temporary(name) && pure(value))
                {
                    break;
                }
            }
            if let Some(consumer) = found {
                CallReplace {
                    ast: self.ast,
                    name: &target,
                    receiver: &receiver,
                    member: &value,
                }
                .visit_statement(&mut body[consumer]);
                body[index] = self.ast.statement_empty(SPAN);
                self.changed = true;
            }
        }
    }
}

impl<'a> VisitMut<'a> for Syntax<'a> {
    fn visit_program(&mut self, program: &mut Program<'a>) {
        walk_mut::walk_program(self, program);
        let usage = Usage::statements(&program.body);
        let mut imports = BTreeSet::new();
        for statement in &program.body {
            if let Statement::ImportDeclaration(import) = statement {
                if import.specifiers.as_ref().is_some_and(|specifiers| specifiers.iter().any(|specifier| !matches!(specifier,
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace) if namespace.local.name.starts_with("__namespace_") && usage.count(&namespace.local.name) == 0))) {
                    imports.insert(import.source.value.to_string());
                }
            }
        }
        program.body.retain(|statement| {
            if let Statement::ImportDeclaration(import) = statement {
                if imports.contains(import.source.value.as_str()) && import.specifiers.as_ref().is_some_and(|specifiers| specifiers.iter().all(|specifier| matches!(specifier,
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(namespace) if namespace.local.name.starts_with("__namespace_") && usage.count(&namespace.local.name) == 0))) {
                    self.changed = true; return false;
                }
            }
            true
        });
    }

    fn visit_statement(&mut self, statement: &mut Statement<'a>) {
        walk_mut::walk_statement(self, statement);
        if let Statement::IfStatement(branch) = statement {
            if empty(&branch.consequent) {
                if let Some(alternate) = branch.alternate.take() {
                    branch.test = self.ast.expression_unary(
                        SPAN,
                        UnaryOperator::LogicalNot,
                        branch.test.clone_in(self.ast.allocator),
                    );
                    branch.consequent = alternate;
                    self.changed = true;
                }
            }
        }
        if let Statement::IfStatement(branch) = statement {
            if let (
                Some((yes, Expression::BooleanLiteral(yes_value))),
                Some((no, Expression::BooleanLiteral(no_value))),
            ) = (
                one_assignment(&branch.consequent),
                branch
                    .alternate
                    .as_ref()
                    .and_then(|alternate| one_assignment(alternate)),
            ) {
                if yes == no && yes_value.value != no_value.value {
                    let mut test = branch.test.clone_in(self.ast.allocator);
                    if !boolean(&test, &self.booleans) {
                        test = self.ast.expression_unary(
                            SPAN,
                            UnaryOperator::LogicalNot,
                            self.ast
                                .expression_unary(SPAN, UnaryOperator::LogicalNot, test),
                        );
                    }
                    if !yes_value.value {
                        test = self
                            .ast
                            .expression_unary(SPAN, UnaryOperator::LogicalNot, test);
                    }
                    *statement = self.ast.statement_expression(
                        SPAN,
                        self.ast.expression_assignment(
                            SPAN,
                            AssignmentOperator::Assign,
                            AssignmentTarget::AssignmentTargetIdentifier(
                                self.ast
                                    .alloc_identifier_reference(SPAN, self.ast.atom(yes)),
                            ),
                            test,
                        ),
                    );
                    self.changed = true;
                }
            }
        }
        if let Statement::TryStatement(guard) = statement {
            if guard.finalizer.is_none() && guard.handler.as_ref().is_some_and(|handler| {
                let Some(parameter) = &handler.param else { return false; };
                let BindingPatternKind::BindingIdentifier(identifier) = &parameter.pattern.kind else { return false; };
                matches!(handler.body.body.as_slice(), [Statement::ThrowStatement(statement)] if matches!(&statement.argument, Expression::Identifier(thrown) if thrown.name == identifier.name))
            }) {
                *statement = Statement::BlockStatement(guard.block.clone_in(self.ast.allocator));
                self.changed = true;
            }
        }
        if matches!(
            statement,
            Statement::ExpressionStatement(_) | Statement::VariableDeclaration(_)
        ) {
            let assigned_boolean = assignment(statement)
                .map(|(name, value)| (name.to_string(), boolean(value, &self.booleans)));
            for name in Usage::statement(statement).writes {
                self.booleans.remove(&name);
            }
            if let Some((name, true)) = assigned_boolean {
                self.booleans.insert(name);
            }
        }
    }
    fn visit_function(&mut self, function: &mut Function<'a>, flags: ScopeFlags) {
        let usage = function
            .body
            .as_ref()
            .map(|body| Usage::statements(&body.statements))
            .unwrap_or_default();
        let outer = std::mem::replace(&mut self.usage, usage);
        let booleans = std::mem::take(&mut self.booleans);
        let mut locals = Locals::default();
        locals.visit_formal_parameters(&function.params);
        if let Some(body) = &function.body {
            locals.visit_function_body(body);
        }
        let owned = std::mem::replace(&mut self.owned, locals.0);
        walk_mut::walk_function(self, function, flags);
        if let Some(body) = &mut function.body {
            if matches!(body.statements.last(), Some(Statement::ReturnStatement(statement)) if statement.argument.is_none())
            {
                body.statements.pop();
                self.changed = true;
            }
            if function.id.as_ref().is_some_and(|name| {
                name.name.starts_with("__function_")
                    && Usage::statements(&body.statements).count(&name.name) == 0
            }) {
                function.id = None;
                self.changed = true;
            }
        }
        self.usage = outer;
        self.booleans = booleans;
        self.owned = owned;
    }
    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        self.calls(statements);
        for statement in statements.iter_mut() {
            self.visit_statement(statement);
        }
        let mut flattened = self.ast.vec();
        for statement in std::mem::replace(statements, self.ast.vec()) {
            if let Statement::BlockStatement(block) = statement {
                // Generated lexical frame names are unique across the record.
                // Keep user-facing lexical declarations inside their block.
                let safe = block.body.iter().all(|statement| match statement {
                    Statement::VariableDeclaration(declaration) => declaration.declarations.iter().all(|declarator|
                        matches!(&declarator.id.kind, BindingPatternKind::BindingIdentifier(identifier) if identifier.name.starts_with("__") || identifier.name.starts_with("local_") || temporary(&identifier.name))),
                    Statement::ClassDeclaration(_) | Statement::FunctionDeclaration(_) => false,
                    _ => true,
                });
                if safe {
                    flattened.extend(block.unbox().body);
                    self.changed = true;
                } else {
                    flattened.push(Statement::BlockStatement(block));
                }
            } else {
                flattened.push(statement);
            }
        }
        *statements = flattened;
    }

    fn visit_if_statement(&mut self, branch: &mut IfStatement<'a>) {
        self.visit_expression(&mut branch.test);
        self.condition(&mut branch.test);
        let before = self.booleans.clone();
        self.visit_statement(&mut branch.consequent);
        let yes = self.booleans.clone();
        self.booleans = before;
        if let Some(alternate) = &mut branch.alternate {
            self.visit_statement(alternate);
        }
        self.booleans = yes.intersection(&self.booleans).cloned().collect();
    }

    fn visit_while_statement(&mut self, statement: &mut WhileStatement<'a>) {
        let writes = Usage::statement(&statement.body).writes;
        self.booleans.retain(|name| !writes.contains(name));
        let before = self.booleans.clone();
        walk_mut::walk_while_statement(self, statement);
        self.condition(&mut statement.test);
        self.booleans = before.intersection(&self.booleans).cloned().collect();
    }

    fn visit_try_statement(&mut self, statement: &mut TryStatement<'a>) {
        let before = self.booleans.clone();
        self.visit_block_statement(&mut statement.block);
        let normal = self.booleans.clone();
        self.booleans = before;
        let writes = Usage::statements(&statement.block.body).writes;
        self.booleans.retain(|name| !writes.contains(name));
        if let Some(handler) = &mut statement.handler {
            self.visit_catch_clause(handler);
        }
        self.booleans = normal.intersection(&self.booleans).cloned().collect();
        if let Some(finalizer) = &mut statement.finalizer {
            self.visit_block_statement(finalizer);
        }
    }

    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if matches!(
            expression,
            Expression::CallExpression(_)
                | Expression::NewExpression(_)
                | Expression::ComputedMemberExpression(_)
                | Expression::StaticMemberExpression(_)
        ) {
            self.booleans
                .retain(|name| !self.usage.captured.contains(name));
        }
        if let Expression::LogicalExpression(logical) = expression {
            if let (Expression::BinaryExpression(left), Expression::BinaryExpression(right)) =
                (&logical.left, &logical.right)
            {
                if left.left.content_eq(&right.left)
                    && matches!(&left.left, Expression::Identifier(identifier) if self.booleans.contains(identifier.name.as_str()))
                    && matches!(&left.right, Expression::NumericLiteral(value) if value.value == 0.0)
                    && matches!(&right.right, Expression::BooleanLiteral(value) if !value.value)
                {
                    let value = left.left.clone_in(self.ast.allocator);
                    if logical.operator.as_str() == "&&"
                        && left.operator.as_str() == "!=="
                        && right.operator.as_str() == "!=="
                    {
                        *expression = value;
                        self.changed = true;
                    } else if logical.operator.as_str() == "||"
                        && left.operator.as_str() == "==="
                        && right.operator.as_str() == "==="
                    {
                        *expression =
                            self.ast
                                .expression_unary(SPAN, UnaryOperator::LogicalNot, value);
                        self.changed = true;
                    }
                }
            }
        }
        if let Expression::ComputedMemberExpression(member) = expression {
            if let Expression::StringLiteral(property) = &member.expression {
                if property_identifier(&property.value) {
                    *expression = Expression::StaticMemberExpression(
                        self.ast.alloc_static_member_expression(
                            SPAN,
                            member.object.clone_in(self.ast.allocator),
                            self.ast.identifier_name(SPAN, property.value),
                            member.optional,
                        ),
                    );
                    self.changed = true;
                }
            }
        }
        if let Expression::UnaryExpression(unary) = expression {
            if unary.operator == UnaryOperator::LogicalNot {
                if let Expression::BinaryExpression(binary) = &unary.argument {
                    let inverse = match binary.operator {
                        BinaryOperator::Equality => Some(BinaryOperator::Inequality),
                        BinaryOperator::Inequality => Some(BinaryOperator::Equality),
                        BinaryOperator::StrictEquality => Some(BinaryOperator::StrictInequality),
                        BinaryOperator::StrictInequality => Some(BinaryOperator::StrictEquality),
                        _ => None,
                    };
                    if let Some(inverse) = inverse {
                        let mut binary = binary.clone_in(self.ast.allocator);
                        binary.operator = inverse;
                        *expression = Expression::BinaryExpression(binary);
                        self.changed = true;
                    }
                }
            }
        }
        if let Expression::UnaryExpression(unary) = expression {
            if unary.operator == UnaryOperator::LogicalNot {
                if let Expression::UnaryExpression(inner) = &unary.argument {
                    if inner.operator == UnaryOperator::LogicalNot
                        && boolean(&inner.argument, &self.booleans)
                    {
                        *expression = inner.argument.clone_in(self.ast.allocator);
                        self.changed = true;
                    }
                }
            }
        }
        if let Expression::UnaryExpression(unary) = expression {
            if unary.operator.as_str() == "void"
                && matches!(&unary.argument, Expression::NumericLiteral(value) if value.value == 0.0)
                && !self.bindings.contains("undefined")
            {
                *expression = self.ast.expression_identifier(SPAN, "undefined");
                // The dead-code pass may spell this as void 0 again. Formatting
                // normalizes it once more after the fixed point.
            }
        }
        if let Expression::StaticMemberExpression(member) = expression {
            let name = member.property.name.as_str();
            const GLOBALS: &[&str] = &[
                "console",
                "JSON",
                "Math",
                "Array",
                "Object",
                "Date",
                "RegExp",
                "Promise",
                "String",
                "Number",
                "Boolean",
                "Symbol",
                "parseInt",
                "parseFloat",
                "isNaN",
                "encodeURI",
                "unescape",
                "Error",
                "TypeError",
                "ReferenceError",
            ];
            if matches!(&member.object, Expression::Identifier(identifier) if identifier.name == "globalThis")
                && GLOBALS.contains(&name)
                && !self.bindings.contains(name)
            {
                *expression = self.ast.expression_identifier(SPAN, self.ast.atom(name));
                self.changed = true;
            }
        }
        if let Expression::CallExpression(call) = expression {
            let Some(member) = call.callee.get_member_expr() else {
                return;
            };
            if member.static_property_name() != Some("call") {
                return;
            }
            let Some(method) = member.object().get_member_expr() else {
                return;
            };
            let Some(receiver) = call.arguments.first().and_then(Argument::as_expression) else {
                return;
            };
            if !stable_receiver(receiver)
                || !method.object().content_eq(receiver)
                || matches!(receiver, Expression::Identifier(identifier) if self.usage.captured.contains(identifier.name.as_str()))
            {
                return;
            }
            call.callee = member.object().clone_in(self.ast.allocator);
            call.arguments.remove(0);
            self.changed = true;
        }
    }

    fn visit_module_export_name(&mut self, name: &mut ModuleExportName<'a>) {
        if let ModuleExportName::StringLiteral(value) = name {
            if property_identifier(&value.value) {
                *name = self
                    .ast
                    .module_export_name_identifier_name(SPAN, value.value);
                self.changed = true;
            }
        }
    }

    fn visit_assignment_target(&mut self, target: &mut AssignmentTarget<'a>) {
        if let Some(member) = target.as_member_expression() {
            let mut expression = Expression::from(member.clone_in(self.ast.allocator));
            self.visit_expression(&mut expression);
            if let Some(member) = expression.as_member_expression() {
                *target = AssignmentTarget::from(member.clone_in(self.ast.allocator));
            }
        } else {
            walk_mut::walk_assignment_target(self, target);
        }
    }
}

impl<'a> Syntax<'a> {
    fn condition(&mut self, expression: &mut Expression<'a>) {
        if let Expression::UnaryExpression(outer) = expression {
            if outer.operator == UnaryOperator::LogicalNot {
                if let Expression::UnaryExpression(inner) = &outer.argument {
                    if inner.operator == UnaryOperator::LogicalNot {
                        *expression = inner.argument.clone_in(self.ast.allocator);
                        self.changed = true;
                    }
                }
            }
        }
    }
}

fn empty(statement: &Statement<'_>) -> bool {
    matches!(statement, Statement::EmptyStatement(_))
        || matches!(statement, Statement::BlockStatement(block) if block.body.is_empty())
}

fn stable_receiver(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::Identifier(_) | Expression::ThisExpression(_)
    )
}

fn boolean(expression: &Expression<'_>, known: &BTreeSet<String>) -> bool {
    match expression {
        Expression::BooleanLiteral(_) => true,
        Expression::Identifier(identifier) => known.contains(identifier.name.as_str()),
        Expression::UnaryExpression(expression) => expression.operator.as_str() == "!",
        Expression::BinaryExpression(expression) => matches!(
            expression.operator.as_str(),
            "==" | "!=" | "===" | "!==" | "<" | "<=" | ">" | ">=" | "in" | "instanceof"
        ),
        Expression::LogicalExpression(expression) => {
            boolean(&expression.left, known) && boolean(&expression.right, known)
        }
        _ => false,
    }
}

pub(super) fn one_assignment<'n, 'a>(
    statement: &'n Statement<'a>,
) -> Option<(&'n str, &'n Expression<'a>)> {
    if let Statement::BlockStatement(block) = statement {
        if block.body.len() == 1 {
            return assignment(&block.body[0]);
        }
        None
    } else {
        assignment(statement)
    }
}

pub(super) fn property_identifier(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_'
                || byte == b'$'
                || byte.is_ascii_alphabetic()
                || (index != 0 && byte.is_ascii_digit())
        })
}

#[derive(Default)]
struct Bindings(BTreeSet<String>);

impl<'a> Visit<'a> for Bindings {
    fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
        self.0.insert(identifier.name.to_string());
    }
}

struct CallMatch<'a, 'n> {
    name: &'n str,
    receiver: &'n Expression<'a>,
    found: bool,
}

impl<'a> Visit<'a> for CallMatch<'a, '_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Some(member) = call.callee.get_member_expr() {
            if member.static_property_name() == Some("call")
                && matches!(member.object(), Expression::Identifier(identifier) if identifier.name == self.name)
                && call
                    .arguments
                    .first()
                    .and_then(Argument::as_expression)
                    .is_some_and(|receiver| receiver.content_eq(self.receiver))
            {
                self.found = true;
            }
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        let _ = (function, flags);
    }

    fn visit_arrow_function_expression(&mut self, function: &ArrowFunctionExpression<'a>) {
        let _ = function;
    }
}

struct CallReplace<'a, 'n> {
    ast: AstBuilder<'a>,
    name: &'n str,
    receiver: &'n Expression<'a>,
    member: &'n Expression<'a>,
}

impl<'a> VisitMut<'a> for CallReplace<'a, '_> {
    fn visit_call_expression(&mut self, call: &mut CallExpression<'a>) {
        if let Some(member) = call.callee.get_member_expr() {
            if member.static_property_name() == Some("call")
                && matches!(member.object(), Expression::Identifier(identifier) if identifier.name == self.name)
                && call
                    .arguments
                    .first()
                    .and_then(Argument::as_expression)
                    .is_some_and(|receiver| receiver.content_eq(self.receiver))
            {
                call.callee = self.member.clone_in(self.ast.allocator);
                call.arguments.remove(0);
            }
        }
        walk_mut::walk_call_expression(self, call);
    }

    fn visit_function(&mut self, function: &mut Function<'a>, flags: ScopeFlags) {
        let _ = (function, flags);
    }

    fn visit_arrow_function_expression(&mut self, function: &mut ArrowFunctionExpression<'a>) {
        let _ = function;
    }
}
