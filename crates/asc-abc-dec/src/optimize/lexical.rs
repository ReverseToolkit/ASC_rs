use std::collections::{BTreeMap, BTreeSet};

use oxc::allocator::{Allocator, CloneIn, Vec};
use oxc::ast::{ast::*, AstBuilder, NONE};
use oxc::ast_visit::{walk, walk_mut, Visit, VisitMut};
use oxc::span::SPAN;
use oxc::syntax::scope::ScopeFlags;

use super::temps::assignment;

pub(super) struct Lexical<'a> {
    ast: AstBuilder<'a>,
    current: Option<Expression<'a>>,
    parents: BTreeMap<String, Expression<'a>>,
    slots: BTreeMap<String, BTreeSet<u32>>,
    next: usize,
    pub changed: bool,
}

impl<'a> Lexical<'a> {
    pub fn new(allocator: &'a Allocator, program: &Program<'a>) -> Self {
        let mut frames = Frames {
            ast: AstBuilder::new(allocator),
            parents: BTreeMap::new(),
            next: 0,
        };
        frames.visit_program(program);
        Self {
            ast: frames.ast,
            current: None,
            parents: frames.parents,
            slots: BTreeMap::new(),
            next: frames.next,
            changed: false,
        }
    }

    fn parent(&self, expression: &Expression<'a>) -> Expression<'a> {
        if let Expression::Identifier(identifier) = expression {
            if let Some(parent) = self.parents.get(identifier.name.as_str()) {
                return parent.clone_in(self.ast.allocator);
            }
        }
        Expression::StaticMemberExpression(self.ast.alloc_static_member_expression(
            SPAN,
            expression.clone_in(self.ast.allocator),
            self.ast.identifier_name(SPAN, "parent"),
            false,
        ))
    }
}

impl<'a> VisitMut<'a> for Lexical<'a> {
    fn visit_program(&mut self, program: &mut Program<'a>) {
        walk_mut::walk_program(self, program);
        let mut slots = Slots {
            ast: self.ast,
            parents: &self.parents,
            slots: &mut self.slots,
            changed: &mut self.changed,
        };
        slots.visit_program(program);
        Declarations {
            ast: self.ast,
            slots: &self.slots,
        }
        .visit_program(program);
    }

    fn visit_function(&mut self, function: &mut Function<'a>, flags: ScopeFlags) {
        let outer = self.current.take();
        let eligible = function.body.as_ref().is_some_and(|body| {
            let mut check = Eligibility {
                nested: 0,
                valid: true,
            };
            check.visit_function_body(body);
            check.valid
        });
        if eligible && function.body.as_ref().is_some_and(|body| body.statements.iter().any(|statement|
            matches!(statement, Statement::VariableDeclaration(declaration) if declaration.declarations.iter().any(|declarator|
                matches!(&declarator.id.kind, BindingPatternKind::BindingIdentifier(identifier) if identifier.name == "__env")
                && matches!(&declarator.init, Some(Expression::Identifier(identifier)) if identifier.name == "__parentEnv")))))
        {
            self.current = Some(self.ast.expression_identifier(SPAN, "__parentEnv"));
        }
        walk_mut::walk_function(self, function, flags);
        self.current = outer;
    }

    fn visit_statements(&mut self, body: &mut Vec<'a, Statement<'a>>) {
        for statement in body.iter_mut() {
            if let Some(current) = &self.current {
                if let Some(("__env", value)) = assignment(statement) {
                    if let Expression::ObjectExpression(object) = value {
                        if let Some(parent) = frame_parent(object) {
                            if matches!(parent, Expression::Identifier(identifier) if identifier.name == "__env") {
                                let name = format!("__scope_{}", self.next);
                                self.next += 1;
                                let mut value = value.clone_in(self.ast.allocator);
                                EnvReference { ast: self.ast, value: current }.visit_expression(&mut value);
                                self.parents.insert(name.clone(), current.clone_in(self.ast.allocator));
                                *statement = declaration(self.ast, &name, Some(value), VariableDeclarationKind::Const);
                                self.current = Some(self.ast.expression_identifier(SPAN, self.ast.atom(&name)));
                                self.changed = true;
                            }
                        }
                    } else if value.get_member_expr().is_some_and(|member| member.static_property_name() == Some("parent")
                        && matches!(member.object(), Expression::Identifier(identifier) if identifier.name == "__env"))
                    {
                        self.current = Some(self.parent(current));
                        *statement = self.ast.statement_empty(SPAN);
                        self.changed = true;
                    }
                }
            }
            self.visit_statement(statement);
        }
        body.retain(|statement| !matches!(statement, Statement::EmptyStatement(_))
            && !matches!(statement, Statement::VariableDeclaration(declaration) if declaration.declarations.is_empty()));
    }

    fn visit_variable_declaration(&mut self, declaration: &mut VariableDeclaration<'a>) {
        if self.current.is_some() {
            declaration.declarations.retain(|declarator| {
                if matches!(&declarator.id.kind, BindingPatternKind::BindingIdentifier(identifier) if identifier.name == "__env") {
                    self.changed = true;
                    false
                } else { true }
            });
        }
        walk_mut::walk_variable_declaration(self, declaration);
    }

    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        if let Some(current) = &self.current {
            if matches!(expression, Expression::Identifier(identifier) if identifier.name == "__env")
            {
                *expression = current.clone_in(self.ast.allocator);
                self.changed = true;
                return;
            }
        }
        walk_mut::walk_expression(self, expression);
    }

    fn visit_try_statement(&mut self, statement: &mut TryStatement<'a>) {
        let start = self
            .current
            .as_ref()
            .map(|current| current.clone_in(self.ast.allocator));
        self.visit_block_statement(&mut statement.block);
        let normal = self.current.take();
        self.current = start;
        if let Some(handler) = &mut statement.handler {
            self.visit_catch_clause(handler);
        }
        self.current = normal;
        if let Some(finalizer) = &mut statement.finalizer {
            self.visit_block_statement(finalizer);
        }
    }
}

pub(super) fn declaration<'a>(
    ast: AstBuilder<'a>,
    name: &str,
    value: Option<Expression<'a>>,
    kind: VariableDeclarationKind,
) -> Statement<'a> {
    Statement::VariableDeclaration(ast.alloc_variable_declaration(
        SPAN,
        kind,
        ast.vec1(ast.variable_declarator(
            SPAN,
            kind,
            ast.binding_pattern(
                ast.binding_pattern_kind_binding_identifier(SPAN, ast.atom(name)),
                NONE,
                false,
            ),
            value,
            false,
        )),
        false,
    ))
}

pub(super) fn frame_parent<'n, 'a>(object: &'n ObjectExpression<'a>) -> Option<&'n Expression<'a>> {
    let mut parent = None;
    let mut slots = false;
    for property in &object.properties {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            return None;
        };
        match property.key.static_name().as_deref() {
            Some("parent") => parent = Some(&property.value),
            Some("slots") => {
                slots = matches!(&property.value, Expression::ArrayExpression(array) if array.elements.is_empty())
            }
            _ => return None,
        }
    }
    if slots {
        parent
    } else {
        None
    }
}

struct Frames<'a> {
    ast: AstBuilder<'a>,
    parents: BTreeMap<String, Expression<'a>>,
    next: usize,
}

impl<'a> Visit<'a> for Frames<'a> {
    fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
        if let Some(id) = frame_id(&identifier.name) {
            self.next = self.next.max(id + 1);
        }
    }
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let BindingPatternKind::BindingIdentifier(identifier) = &declarator.id.kind {
            if let Some(id) = identifier
                .name
                .strip_prefix("__scope_")
                .and_then(|id| id.parse::<usize>().ok())
            {
                self.next = self.next.max(id + 1);
                if let Some(Expression::ObjectExpression(object)) = &declarator.init {
                    if let Some(parent) = frame_parent(object) {
                        self.parents.insert(
                            identifier.name.to_string(),
                            parent.clone_in(self.ast.allocator),
                        );
                    }
                }
            }
        }
        walk::walk_variable_declarator(self, declarator);
    }
}

pub(super) fn frame_id(name: &str) -> Option<usize> {
    name.strip_prefix("__scope_")
        .or_else(|| {
            name.strip_prefix("local_")
                .and_then(|tail| tail.split('_').next())
        })?
        .parse()
        .ok()
}

struct EnvReference<'a, 'n> {
    ast: AstBuilder<'a>,
    value: &'n Expression<'a>,
}

impl<'a> VisitMut<'a> for EnvReference<'a, '_> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        if matches!(expression, Expression::Identifier(identifier) if identifier.name == "__env") {
            *expression = self.value.clone_in(self.ast.allocator);
        } else {
            walk_mut::walk_expression(self, expression);
        }
    }
}

struct Eligibility {
    nested: usize,
    valid: bool,
}

impl<'a> Visit<'a> for Eligibility {
    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        let _ = (function, flags);
    }
    fn visit_assignment_expression(&mut self, expression: &AssignmentExpression<'a>) {
        if matches!(&expression.left, AssignmentTarget::AssignmentTargetIdentifier(identifier) if identifier.name == "__env")
            && self.nested != 0
        {
            self.valid = false;
        }
        walk::walk_assignment_expression(self, expression);
    }
    fn visit_if_statement(&mut self, statement: &IfStatement<'a>) {
        self.nested += 1;
        walk::walk_if_statement(self, statement);
        self.nested -= 1;
    }
    fn visit_while_statement(&mut self, statement: &WhileStatement<'a>) {
        self.nested += 1;
        walk::walk_while_statement(self, statement);
        self.nested -= 1;
    }
    fn visit_switch_statement(&mut self, statement: &SwitchStatement<'a>) {
        self.nested += 1;
        walk::walk_switch_statement(self, statement);
        self.nested -= 1;
    }
}

struct Slots<'a, 'n> {
    ast: AstBuilder<'a>,
    parents: &'n BTreeMap<String, Expression<'a>>,
    slots: &'n mut BTreeMap<String, BTreeSet<u32>>,
    changed: &'n mut bool,
}

impl<'a> VisitMut<'a> for Slots<'a, '_> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        if let Some(member) = expression.get_member_expr() {
            if member.static_property_name() == Some("parent") {
                if let Expression::Identifier(identifier) = member.object() {
                    if let Some(parent) = self.parents.get(identifier.name.as_str()) {
                        *expression = parent.clone_in(self.ast.allocator);
                        *self.changed = true;
                        return;
                    }
                }
            }
        }
        if let Expression::ComputedMemberExpression(member) = expression {
            let Some(slots) = member.object.get_member_expr() else {
                return;
            };
            let Expression::NumericLiteral(index) = &member.expression else {
                return;
            };
            let Expression::Identifier(scope) = slots.object() else {
                return;
            };
            if slots.static_property_name() != Some("slots")
                || !self.parents.contains_key(scope.name.as_str())
                || index.value < 0.0
                || index.value > f64::from(u32::MAX)
                || index.value.fract() != 0.0
            {
                return;
            }
            let index: u32 = index
                .value
                .to_string()
                .parse()
                .expect("checked integral slot index");
            self.slots
                .entry(scope.name.to_string())
                .or_default()
                .insert(index);
            let id = scope.name.trim_start_matches("__scope_");
            *expression = self
                .ast
                .expression_identifier(SPAN, self.ast.atom(&format!("local_{id}_{index}")));
            *self.changed = true;
        }
    }
    fn visit_assignment_target(&mut self, target: &mut AssignmentTarget<'a>) {
        if let Some(member) = target.as_member_expression() {
            let mut expression = Expression::from(member.clone_in(self.ast.allocator));
            self.visit_expression(&mut expression);
            if let Expression::Identifier(identifier) = expression {
                *target = AssignmentTarget::AssignmentTargetIdentifier(identifier);
            } else if let Some(member) = expression.as_member_expression() {
                *target = AssignmentTarget::from(member.clone_in(self.ast.allocator));
            }
        } else {
            walk_mut::walk_assignment_target(self, target);
        }
    }
}

struct Declarations<'a, 'n> {
    ast: AstBuilder<'a>,
    slots: &'n BTreeMap<String, BTreeSet<u32>>,
}

impl<'a> VisitMut<'a> for Declarations<'a, '_> {
    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        let mut added = self.ast.vec();
        let mut existing: BTreeSet<_> = statements
            .iter()
            .filter_map(|statement| match statement {
                Statement::VariableDeclaration(declaration) => {
                    Some(declaration.declarations.iter().filter_map(|declarator| {
                        if let BindingPatternKind::BindingIdentifier(identifier) =
                            &declarator.id.kind
                        {
                            Some(identifier.name.to_string())
                        } else {
                            None
                        }
                    }))
                }
                _ => None,
            })
            .flatten()
            .collect();
        for statement in std::mem::replace(statements, self.ast.vec()) {
            let names: std::vec::Vec<_> = match &statement {
                Statement::VariableDeclaration(declaration) => declaration
                    .declarations
                    .iter()
                    .filter_map(|declarator| {
                        let BindingPatternKind::BindingIdentifier(identifier) = &declarator.id.kind
                        else {
                            return None;
                        };
                        self.slots.get(identifier.name.as_str()).map(|slots| {
                            (
                                identifier.name.trim_start_matches("__scope_").to_string(),
                                slots,
                            )
                        })
                    })
                    .collect(),
                _ => std::vec::Vec::new(),
            };
            for (scope, slots) in names {
                for slot in slots {
                    let name = format!("local_{scope}_{slot}");
                    if existing.insert(name.clone()) {
                        added.push(declaration(
                            self.ast,
                            &name,
                            None,
                            VariableDeclarationKind::Let,
                        ));
                    }
                }
            }
            added.push(statement);
        }
        *statements = added;
        walk_mut::walk_statements(self, statements);
    }
}
