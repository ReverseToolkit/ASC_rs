use std::collections::BTreeSet;

use oxc::allocator::{Allocator, CloneIn};
use oxc::ast::{ast::*, AstBuilder};
use oxc::ast_visit::{walk, walk_mut, Visit, VisitMut};
use oxc::span::SPAN;
use oxc::syntax::operator::AssignmentOperator;

use super::lexical::declaration;
use crate::lower::{binding_name, identifier};

pub(super) fn records(program: &Program<'_>) -> BTreeSet<String> {
    let mut records = Records(BTreeSet::new());
    records.visit_program(program);
    records.0
}

struct Records(BTreeSet<String>);
impl<'a> Visit<'a> for Records {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if matches!(&call.callee, Expression::Identifier(identifier) if identifier.name == "__abc_record_store")
        {
            if let Some(Expression::StringLiteral(name)) =
                call.arguments.first().and_then(Argument::as_expression)
            {
                self.0.insert(name.value.to_string());
            }
        }
        walk::walk_call_expression(self, call);
    }
}

pub(super) struct Globals<'a, 'n> {
    ast: AstBuilder<'a>,
    records: &'n BTreeSet<String>,
    bindings: BTreeSet<String>,
    declare: bool,
}
impl<'a, 'n> Globals<'a, 'n> {
    pub fn new(
        allocator: &'a Allocator,
        records: &'n BTreeSet<String>,
        program: &Program<'a>,
        declare: bool,
    ) -> Self {
        let mut bindings = Bindings(BTreeSet::new());
        bindings.visit_program(program);
        Self {
            ast: AstBuilder::new(allocator),
            records,
            bindings: bindings.0,
            declare,
        }
    }
    fn binding(&self, name: &str) -> Expression<'a> {
        if self.records.contains(name) {
            self.ast
                .expression_identifier(SPAN, self.ast.atom(&binding_name(name)))
        } else if identifier(name) == name && name != "eval" && !self.bindings.contains(name) {
            self.ast.expression_identifier(SPAN, self.ast.atom(name))
        } else {
            Expression::ComputedMemberExpression(
                self.ast.alloc_computed_member_expression(
                    SPAN,
                    self.ast.expression_identifier(SPAN, "globalThis"),
                    self.ast
                        .expression_string_literal(SPAN, self.ast.atom(name), None),
                    false,
                ),
            )
        }
    }
}

impl<'a> VisitMut<'a> for Globals<'a, '_> {
    fn visit_program(&mut self, program: &mut Program<'a>) {
        walk_mut::walk_program(self, program);
        if self.declare {
            for name in self.records {
                program.body.insert(
                    0,
                    declaration(
                        self.ast,
                        &binding_name(name),
                        None,
                        VariableDeclarationKind::Let,
                    ),
                );
            }
        }
    }
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        let Expression::CallExpression(call) = expression else {
            return;
        };
        let Expression::Identifier(callee) = &call.callee else {
            return;
        };
        if !matches!(
            callee.name.as_str(),
            "__abc_global" | "__abc_record_store" | "__abc_global_store"
        ) {
            return;
        }
        let Some(Expression::StringLiteral(name)) =
            call.arguments.first().and_then(Argument::as_expression)
        else {
            return;
        };
        let binding = self.binding(&name.value);
        if callee.name == "__abc_global" {
            *expression = binding;
            return;
        }
        let Some(value) = call.arguments.get(1).and_then(Argument::as_expression) else {
            return;
        };
        // A global-object store must retain property assignment semantics even
        // when a corresponding load can use an unshadowed global identifier.
        let binding = if !self.records.contains(name.value.as_str()) {
            Expression::ComputedMemberExpression(self.ast.alloc_computed_member_expression(
                SPAN,
                self.ast.expression_identifier(SPAN, "globalThis"),
                self.ast.expression_string_literal(SPAN, name.value, None),
                false,
            ))
        } else {
            binding
        };
        let target = match binding {
            Expression::Identifier(identifier) => {
                AssignmentTarget::AssignmentTargetIdentifier(identifier)
            }
            expression => AssignmentTarget::from(expression.into_member_expression()),
        };
        *expression = self.ast.expression_assignment(
            SPAN,
            AssignmentOperator::Assign,
            target,
            value.clone_in(self.ast.allocator),
        );
    }
}

struct Bindings(BTreeSet<String>);
impl<'a> Visit<'a> for Bindings {
    fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
        self.0.insert(identifier.name.to_string());
    }
}
