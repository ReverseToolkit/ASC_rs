use std::collections::BTreeSet;

use oxc::allocator::{Allocator, CloneIn};
use oxc::ast::{ast::*, AstBuilder};
use oxc::ast_visit::{walk, walk_mut, Visit, VisitMut};
use oxc::span::SPAN;
use oxc::syntax::{
    operator::{AssignmentOperator, LogicalOperator, UnaryOperator},
    scope::ScopeFlags,
};

use super::analysis::{temporary, Locals};
use super::syntax::one_assignment;

pub(super) struct Branches<'a> {
    ast: AstBuilder<'a>,
    owned: BTreeSet<String>,
    mutable: BTreeSet<String>,
    parameters: BTreeSet<String>,
    undefined_shadowed: bool,
    pub changed: bool,
}

impl<'a> Branches<'a> {
    pub fn new(allocator: &'a Allocator, program: &Program<'a>) -> Self {
        let mut locals = Locals::default();
        locals.visit_program(program);
        let mut bindings = Mutable::default();
        bindings.visit_program(program);
        Self {
            ast: AstBuilder::new(allocator),
            undefined_shadowed: locals.0.contains("undefined"),
            owned: locals.0,
            mutable: bindings
                .names
                .difference(&bindings.constants)
                .cloned()
                .collect(),
            parameters: BTreeSet::new(),
            changed: false,
        }
    }

    fn store(&self, target: &str, value: Expression<'a>) -> Statement<'a> {
        self.ast.statement_expression(
            SPAN,
            self.ast.expression_assignment(
                SPAN,
                AssignmentOperator::Assign,
                AssignmentTarget::AssignmentTargetIdentifier(
                    self.ast
                        .alloc_identifier_reference(SPAN, self.ast.atom(target)),
                ),
                value,
            ),
        )
    }
}

impl<'a> VisitMut<'a> for Branches<'a> {
    fn visit_function(&mut self, function: &mut Function<'a>, flags: ScopeFlags) {
        let mut locals = Locals::default();
        locals.visit_formal_parameters(&function.params);
        let parameters = locals.0.clone();
        let mut bindings = Mutable::default();
        if let Some(body) = &function.body {
            locals.visit_function_body(body);
            bindings.visit_function_body(body);
        }
        bindings.names.extend(parameters.iter().cloned());
        let shadowed = self.undefined_shadowed;
        self.undefined_shadowed |= locals.0.contains("undefined");
        let owned = std::mem::replace(&mut self.owned, locals.0);
        let mutable = std::mem::replace(
            &mut self.mutable,
            bindings
                .names
                .difference(&bindings.constants)
                .cloned()
                .collect(),
        );
        let parameters = std::mem::replace(&mut self.parameters, parameters);
        walk_mut::walk_function(self, function, flags);
        self.owned = owned;
        self.mutable = mutable;
        self.parameters = parameters;
        self.undefined_shadowed = shadowed;
    }

    fn visit_arrow_function_expression(&mut self, function: &mut ArrowFunctionExpression<'a>) {
        let mut locals = Locals::default();
        locals.visit_formal_parameters(&function.params);
        let parameters = locals.0.clone();
        locals.visit_function_body(&function.body);
        let mut bindings = Mutable::default();
        bindings.visit_function_body(&function.body);
        bindings.names.extend(parameters.iter().cloned());
        let shadowed = self.undefined_shadowed;
        self.undefined_shadowed |= locals.0.contains("undefined");
        let owned = std::mem::replace(&mut self.owned, locals.0);
        let mutable = std::mem::replace(
            &mut self.mutable,
            bindings
                .names
                .difference(&bindings.constants)
                .cloned()
                .collect(),
        );
        let parameters = std::mem::replace(&mut self.parameters, parameters);
        walk_mut::walk_arrow_function_expression(self, function);
        self.owned = owned;
        self.mutable = mutable;
        self.parameters = parameters;
        self.undefined_shadowed = shadowed;
    }

    fn visit_statement(&mut self, statement: &mut Statement<'a>) {
        walk_mut::walk_statement(self, statement);
        let Statement::IfStatement(branch) = statement else {
            return;
        };
        let Some((target, yes)) = one_assignment(&branch.consequent) else {
            return;
        };
        if !self.owned.contains(target) {
            return;
        }
        if let Some(alternate) = &branch.alternate {
            let Some((other, no)) = one_assignment(alternate) else {
                return;
            };
            if target != other || named_value(yes) || named_value(no) {
                return;
            }
            let (test, yes, no) = if let Expression::UnaryExpression(test) = &branch.test {
                if test.operator == UnaryOperator::LogicalNot {
                    (&test.argument, no, yes)
                } else {
                    (&branch.test, yes, no)
                }
            } else {
                (&branch.test, yes, no)
            };
            let value = self.ast.expression_conditional(
                SPAN,
                test.clone_in(self.ast.allocator),
                yes.clone_in(self.ast.allocator),
                no.clone_in(self.ast.allocator),
            );
            *statement = self.store(target, value);
            self.changed = true;
            return;
        }
        if !self.undefined_shadowed
            && self.parameters.contains(target)
            && self.mutable.contains(target)
            && matches!(yes, Expression::Identifier(identifier) if identifier.name == "undefined")
            && matches!(&branch.test, Expression::BinaryExpression(test) if test.operator.as_str() == "==="
                && matches!(&test.left, Expression::Identifier(identifier) if identifier.name == target)
                && matches!(&test.right, Expression::Identifier(identifier) if identifier.name == "undefined"))
        {
            *statement = self.ast.statement_empty(SPAN);
            self.changed = true;
            return;
        }
        if !temporary(target) || !self.mutable.contains(target) || named_value(yes) {
            return;
        }
        let operator = if matches!(&branch.test, Expression::Identifier(identifier) if identifier.name == target)
        {
            LogicalOperator::And
        } else if matches!(&branch.test, Expression::UnaryExpression(test) if test.operator == UnaryOperator::LogicalNot && matches!(&test.argument, Expression::Identifier(identifier) if identifier.name == target))
        {
            LogicalOperator::Or
        } else {
            return;
        };
        let value = self.ast.expression_logical(
            SPAN,
            self.ast.expression_identifier(SPAN, self.ast.atom(target)),
            operator,
            yes.clone_in(self.ast.allocator),
        );
        *statement = self.store(target, value);
        self.changed = true;
    }
}

// Conditional expressions do not perform the anonymous function/class name
// inference that a direct binding assignment performs.
fn named_value(value: &Expression<'_>) -> bool {
    matches!(
        value,
        Expression::FunctionExpression(_)
            | Expression::ArrowFunctionExpression(_)
            | Expression::ClassExpression(_)
    )
}

#[derive(Default)]
struct Mutable {
    names: BTreeSet<String>,
    constants: BTreeSet<String>,
}
impl<'a> Visit<'a> for Mutable {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let BindingPatternKind::BindingIdentifier(identifier) = &declarator.id.kind {
            if declarator.kind == VariableDeclarationKind::Const {
                self.constants.insert(identifier.name.to_string());
            } else {
                self.names.insert(identifier.name.to_string());
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
