use oxc::allocator::{Allocator, CloneIn, Vec};
use oxc::ast::{ast::*, AstBuilder};
use oxc::ast_visit::{walk_mut, Visit, VisitMut};
use oxc::span::SPAN;

use super::analysis::Usage;
use super::temps::assignment;

pub(super) struct Finally<'a> {
    ast: AstBuilder<'a>,
    pub changed: bool,
}
impl<'a> Finally<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            changed: false,
        }
    }
}

impl<'a> VisitMut<'a> for Finally<'a> {
    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        walk_mut::walk_statements(self, statements);
        let usage = Usage::statements(statements);
        for index in 1..statements.len().saturating_sub(2) {
            let Some((flag, value)) = assignment(&statements[index - 1]) else {
                continue;
            };
            if !undefined(value)
                || usage.captured.contains(flag)
                || Usage::statements(&statements[index..])
                    .assigned
                    .contains(flag)
            {
                continue;
            }
            let Statement::TryStatement(guard) = &statements[index] else {
                continue;
            };
            if guard.finalizer.is_some() {
                continue;
            }
            let Some(handler) = &guard.handler else {
                continue;
            };
            let Some(parameter) = &handler.param else {
                continue;
            };
            let BindingPatternKind::BindingIdentifier(parameter) = &parameter.pattern.kind else {
                continue;
            };
            let [caught] = handler.body.body.as_slice() else {
                continue;
            };
            let Some((saved, Expression::Identifier(caught))) = assignment(caught) else {
                continue;
            };
            if caught.name != parameter.name {
                continue;
            }
            let Some((normal, Expression::Identifier(sentinel))) =
                guard.block.body.last().and_then(assignment)
            else {
                continue;
            };
            if normal != saved || sentinel.name != "__hole" {
                continue;
            }
            if usage.captured.contains(saved)
                || Usage::statements(&statements[index..]).count(saved) != 2
            {
                continue;
            }
            if Usage::statements(&guard.block.body[..guard.block.body.len() - 1])
                .writes
                .contains(saved)
            {
                continue;
            }
            let mut abrupt = Abrupt::default();
            abrupt.visit_statements(&guard.block.body);
            if abrupt.0 {
                continue;
            }
            let Statement::IfStatement(finalizer) = &statements[index + 1] else {
                continue;
            };
            if finalizer.alternate.is_some() || !undefined_test(&finalizer.test, flag) {
                continue;
            }
            let Statement::IfStatement(rethrow) = &statements[index + 2] else {
                continue;
            };
            if rethrow.alternate.is_some()
                || !rethrow_test(&rethrow.test, saved)
                || !matches!(&rethrow.consequent, Statement::ThrowStatement(thrown) if matches!(&thrown.argument, Expression::Identifier(identifier) if identifier.name == saved))
            {
                continue;
            }
            let finalizer = match &finalizer.consequent {
                Statement::BlockStatement(block) => block.clone_in(self.ast.allocator),
                statement => self.ast.alloc_block_statement(
                    SPAN,
                    self.ast.vec1(statement.clone_in(self.ast.allocator)),
                ),
            };
            let Statement::TryStatement(guard) = &mut statements[index] else {
                unreachable!("matched try statement")
            };
            guard.block.body.pop();
            guard.handler = None;
            guard.finalizer = Some(finalizer);
            statements[index + 1] = self.ast.statement_empty(SPAN);
            statements[index + 2] = self.ast.statement_empty(SPAN);
            self.changed = true;
        }
        statements.retain(|statement| !matches!(statement, Statement::EmptyStatement(_)));
    }
}

fn undefined(expression: &Expression<'_>) -> bool {
    matches!(expression, Expression::Identifier(identifier) if identifier.name == "undefined")
        || matches!(expression, Expression::UnaryExpression(unary) if unary.operator.as_str() == "void" && matches!(&unary.argument, Expression::NumericLiteral(value) if value.value == 0.0))
}

#[derive(Default)]
struct Abrupt(bool);
impl<'a> Visit<'a> for Abrupt {
    fn visit_function(&mut self, function: &Function<'a>, flags: oxc::syntax::scope::ScopeFlags) {
        let _ = (function, flags);
    }
    fn visit_arrow_function_expression(&mut self, function: &ArrowFunctionExpression<'a>) {
        let _ = function;
    }
    fn visit_class(&mut self, class: &Class<'a>) {
        let _ = class;
    }
    fn visit_return_statement(&mut self, statement: &ReturnStatement<'a>) {
        let _ = statement;
        self.0 = true;
    }
    fn visit_break_statement(&mut self, statement: &BreakStatement<'a>) {
        let _ = statement;
        self.0 = true;
    }
    fn visit_continue_statement(&mut self, statement: &ContinueStatement<'a>) {
        let _ = statement;
        self.0 = true;
    }
}

fn undefined_test(expression: &Expression<'_>, name: &str) -> bool {
    matches!(expression, Expression::BinaryExpression(binary) if matches!(binary.operator.as_str(), "==" | "===")
        && matches!(&binary.left, Expression::Identifier(identifier) if identifier.name == name) && undefined(&binary.right))
}

fn rethrow_test(expression: &Expression<'_>, name: &str) -> bool {
    matches!(expression, Expression::BinaryExpression(binary) if matches!(binary.operator.as_str(), "!=" | "!==")
        && matches!(&binary.left, Expression::Identifier(identifier) if identifier.name == "__hole")
        && matches!(&binary.right, Expression::Identifier(identifier) if identifier.name == name))
}
