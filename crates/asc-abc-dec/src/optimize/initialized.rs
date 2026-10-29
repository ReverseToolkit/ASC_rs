use std::collections::BTreeSet;

use oxc::allocator::{Allocator, Vec};
use oxc::ast::{ast::*, AstBuilder};
use oxc::ast_visit::{walk, walk_mut, Visit, VisitMut};
use oxc::span::SPAN;
use oxc::syntax::scope::ScopeFlags;

use super::analysis::{temporary, Usage};
use super::temps::assignment;

/// Import reads already enforce the module's TDZ. The bytecode's additional
/// comparison with this record's private sentinel cannot succeed after them.
pub(super) struct Initialized<'a> {
    ast: AstBuilder<'a>,
    permanent: BTreeSet<String>,
    known: BTreeSet<String>,
    captured: BTreeSet<String>,
    single_stores: BTreeSet<String>,
    depth: usize,
    private_sentinel: bool,
    pub changed: bool,
}

impl<'a> Initialized<'a> {
    pub fn new(allocator: &'a Allocator, program: &Program<'a>) -> Self {
        let usage = Usage::statements(&program.body);
        let mut sentinel = SentinelUses::default();
        sentinel.visit_program(program);
        let mut permanent = BTreeSet::from(["undefined".to_string()]);
        for statement in &program.body {
            match statement {
                Statement::ImportDeclaration(import) => {
                    if let Some(specifiers) = &import.specifiers {
                        permanent.extend(
                            specifiers
                                .iter()
                                .map(|specifier| specifier.local().name.to_string()),
                        );
                    }
                }
                Statement::ClassDeclaration(class) => {
                    if let Some(name) = &class.id {
                        if !usage.assigned.contains(name.name.as_str()) {
                            permanent.insert(name.name.to_string());
                        }
                    }
                }
                _ => {}
            }
        }
        // Find bindings for which every store excludes the private sentinel.
        // Generated locals start as undefined when their frame is flattened.
        for _ in 0..16 {
            let mut stores = Stores {
                known: &permanent,
                safe: BTreeSet::new(),
                unknown: BTreeSet::new(),
            };
            stores.visit_program(program);
            let previous = permanent.len();
            permanent.extend(stores.safe.difference(&stores.unknown).cloned());
            if previous == permanent.len() {
                break;
            }
        }
        Self {
            ast: AstBuilder::new(allocator),
            known: permanent.clone(),
            permanent,
            captured: usage.captured,
            single_stores: usage
                .assignments
                .into_iter()
                .filter_map(|(name, count)| {
                    (name.starts_with("local_") && count == 1).then_some(name)
                })
                .collect(),
            depth: 0,
            private_sentinel: sentinel.declared && !sentinel.escaped,
            changed: false,
        }
    }
}

impl<'a> VisitMut<'a> for Initialized<'a> {
    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        for statement in statements.iter_mut() {
            self.visit_statement(statement);
        }
        statements.retain(|statement| !matches!(statement, Statement::EmptyStatement(_)));
    }

    fn visit_statement(&mut self, statement: &mut Statement<'a>) {
        if let Statement::IfStatement(branch) = statement {
            if let Expression::BinaryExpression(test) = &branch.test {
                if test.operator.as_str() == "==="
                    && branch.alternate.is_none()
                    && matches!(&test.right, Expression::Identifier(identifier) if identifier.name == "__hole")
                    && (excludes_hole(&test.left, &self.known)
                        || (self.private_sentinel
                            && matches!(&test.left, Expression::Identifier(identifier) if temporary(&identifier.name) || identifier.name.starts_with("local_"))))
                    && matches!(&branch.consequent, Statement::ThrowStatement(_))
                {
                    *statement = self.ast.statement_empty(SPAN);
                    self.changed = true;
                    return;
                }
            }
        }
        walk_mut::walk_statement(self, statement);
        if let Some((name, value)) = assignment(statement) {
            if excludes_hole(value, &self.known) {
                self.known.insert(name.to_string());
                if self.depth == 0 && self.single_stores.contains(name) {
                    self.permanent.insert(name.to_string());
                }
            } else {
                self.known.remove(name);
            }
        }
    }

    fn visit_function(&mut self, function: &mut Function<'a>, flags: ScopeFlags) {
        let known = std::mem::replace(&mut self.known, self.permanent.clone());
        let usage = function
            .body
            .as_ref()
            .map(|body| Usage::statements(&body.statements))
            .unwrap_or_default();
        let captured = std::mem::replace(&mut self.captured, usage.captured);
        self.depth += 1;
        walk_mut::walk_function(self, function, flags);
        self.depth -= 1;
        self.known = known;
        self.captured = captured;
    }

    fn visit_if_statement(&mut self, branch: &mut IfStatement<'a>) {
        self.visit_expression(&mut branch.test);
        let before = self.known.clone();
        self.visit_statement(&mut branch.consequent);
        let yes = self.known.clone();
        self.known = before;
        if let Some(alternate) = &mut branch.alternate {
            self.visit_statement(alternate);
        }
        self.known = yes.intersection(&self.known).cloned().collect();
    }

    fn visit_while_statement(&mut self, statement: &mut WhileStatement<'a>) {
        let writes = Usage::statement(&statement.body).writes;
        self.known
            .retain(|name| self.permanent.contains(name) || !writes.contains(name));
        let before = self.known.clone();
        walk_mut::walk_while_statement(self, statement);
        self.known = before.intersection(&self.known).cloned().collect();
    }

    fn visit_try_statement(&mut self, statement: &mut TryStatement<'a>) {
        let before = self.known.clone();
        self.visit_block_statement(&mut statement.block);
        let normal = self.known.clone();
        self.known = before;
        self.known.retain(|name| {
            self.permanent.contains(name)
                || !Usage::statements(&statement.block.body)
                    .writes
                    .contains(name)
        });
        if let Some(handler) = &mut statement.handler {
            self.visit_catch_clause(handler);
        }
        self.known = normal.intersection(&self.known).cloned().collect();
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
            self.known
                .retain(|name| self.permanent.contains(name) || !self.captured.contains(name));
        }
    }
}

/// When the private symbol is used only in compiler TDZ guards, it cannot
/// occur in a register or a captured value. Keep checks if it is ever stored,
/// passed to a call, or returned by the record.
#[derive(Default)]
struct SentinelUses {
    declared: bool,
    escaped: bool,
}
impl<'a> Visit<'a> for SentinelUses {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if matches!(&declarator.id.kind, BindingPatternKind::BindingIdentifier(identifier) if identifier.name == "__hole")
            && matches!(&declarator.init, Some(Expression::CallExpression(call)) if matches!(&call.callee, Expression::Identifier(identifier) if identifier.name == "Symbol"))
        {
            self.declared = true;
        }
        walk::walk_variable_declarator(self, declarator);
    }
    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
        if identifier.name == "__hole" {
            self.escaped = true;
        }
    }
    fn visit_if_statement(&mut self, statement: &IfStatement<'a>) {
        if let Expression::BinaryExpression(test) = &statement.test {
            if test.operator.as_str() == "==="
                && statement.alternate.is_none()
                && matches!(&test.right, Expression::Identifier(identifier) if identifier.name == "__hole")
                && matches!(&test.left, Expression::Identifier(identifier) if temporary(&identifier.name) || identifier.name.starts_with("local_"))
                && matches!(&statement.consequent, Statement::ThrowStatement(_))
            {
                self.visit_expression(&test.left);
                self.visit_statement(&statement.consequent);
                return;
            }
        }
        walk::walk_if_statement(self, statement);
    }
}

fn excludes_hole(expression: &Expression<'_>, known: &BTreeSet<String>) -> bool {
    match expression {
        Expression::Identifier(identifier) => known.contains(identifier.name.as_str()),
        Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::ObjectExpression(_)
        | Expression::ArrayExpression(_)
        | Expression::FunctionExpression(_)
        | Expression::ArrowFunctionExpression(_)
        | Expression::ClassExpression(_)
        | Expression::BinaryExpression(_)
        | Expression::TemplateLiteral(_) => true,
        Expression::UnaryExpression(expression) => matches!(
            expression.operator.as_str(),
            "!" | "void" | "typeof" | "+" | "-" | "~"
        ),
        _ => false,
    }
}

struct Stores<'n> {
    known: &'n BTreeSet<String>,
    safe: BTreeSet<String>,
    unknown: BTreeSet<String>,
}
impl Stores<'_> {
    fn store(&mut self, name: &str, value: Option<&Expression<'_>>) {
        if !name.starts_with("local_") {
            return;
        }
        if value.is_none_or(|value| excludes_hole(value, self.known)) {
            self.safe.insert(name.to_string());
        } else {
            self.unknown.insert(name.to_string());
        }
    }
}
impl<'a> Visit<'a> for Stores<'_> {
    fn visit_variable_declarator(&mut self, declarator: &VariableDeclarator<'a>) {
        if let BindingPatternKind::BindingIdentifier(identifier) = &declarator.id.kind {
            self.store(&identifier.name, declarator.init.as_ref());
        }
        walk::walk_variable_declarator(self, declarator);
    }
    fn visit_assignment_expression(&mut self, expression: &AssignmentExpression<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(identifier) = &expression.left {
            self.store(&identifier.name, Some(&expression.right));
        }
        walk::walk_assignment_expression(self, expression);
    }
}
