use std::collections::{BTreeMap, BTreeSet};

use oxc::allocator::{Allocator, CloneIn, Vec};
use oxc::ast::{ast::*, AstBuilder, NONE};
use oxc::ast_visit::{walk_mut, Visit, VisitMut};
use oxc::span::{ContentEq, SPAN};
use oxc::syntax::{operator::UnaryOperator, scope::ScopeFlags};

use super::analysis::{pure, temporary, Locals, Usage};
use super::lexical::frame_id;
use super::temps::assignment;

pub(super) struct Polish<'a> {
    ast: AstBuilder<'a>,
    owned: BTreeSet<String>,
}
impl<'a> Polish<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            owned: BTreeSet::new(),
        }
    }

    fn initializers(&self, statements: &mut Vec<'a, Statement<'a>>) {
        let usage = Usage::statements(statements);
        for index in 0..statements.len() {
            let Some((target, value)) = assignment(&statements[index]) else {
                continue;
            };
            if !temporary(target) && !target.starts_with("local_") {
                continue;
            }
            let target = target.to_string();
            let dependencies = Usage::eager_expression(value);
            let value = value.clone_in(self.ast.allocator);
            let mut later = BTreeSet::new();
            for declaration_index in (0..index).rev() {
                match &statements[declaration_index] {
                    Statement::EmptyStatement(_) => continue,
                    Statement::VariableDeclaration(declaration) => {
                        let Some(position) = declaration.declarations.iter().position(|declarator| matches!(&declarator.id.kind, BindingPatternKind::BindingIdentifier(identifier) if identifier.name == target && declarator.init.is_none())) else {
                            if declaration.declarations.iter().any(|declarator| declarator.init.is_some()) { break; }
                            for declarator in &declaration.declarations {
                                if let BindingPatternKind::BindingIdentifier(identifier) = &declarator.id.kind { later.insert(identifier.name.to_string()); }
                            }
                            continue;
                        };
                        if declaration.declarations[position + 1..]
                            .iter()
                            .any(|declarator| declarator.init.is_some())
                        {
                            break;
                        }
                        later.extend(declaration.declarations[position + 1..].iter().filter_map(
                            |declarator| match &declarator.id.kind {
                                BindingPatternKind::BindingIdentifier(identifier)
                                    if declarator.init.is_none() =>
                                {
                                    Some(identifier.name.to_string())
                                }
                                _ => None,
                            },
                        ));
                        if dependencies.count(&target) != 0
                            || later.iter().any(|name| dependencies.count(name) != 0)
                            || (!pure(&value)
                                && later.iter().any(|name| usage.captured.contains(name)))
                        {
                            break;
                        }
                        if let Statement::VariableDeclaration(declaration) =
                            &mut statements[declaration_index]
                        {
                            declaration.declarations[position].init = Some(value);
                        }
                        statements[index] = self.ast.statement_empty(SPAN);
                        break;
                    }
                    _ => break,
                }
            }
        }
        statements.retain(|statement| !matches!(statement, Statement::EmptyStatement(_)));
    }

    fn switches(&self, statements: &mut Vec<'a, Statement<'a>>) {
        let mut index = 0;
        while index < statements.len() {
            let Some((name, _, _)) = return_case(&statements[index]) else {
                index += 1;
                continue;
            };
            if !self.owned.contains(name) {
                index += 1;
                continue;
            }
            let name = name.to_string();
            let mut keys = BTreeSet::new();
            let mut groups: std::vec::Vec<(std::vec::Vec<Expression<'a>>, Statement<'a>)> =
                std::vec::Vec::new();
            let mut end = index;
            while let Some(statement) = statements.get(end) {
                let Some((other, test, result)) = return_case(statement) else {
                    break;
                };
                if other != name {
                    break;
                }
                let Some(key) = case_key(test) else {
                    break;
                };
                // A repeated case must retain its first-match behavior.
                if !keys.insert(key) {
                    break;
                }
                if let Some((tests, _)) = groups
                    .iter_mut()
                    .find(|(_, previous)| previous.content_eq(result))
                {
                    tests.push(test.clone_in(self.ast.allocator));
                } else {
                    groups.push((
                        vec![test.clone_in(self.ast.allocator)],
                        result.clone_in(self.ast.allocator),
                    ));
                }
                end += 1;
            }
            if end - index < 4 {
                index += 1;
                continue;
            }
            let mut cases = self.ast.vec();
            for (tests, result) in groups {
                let last = tests.len() - 1;
                for (position, test) in tests.into_iter().enumerate() {
                    let body = if position == last {
                        self.ast.vec1(result.clone_in(self.ast.allocator))
                    } else {
                        self.ast.vec()
                    };
                    cases.push(self.ast.switch_case(SPAN, Some(test), body));
                }
            }
            if let Some(result @ Statement::ReturnStatement(_)) = statements.get(end) {
                cases.push(self.ast.switch_case(
                    SPAN,
                    None,
                    self.ast.vec1(result.clone_in(self.ast.allocator)),
                ));
                end += 1;
            }
            statements[index] = Statement::SwitchStatement(self.ast.alloc_switch_statement(
                SPAN,
                self.ast.expression_identifier(SPAN, self.ast.atom(&name)),
                cases,
            ));
            statements.drain(index + 1..end);
            index += 1;
        }
    }

    fn exports(&self, program: &mut Program<'a>) {
        let mut classes = BTreeMap::new();
        for (index, statement) in program.body.iter().enumerate() {
            if let Statement::ClassDeclaration(class) = statement {
                if let Some(name) = &class.id {
                    classes.insert(name.name.to_string(), index);
                }
            }
        }
        let usage = Usage::statements(&program.body);
        program.body.retain(|statement| {
            !matches!(statement, Statement::ExpressionStatement(statement) if statement.expression.get_member_expr().is_some_and(|member|
                member.static_property_name() == Some("prototype") && matches!(member.object(), Expression::Identifier(identifier) if classes.contains_key(identifier.name.as_str()) && !usage.assigned.contains(identifier.name.as_str()))))
        });
        // Removing harmless prototype reads can shift indices.
        classes.clear();
        for (index, statement) in program.body.iter().enumerate() {
            if let Statement::ClassDeclaration(class) = statement {
                if let Some(name) = &class.id {
                    classes.insert(name.name.to_string(), index);
                }
            }
        }
        let mut exports = BTreeMap::new();
        for statement in &mut program.body {
            let Statement::ExportNamedDeclaration(export) = statement else {
                continue;
            };
            if export.source.is_some() || export.declaration.is_some() {
                continue;
            }
            export.specifiers.retain(|specifier| {
                let name = specifier.local.name();
                if specifier.exported.name() == name {
                    if let Some(index) = classes.get(name.as_str()) {
                        exports.insert(*index, ());
                        return false;
                    }
                }
                true
            });
        }
        for (index, ()) in exports {
            let Statement::ClassDeclaration(class) = &program.body[index] else {
                continue;
            };
            program.body[index] =
                Statement::ExportNamedDeclaration(self.ast.alloc_export_named_declaration(
                    SPAN,
                    Some(Declaration::ClassDeclaration(
                        class.clone_in(self.ast.allocator),
                    )),
                    self.ast.vec(),
                    None,
                    ImportOrExportKind::Value,
                    NONE,
                ));
        }
        program.body.retain(|statement| !matches!(statement, Statement::ExportNamedDeclaration(export) if export.source.is_none() && export.declaration.is_none() && export.specifiers.is_empty()));
    }
}

impl<'a> VisitMut<'a> for Polish<'a> {
    fn visit_program(&mut self, program: &mut Program<'a>) {
        let mut locals = Locals::default();
        locals.visit_program(program);
        self.owned = locals.0;
        walk_mut::walk_program(self, program);
        self.exports(program);
        let mut names = Names::default();
        names.visit_program(program);
        Rename {
            ast: self.ast,
            mapping: &names.mapping,
        }
        .visit_program(program);
    }
    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        walk_mut::walk_statements(self, statements);
        self.initializers(statements);
        self.switches(statements);
    }
    fn visit_function(&mut self, function: &mut Function<'a>, flags: ScopeFlags) {
        let mut locals = Locals::default();
        locals.visit_formal_parameters(&function.params);
        if let Some(body) = &function.body {
            locals.visit_function_body(body);
        }
        let owned = std::mem::replace(&mut self.owned, locals.0);
        walk_mut::walk_function(self, function, flags);
        self.owned = owned;
    }
    fn visit_arrow_function_expression(&mut self, function: &mut ArrowFunctionExpression<'a>) {
        let mut locals = Locals::default();
        locals.visit_formal_parameters(&function.params);
        locals.visit_function_body(&function.body);
        let owned = std::mem::replace(&mut self.owned, locals.0);
        walk_mut::walk_arrow_function_expression(self, function);
        self.owned = owned;
    }
    fn visit_while_statement(&mut self, statement: &mut WhileStatement<'a>) {
        walk_mut::walk_while_statement(self, statement);
        if !matches!(&statement.test, Expression::BooleanLiteral(value) if value.value) {
            return;
        }
        let Statement::BlockStatement(body) = &mut statement.body else {
            return;
        };
        let Some(Statement::IfStatement(guard)) = body.body.first() else {
            return;
        };
        if guard.alternate.is_some()
            || !matches!(&guard.consequent, Statement::BreakStatement(statement) if statement.label.is_none())
        {
            return;
        }
        let test = guard.test.clone_in(self.ast.allocator);
        statement.test = if let Expression::UnaryExpression(unary) = test {
            if unary.operator == UnaryOperator::LogicalNot {
                unary.unbox().argument
            } else {
                self.ast.expression_unary(
                    SPAN,
                    UnaryOperator::LogicalNot,
                    Expression::UnaryExpression(unary),
                )
            }
        } else {
            self.ast
                .expression_unary(SPAN, UnaryOperator::LogicalNot, test)
        };
        body.body.remove(0);
    }
}

fn return_case<'n, 'a>(
    statement: &'n Statement<'a>,
) -> Option<(&'n str, &'n Expression<'a>, &'n Statement<'a>)> {
    let Statement::IfStatement(branch) = statement else {
        return None;
    };
    if branch.alternate.is_some() {
        return None;
    }
    let Expression::BinaryExpression(test) = &branch.test else {
        return None;
    };
    if test.operator.as_str() != "===" || case_key(&test.right).is_none() {
        return None;
    }
    let Expression::Identifier(name) = &test.left else {
        return None;
    };
    let result = if let Statement::BlockStatement(block) = &branch.consequent {
        let [result] = block.body.as_slice() else {
            return None;
        };
        result
    } else {
        &branch.consequent
    };
    if !matches!(result, Statement::ReturnStatement(_)) {
        return None;
    }
    Some((name.name.as_str(), &test.right, result))
}

fn case_key(expression: &Expression<'_>) -> Option<String> {
    let number = match expression {
        Expression::NumericLiteral(number) => number.value,
        Expression::StringLiteral(string) => return Some(format!("s:{}", string.value)),
        Expression::UnaryExpression(unary) if unary.operator == UnaryOperator::UnaryNegation => {
            let Expression::NumericLiteral(number) = &unary.argument else {
                return None;
            };
            -number.value
        }
        _ => return None,
    };
    Some(format!(
        "n:{:016x}",
        if number == 0.0 {
            0.0f64.to_bits()
        } else {
            number.to_bits()
        }
    ))
}

#[derive(Default)]
struct Names {
    ids: BTreeMap<usize, usize>,
    mapping: BTreeMap<String, String>,
}
impl<'a> Visit<'a> for Names {
    fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
        let name = identifier.name.as_str();
        if !name.starts_with("local_") {
            return;
        }
        let Some(frame) = frame_id(name) else {
            return;
        };
        let Some(slot) = name
            .strip_prefix("local_")
            .and_then(|tail| tail.split_once('_'))
            .map(|(_, slot)| slot)
        else {
            return;
        };
        let next = self.ids.len();
        let id = *self.ids.entry(frame).or_insert(next);
        self.mapping
            .insert(name.to_string(), format!("local_{id}_{slot}"));
    }
    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'a>) {
        let _ = declaration;
    }
}

struct Rename<'a, 'n> {
    ast: AstBuilder<'a>,
    mapping: &'n BTreeMap<String, String>,
}
impl<'a> VisitMut<'a> for Rename<'a, '_> {
    fn visit_binding_identifier(&mut self, identifier: &mut BindingIdentifier<'a>) {
        if let Some(name) = self.mapping.get(identifier.name.as_str()) {
            identifier.name = self.ast.atom(name);
        }
    }
    fn visit_identifier_reference(&mut self, identifier: &mut IdentifierReference<'a>) {
        if let Some(name) = self.mapping.get(identifier.name.as_str()) {
            identifier.name = self.ast.atom(name);
        }
    }
}
