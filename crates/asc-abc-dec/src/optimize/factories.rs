use std::collections::BTreeMap;

use oxc::allocator::{Allocator, CloneIn};
use oxc::ast::{ast::*, AstBuilder};
use oxc::ast_visit::{walk_mut, Visit, VisitMut};
use oxc::syntax::scope::ScopeFlags;

use super::analysis::Usage;

enum Template<'a> {
    Function(Expression<'a>),
    Class {
        base: Expression<'a>,
        derived: Expression<'a>,
    },
}

pub(super) struct Factories<'a> {
    ast: AstBuilder<'a>,
    templates: BTreeMap<String, Template<'a>>,
    next: usize,
    has_entry: bool,
    pub changed: bool,
}

impl<'a> Factories<'a> {
    pub fn new(allocator: &'a Allocator, program: &Program<'a>, has_entry: bool) -> Self {
        let ast = AstBuilder::new(allocator);
        let mut templates = BTreeMap::new();
        for statement in &program.body {
            let Statement::FunctionDeclaration(function) = statement else {
                continue;
            };
            let Some(name) = &function.id else {
                continue;
            };
            let Some(body) = &function.body else {
                continue;
            };
            if name.name.starts_with("__fn_") && body.statements.len() == 1 {
                if let Some(expression @ Expression::FunctionExpression(_)) =
                    returned(&body.statements[0])
                {
                    templates.insert(
                        name.name.to_string(),
                        Template::Function(expression.clone_in(allocator)),
                    );
                }
            } else if name.name.starts_with("__class_") && body.statements.len() == 2 {
                let Statement::IfStatement(branch) = &body.statements[0] else {
                    continue;
                };
                if let (
                    Some(base @ Expression::ClassExpression(_)),
                    Some(derived @ Expression::ClassExpression(_)),
                ) = (returned(&branch.consequent), returned(&body.statements[1]))
                {
                    templates.insert(
                        name.name.to_string(),
                        Template::Class {
                            base: base.clone_in(allocator),
                            derived: derived.clone_in(allocator),
                        },
                    );
                }
            }
        }
        let mut scopes = ScopeNames::default();
        scopes.visit_program(program);
        Self {
            ast,
            templates,
            next: scopes.next,
            has_entry,
            changed: false,
        }
    }

    fn fresh_scopes(&mut self, expression: &mut Expression<'a>) {
        let mut names = ScopeNames::default();
        names.visit_expression(expression);
        let mut mapping = BTreeMap::new();
        for id in names.ids {
            mapping.insert(format!("__scope_{id}"), format!("__scope_{}", self.next));
            for local in &names.names {
                if let Some(slot) = local.strip_prefix(&format!("local_{id}_")) {
                    mapping.insert(local.clone(), format!("local_{}_{slot}", self.next));
                }
            }
            self.next += 1;
        }
        Rename {
            ast: self.ast,
            mapping: &mapping,
        }
        .visit_expression(expression);
    }
}

impl<'a> VisitMut<'a> for Factories<'a> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        walk_mut::walk_expression(self, expression);
        let Expression::CallExpression(call) = expression else {
            return;
        };
        let Expression::Identifier(identifier) = &call.callee else {
            return;
        };
        let Some(template) = self.templates.get(identifier.name.as_str()) else {
            return;
        };
        let parent = call.arguments.first().and_then(Argument::as_expression);
        let mut value = match template {
            Template::Function(expression) => expression.clone_in(self.ast.allocator),
            Template::Class { base, derived } => {
                let Some(proto) = call.arguments.get(1).and_then(Argument::as_expression) else {
                    return;
                };
                let mut value = if sentinel(proto) {
                    base.clone_in(self.ast.allocator)
                } else if matches!(proto, Expression::Identifier(identifier) if !super::analysis::temporary(&identifier.name))
                    || matches!(
                        proto,
                        Expression::StaticMemberExpression(_)
                            | Expression::ComputedMemberExpression(_)
                    )
                {
                    derived.clone_in(self.ast.allocator)
                } else {
                    return;
                };
                Capture {
                    ast: self.ast,
                    name: "__proto",
                    value: proto,
                }
                .visit_expression(&mut value);
                value
            }
        };
        let usage = Usage::expression(&value);
        if usage.count("__parentEnv") != 0 {
            let Some(parent) = parent else {
                return;
            };
            if !stable_frame(parent) {
                return;
            }
            Capture {
                ast: self.ast,
                name: "__parentEnv",
                value: parent,
            }
            .visit_expression(&mut value);
        }
        if usage.count("__home") != 0 {
            let Some(home) = call.arguments.get(1).and_then(Argument::as_expression) else {
                return;
            };
            if !stable_frame(home) {
                return;
            }
            Capture {
                ast: self.ast,
                name: "__home",
                value: home,
            }
            .visit_expression(&mut value);
        }
        self.fresh_scopes(&mut value);
        *expression = value;
        self.changed = true;
    }

    fn visit_program(&mut self, program: &mut Program<'a>) {
        walk_mut::walk_program(self, program);
        if !self.has_entry {
            return;
        }
        let usage = Usage::statements(&program.body);
        program.body.retain(|statement| {
            if let Statement::FunctionDeclaration(function) = statement {
                if function.id.as_ref().is_some_and(|name| {
                    self.templates.contains_key(name.name.as_str()) && usage.count(&name.name) == 0
                }) {
                    self.changed = true;
                    return false;
                }
            }
            true
        });
        let mut output = self.ast.vec();
        for statement in std::mem::replace(&mut program.body, self.ast.vec()) {
            if let Statement::ExpressionStatement(statement) = &statement {
                if let Expression::CallExpression(call) = &statement.expression {
                    if let Expression::FunctionExpression(function) = &call.callee {
                        if function
                            .id
                            .as_ref()
                            .is_some_and(|name| name.name == "func_main_0")
                            && function.params.items.is_empty()
                            && call.arguments.is_empty()
                        {
                            if let Some(body) = &function.body {
                                let mut body = body.statements.clone_in(self.ast.allocator);
                                if matches!(body.last(), Some(Statement::ReturnStatement(statement)) if statement.argument.is_none())
                                {
                                    body.pop();
                                }
                                let mut check = EntryCheck { valid: true };
                                for statement in &body {
                                    check.visit_statement(statement);
                                }
                                if check.valid {
                                    output.extend(body);
                                    self.changed = true;
                                    continue;
                                }
                            }
                        }
                    }
                }
            }
            output.push(statement);
        }
        program.body = output;
    }
}

fn returned<'n, 'a>(statement: &'n Statement<'a>) -> Option<&'n Expression<'a>> {
    match statement {
        Statement::ReturnStatement(statement) => statement.argument.as_ref(),
        Statement::BlockStatement(block) if block.body.len() == 1 => returned(&block.body[0]),
        _ => None,
    }
}

fn sentinel(expression: &Expression<'_>) -> bool {
    matches!(expression, Expression::NullLiteral(_))
        || matches!(expression, Expression::Identifier(identifier) if matches!(identifier.name.as_str(), "__hole" | "undefined"))
        || matches!(expression, Expression::UnaryExpression(expression) if expression.operator.as_str() == "void" && matches!(&expression.argument, Expression::NumericLiteral(value) if value.value == 0.0))
}

fn stable_frame(expression: &Expression<'_>) -> bool {
    sentinel(expression)
        || matches!(expression, Expression::Identifier(identifier) if identifier.name == "__parentEnv" || identifier.name.starts_with("__scope_"))
}

struct Capture<'a, 'n> {
    ast: AstBuilder<'a>,
    name: &'n str,
    value: &'n Expression<'a>,
}

impl<'a> VisitMut<'a> for Capture<'a, '_> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        if matches!(expression, Expression::Identifier(identifier) if identifier.name == self.name)
        {
            *expression = self.value.clone_in(self.ast.allocator);
        } else {
            walk_mut::walk_expression(self, expression);
        }
    }
    fn visit_function(&mut self, function: &mut Function<'a>, flags: ScopeFlags) {
        if !function.params.items.iter().any(|parameter| matches!(&parameter.pattern.kind, BindingPatternKind::BindingIdentifier(identifier) if identifier.name == self.name)) {
            walk_mut::walk_function(self, function, flags);
        }
    }
}

#[derive(Default)]
struct ScopeNames {
    names: std::collections::BTreeSet<String>,
    ids: std::collections::BTreeSet<usize>,
    next: usize,
}

impl<'a> Visit<'a> for ScopeNames {
    fn visit_binding_identifier(&mut self, identifier: &BindingIdentifier<'a>) {
        if let Some(id) = super::lexical::frame_id(&identifier.name) {
            self.names.insert(identifier.name.to_string());
            self.ids.insert(id);
            self.next = self.next.max(id + 1);
        }
    }
}

struct Rename<'a, 'n> {
    ast: AstBuilder<'a>,
    mapping: &'n BTreeMap<String, String>,
}
impl<'a> VisitMut<'a> for Rename<'a, '_> {
    fn visit_identifier_reference(&mut self, identifier: &mut IdentifierReference<'a>) {
        if let Some(name) = self.mapping.get(identifier.name.as_str()) {
            identifier.name = self.ast.atom(name);
        }
    }
    fn visit_binding_identifier(&mut self, identifier: &mut BindingIdentifier<'a>) {
        if let Some(name) = self.mapping.get(identifier.name.as_str()) {
            identifier.name = self.ast.atom(name);
        }
    }
}

struct EntryCheck {
    valid: bool,
}
impl<'a> Visit<'a> for EntryCheck {
    fn visit_function(&mut self, function: &Function<'a>, flags: ScopeFlags) {
        let _ = (function, flags);
    }
    fn visit_return_statement(&mut self, statement: &ReturnStatement<'a>) {
        let _ = statement;
        self.valid = false;
    }
    fn visit_meta_property(&mut self, property: &MetaProperty<'a>) {
        let _ = property;
        self.valid = false;
    }
}
