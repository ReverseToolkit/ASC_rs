use std::collections::BTreeSet;

use oxc::allocator::{Allocator, CloneIn, Vec};
use oxc::ast::{ast::*, AstBuilder};
use oxc::ast_visit::{walk_mut, Visit, VisitMut};
use oxc::span::SPAN;
use oxc::syntax::scope::ScopeFlags;

use super::analysis::{pure, temporary, Locals, Usage};
use super::syntax::property_identifier;
use super::temps::assignment;

pub(super) struct Objects<'a> {
    ast: AstBuilder<'a>,
    usage: Usage,
    owned: BTreeSet<String>,
    pub changed: bool,
}
impl<'a> Objects<'a> {
    pub fn new(allocator: &'a Allocator, program: &Program<'a>) -> Self {
        let mut locals = Locals::default();
        locals.visit_program(program);
        Self {
            ast: AstBuilder::new(allocator),
            usage: Usage::statements(&program.body),
            owned: locals.0,
            changed: false,
        }
    }

    fn literals(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        for index in 0..statements.len() {
            let Some((target, Expression::ObjectExpression(object))) =
                assignment(&statements[index])
            else {
                continue;
            };
            if !temporary(target)
                || !self.owned.contains(target)
                || self.usage.captured.contains(target)
                || !initial(object)
            {
                continue;
            }
            let target = target.to_string();
            let mut object = object.clone_in(self.ast.allocator);
            let sensitive = object
                .properties
                .iter()
                .enumerate()
                .filter_map(|(position, property)| {
                    let ObjectPropertyKind::ObjectProperty(property) = property else {
                        return None;
                    };
                    (!snapshot(&property.value)).then_some(position)
                })
                .next_back();
            let mut consumed = std::vec::Vec::new();
            let mut defined = BTreeSet::new();
            let mut previous = None;
            for (offset, statement) in statements[index + 1..].iter().enumerate() {
                let Some((receiver, key, value)) = definition(statement) else {
                    break;
                };
                if receiver != target
                    || !defined.insert(key.to_string())
                    || Usage::expression(value).count(&target) != 0
                {
                    break;
                }
                let position = object.properties.iter().position(|property| matches!(property, ObjectPropertyKind::ObjectProperty(property) if property.key.static_name().as_deref() == Some(key))).unwrap_or(object.properties.len());
                if sensitive.is_some_and(|sensitive| position <= sensitive) {
                    break;
                }
                // Property evaluation must follow the bytecode store order,
                // while existing keys keep their original enumeration order.
                if previous.is_some_and(|previous| position < previous) {
                    break;
                }
                previous = Some(position);
                if let Some(ObjectPropertyKind::ObjectProperty(property)) =
                    object.properties.get_mut(position)
                {
                    property.value = value.clone_in(self.ast.allocator);
                } else {
                    let (key, computed) = if property_identifier(key) && key != "__proto__" {
                        (
                            self.ast
                                .property_key_static_identifier(SPAN, self.ast.atom(key)),
                            false,
                        )
                    } else {
                        (
                            PropertyKey::StringLiteral(self.ast.alloc_string_literal(
                                SPAN,
                                self.ast.atom(key),
                                None,
                            )),
                            key == "__proto__",
                        )
                    };
                    object
                        .properties
                        .push(self.ast.object_property_kind_object_property(
                            SPAN,
                            PropertyKind::Init,
                            key,
                            value.clone_in(self.ast.allocator),
                            false,
                            false,
                            computed,
                        ));
                }
                consumed.push(index + 1 + offset);
            }
            if consumed.is_empty() {
                continue;
            }
            let Statement::ExpressionStatement(statement) = &mut statements[index] else {
                unreachable!("matched literal assignment")
            };
            let Expression::AssignmentExpression(store) = &mut statement.expression else {
                unreachable!("matched literal assignment")
            };
            store.right = Expression::ObjectExpression(object);
            for index in consumed {
                statements[index] = self.ast.statement_empty(SPAN);
            }
            self.changed = true;
        }
        statements.retain(|statement| !matches!(statement, Statement::EmptyStatement(_)));
    }
}

impl<'a> VisitMut<'a> for Objects<'a> {
    fn visit_statements(&mut self, statements: &mut Vec<'a, Statement<'a>>) {
        self.literals(statements);
        walk_mut::walk_statements(self, statements);
    }
    fn visit_function(&mut self, function: &mut Function<'a>, flags: ScopeFlags) {
        let mut locals = Locals::default();
        locals.visit_formal_parameters(&function.params);
        let usage = function
            .body
            .as_ref()
            .map(|body| {
                locals.visit_function_body(body);
                Usage::statements(&body.statements)
            })
            .unwrap_or_default();
        let outer = std::mem::replace(&mut self.usage, usage);
        let owned = std::mem::replace(&mut self.owned, locals.0);
        walk_mut::walk_function(self, function, flags);
        self.usage = outer;
        self.owned = owned;
    }
}

fn initial(object: &ObjectExpression<'_>) -> bool {
    let mut names = BTreeSet::new();
    object.properties.iter().all(|property| {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            return false;
        };
        let Some(name) = property.key.static_name() else {
            return false;
        };
        !property.computed
            && !property.method
            && property.kind == PropertyKind::Init
            && name != "__proto__"
            && names.insert(name.to_string())
    })
}

fn snapshot(value: &Expression<'_>) -> bool {
    pure(value)
        && Usage::eager_expression(value)
            .reads
            .keys()
            .all(|name| name == "undefined")
}

fn definition<'n, 'a>(
    statement: &'n Statement<'a>,
) -> Option<(&'n str, &'n str, &'n Expression<'a>)> {
    let Statement::ExpressionStatement(statement) = statement else {
        return None;
    };
    let Expression::CallExpression(call) = &statement.expression else {
        return None;
    };
    let member = call.callee.get_member_expr()?;
    if member.static_property_name() != Some("defineProperty")
        || !matches!(member.object(), Expression::Identifier(identifier) if identifier.name == "Object")
        || call.arguments.len() != 3
    {
        return None;
    }
    let Expression::Identifier(receiver) = call.arguments[0].as_expression()? else {
        return None;
    };
    let Expression::StringLiteral(key) = call.arguments[1].as_expression()? else {
        return None;
    };
    let Expression::ObjectExpression(descriptor) = call.arguments[2].as_expression()? else {
        return None;
    };
    let mut value = None;
    let mut attributes = BTreeSet::new();
    for property in &descriptor.properties {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            return None;
        };
        if property.computed {
            return None;
        }
        let name = property.key.static_name()?;
        if !attributes.insert(name.to_string()) {
            return None;
        }
        if name == "value" {
            value = Some(&property.value);
        } else if !matches!(name.as_ref(), "writable" | "enumerable" | "configurable")
            || !matches!(&property.value, Expression::BooleanLiteral(value) if value.value)
        {
            return None;
        }
    }
    if attributes.len() != 4 {
        return None;
    }
    Some((receiver.name.as_str(), key.value.as_str(), value?))
}
