use std::collections::BTreeMap;

use oxc::allocator::{Allocator, CloneIn, Vec};
use oxc::ast::{ast::*, AstBuilder, NONE};
use oxc::ast_visit::{walk_mut, Visit, VisitMut};
use oxc::span::SPAN;
use oxc::syntax::operator::AssignmentOperator;

use super::analysis::{pure, temporary, Locals, Usage};
use super::lexical::declaration;
use super::syntax::property_identifier;
use super::temps::assignment;

pub(super) struct Classes<'a> {
    ast: AstBuilder<'a>,
    pub changed: bool,
}

impl<'a> Classes<'a> {
    pub fn new(allocator: &'a Allocator) -> Self {
        Self {
            ast: AstBuilder::new(allocator),
            changed: false,
        }
    }

    fn key(&self, name: &str) -> (PropertyKey<'a>, bool) {
        if property_identifier(name) {
            (
                self.ast
                    .property_key_static_identifier(SPAN, self.ast.atom(name)),
                false,
            )
        } else {
            (
                PropertyKey::StringLiteral(self.ast.alloc_string_literal(
                    SPAN,
                    self.ast.atom(name),
                    None,
                )),
                false,
            )
        }
    }

    fn field(&self, name: &str, value: &Expression<'a>, is_static: bool) -> ClassElement<'a> {
        let (key, computed) = self.key(name);
        self.ast.class_element_property_definition(
            SPAN,
            PropertyDefinitionType::PropertyDefinition,
            self.ast.vec(),
            key,
            NONE,
            Some(value.clone_in(self.ast.allocator)),
            computed,
            is_static,
            false,
            false,
            false,
            false,
            false,
            None,
        )
    }

    fn method(
        &self,
        name: &str,
        function: &Function<'a>,
        kind: MethodDefinitionKind,
        is_static: bool,
    ) -> Option<ClassElement<'a>> {
        if name == "constructor" || (name == "prototype" && is_static) {
            return None;
        }
        if function.id.as_ref().is_some_and(|identifier| {
            function.body.as_ref().is_some_and(|body| {
                Usage::statements(&body.statements).count(&identifier.name) != 0
            })
        }) {
            return None;
        }
        let mut function = function.clone_in(self.ast.allocator);
        function.id = None;
        let (key, computed) = self.key(name);
        Some(self.ast.class_element_method_definition(
            SPAN,
            MethodDefinitionType::MethodDefinition,
            self.ast.vec(),
            key,
            function,
            kind,
            computed,
            is_static,
            false,
            false,
            None,
        ))
    }

    fn promote(&mut self, body: &mut Vec<'a, Statement<'a>>) {
        let mut index = 0;
        while index < body.len() {
            if let Some((target, Expression::ClassExpression(class))) = assignment(&body[index]) {
                if let Some(name) = &class.id {
                    let target = target.to_string();
                    let name = name.name.to_string();
                    let conflicting = body.iter().any(|statement| match statement {
                        Statement::ImportDeclaration(import) => {
                            import.specifiers.as_ref().is_some_and(|specifiers| {
                                specifiers
                                    .iter()
                                    .any(|specifier| specifier.local().name == name)
                            })
                        }
                        Statement::ClassDeclaration(other) => other
                            .id
                            .as_ref()
                            .is_some_and(|identifier| identifier.name == name),
                        Statement::FunctionDeclaration(other) => other
                            .id
                            .as_ref()
                            .is_some_and(|identifier| identifier.name == name),
                        _ => false,
                    });
                    if !conflicting {
                        let mut class = class.clone_in(self.ast.allocator);
                        class.r#type = ClassType::ClassDeclaration;
                        body[index] = Statement::ClassDeclaration(class);
                        if target != name {
                            body.insert(
                                index + 1,
                                self.ast.statement_expression(
                                    SPAN,
                                    self.ast.expression_assignment(
                                        SPAN,
                                        AssignmentOperator::Assign,
                                        AssignmentTarget::AssignmentTargetIdentifier(
                                            self.ast.alloc_identifier_reference(
                                                SPAN,
                                                self.ast.atom(&target),
                                            ),
                                        ),
                                        self.ast.expression_identifier(SPAN, self.ast.atom(&name)),
                                    ),
                                ),
                            );
                            for statement in body[index + 2..].iter_mut() {
                                if assignment(statement).is_some_and(|(binding, value)| binding == name && matches!(value, Expression::Identifier(identifier) if identifier.name == target)) {
                                    *statement = self.ast.statement_empty(SPAN);
                                } else if Usage::statement(statement).writes.contains(&target) { break; }
                            }
                        }
                        for statement in body.iter_mut() {
                            if let Statement::VariableDeclaration(declaration) = statement {
                                declaration.declarations.retain(|declarator| !matches!(&declarator.id.kind, BindingPatternKind::BindingIdentifier(identifier) if identifier.name == name && declarator.init.is_none()));
                            }
                        }
                        self.changed = true;
                    }
                }
            }
            index += 1;
        }
    }

    fn absorb(&mut self, body: &mut Vec<'a, Statement<'a>>) {
        let mut classes = BTreeMap::new();
        for index in 0..body.len() {
            if let Statement::ClassDeclaration(class) = &body[index] {
                if let Some(name) = &class.id {
                    classes.insert(name.name.to_string(), index);
                }
                continue;
            }
            let Statement::ExpressionStatement(statement) = &body[index] else {
                continue;
            };
            let Expression::CallExpression(call) = &statement.expression else {
                continue;
            };
            if let Some((object, key, buffer)) = definition(call) {
                let Some((name, is_static)) = class_receiver(object) else {
                    continue;
                };
                let Some(&class_index) = classes.get(name) else {
                    continue;
                };
                if !body[class_index + 1..index]
                    .iter()
                    .all(|statement| movable(statement))
                {
                    continue;
                }
                let Some(properties) = descriptor(buffer) else {
                    continue;
                };
                let mut methods = self.ast.vec();
                for (property, kind) in [
                    ("value", MethodDefinitionKind::Method),
                    ("get", MethodDefinitionKind::Get),
                    ("set", MethodDefinitionKind::Set),
                ] {
                    if let Some(Expression::FunctionExpression(function)) = properties.get(property)
                    {
                        if let Some(method) = self.method(key, function, kind, is_static) {
                            methods.push(method);
                        }
                    }
                }
                if methods.is_empty() {
                    continue;
                }
                if let Statement::ClassDeclaration(class) = &mut body[class_index] {
                    class.body.body.extend(methods);
                }
                body[index] = self.ast.statement_empty(SPAN);
                self.changed = true;
            } else if let Some(member) = call.callee.get_member_expr() {
                if member.static_property_name() != Some("call") || call.arguments.len() != 1 {
                    continue;
                }
                let Expression::FunctionExpression(function) = member.object() else {
                    continue;
                };
                let Some(Expression::Identifier(receiver)) = call.arguments[0].as_expression()
                else {
                    continue;
                };
                let Some(&class_index) = classes.get(receiver.name.as_str()) else {
                    continue;
                };
                let Some(function_body) = &function.body else {
                    continue;
                };
                let mut fields = self.ast.vec();
                let mut valid = true;
                for statement in &function_body.statements {
                    if matches!(statement, Statement::ReturnStatement(statement) if statement.argument.is_none())
                    {
                        continue;
                    }
                    let Statement::ExpressionStatement(statement) = statement else {
                        valid = false;
                        break;
                    };
                    let Expression::CallExpression(call) = &statement.expression else {
                        valid = false;
                        break;
                    };
                    let Some((Expression::ThisExpression(_), key, object)) = definition(call)
                    else {
                        valid = false;
                        break;
                    };
                    let Some(value) = field_value(object) else {
                        valid = false;
                        break;
                    };
                    if !literal_initializer(value) {
                        valid = false;
                        break;
                    }
                    fields.push(self.field(key, value, true));
                }
                if valid && !fields.is_empty() {
                    if let Statement::ClassDeclaration(class) = &mut body[class_index] {
                        for (index, field) in fields.into_iter().enumerate() {
                            class.body.body.insert(index, field);
                        }
                    }
                    body[index] = self.ast.statement_empty(SPAN);
                    self.changed = true;
                }
            }
        }
    }

    fn aliases(&mut self, program: &mut Program<'a>) {
        let usage = Usage::statements(&program.body);
        let classes: std::collections::BTreeSet<_> = program
            .body
            .iter()
            .filter_map(|statement| match statement {
                Statement::ClassDeclaration(class) => {
                    class.id.as_ref().map(|name| name.name.to_string())
                }
                _ => None,
            })
            .collect();
        let mut aliases = BTreeMap::new();
        for (index, statement) in program.body.iter().enumerate() {
            let Some((alias, Expression::Identifier(value))) = assignment(statement) else {
                continue;
            };
            if !alias.starts_with("local_")
                || !classes.contains(value.name.as_str())
                || usage.assignments.get(alias) != Some(&1)
                || usage.assigned.contains(value.name.as_str())
            {
                continue;
            }
            let mut eager = EagerReads::default();
            for statement in &program.body[..index] {
                eager.visit_statement(statement);
            }
            if !eager.0.contains(alias) {
                aliases.insert(alias.to_string(), value.name.to_string());
            }
        }
        if aliases.is_empty() {
            return;
        }
        Alias {
            ast: self.ast,
            aliases: &aliases,
            shadowed: std::collections::BTreeSet::new(),
        }
        .visit_program(program);
        self.changed = true;
    }

    fn constructor(&mut self, body: &mut FunctionBody<'a>) {
        let usage = Usage::statements(&body.statements);
        if usage.assignments.get("__this") != Some(&1) || usage.captured.contains("__this") {
            return;
        }
        for index in 0..body.statements.len() {
            if let Some(("__this", Expression::CallExpression(call))) =
                assignment(&body.statements[index])
            {
                if matches!(&call.callee, Expression::Super(_))
                    && Usage::statements(&body.statements[..index]).count("__this") == 0
                    && Usage::expression(&call.callee).count("__this") == 0
                {
                    let super_call = Expression::CallExpression(call.clone_in(self.ast.allocator));
                    body.statements[index] = self.ast.statement_expression(SPAN, super_call);
                    DirectThis {
                        ast: self.ast,
                        alias: "__this",
                    }
                    .visit_statements(&mut body.statements);
                    self.changed = true;
                    break;
                }
            }
            let Some((alias, Expression::AssignmentExpression(store))) =
                assignment(&body.statements[index])
            else {
                continue;
            };
            if !alias.starts_with("local_")
                || usage.assignments.get(alias) != Some(&2)
                || !matches!(&store.left, AssignmentTarget::AssignmentTargetIdentifier(identifier) if identifier.name == "__this")
            {
                continue;
            }
            let Expression::CallExpression(call) = &store.right else {
                continue;
            };
            if !matches!(&call.callee, Expression::Super(_)) {
                continue;
            }
            let alias = alias.to_string();
            let super_call = store.right.clone_in(self.ast.allocator);
            let inputs = Usage::expression(&super_call);
            if inputs.count("__this") != 0 || inputs.count(&alias) != 0 {
                continue;
            }
            let before = Usage::statements(&body.statements[..index]);
            if before.count(&alias) != 0 || before.count("__this") != 1 {
                continue;
            }
            let Some(initial) = body.statements[..index].iter().position(|statement| assignment(statement).is_some_and(|(target, value)| target == alias && matches!(value, Expression::Identifier(identifier) if identifier.name == "__this"))) else { continue; };
            body.statements[initial] = self.ast.statement_empty(SPAN);
            body.statements[index] = self.ast.statement_expression(SPAN, super_call);
            for statement in &mut body.statements {
                if let Statement::VariableDeclaration(declaration) = statement {
                    declaration.declarations.retain(|declarator| !matches!(&declarator.id.kind, BindingPatternKind::BindingIdentifier(identifier) if identifier.name == alias && declarator.init.is_none()));
                }
            }
            let this = self.ast.expression_this(SPAN);
            DirectThis {
                ast: self.ast,
                alias: "__this",
            }
            .visit_statements(&mut body.statements);
            DirectThis {
                ast: self.ast,
                alias: &alias,
            }
            .visit_statements(&mut body.statements);
            body.statements.insert(
                index + 1,
                declaration(self.ast, &alias, Some(this), VariableDeclarationKind::Const),
            );
            self.changed = true;
            break;
        }
    }
}

impl<'a> VisitMut<'a> for Classes<'a> {
    fn visit_program(&mut self, program: &mut Program<'a>) {
        walk_mut::walk_program(self, program);
        self.promote(&mut program.body);
        self.absorb(&mut program.body);
        self.aliases(program);
        program.body.retain(|statement| !matches!(statement, Statement::EmptyStatement(_))
            && !matches!(statement, Statement::VariableDeclaration(declaration) if declaration.declarations.is_empty()));
    }

    fn visit_class(&mut self, class: &mut Class<'a>) {
        walk_mut::walk_class(self, class);
        let mut fields = self.ast.vec();
        for element in &mut class.body.body {
            let ClassElement::MethodDefinition(method) = element else {
                continue;
            };
            if let Some(name) = method.key.static_name() {
                if method.computed && property_identifier(&name) {
                    method.key = self
                        .ast
                        .property_key_static_identifier(SPAN, self.ast.atom(&name));
                    method.computed = false;
                    self.changed = true;
                }
            }
            let constructor = method.kind == MethodDefinitionKind::Constructor;
            let Some(body) = &mut method.value.body else {
                continue;
            };
            if constructor {
                if class.super_class.is_some() {
                    self.constructor(body);
                }
                let mut count = 0;
                for statement in &body.statements {
                    let Statement::ExpressionStatement(statement) = statement else {
                        break;
                    };
                    let Expression::CallExpression(call) = &statement.expression else {
                        break;
                    };
                    let Some((Expression::ThisExpression(_), key, object)) = definition(call)
                    else {
                        break;
                    };
                    let Some(value) = field_value(object) else {
                        break;
                    };
                    if !literal_initializer(value) {
                        break;
                    }
                    fields.push(self.field(key, value, false));
                    count += 1;
                }
                if count != 0 {
                    body.statements.drain(..count);
                    self.changed = true;
                }
                if matches!(body.statements.last(), Some(Statement::ReturnStatement(statement)) if matches!(&statement.argument, Some(Expression::ThisExpression(_))))
                {
                    body.statements.pop();
                    self.changed = true;
                }
            }
            if matches!(body.statements.last(), Some(Statement::ReturnStatement(statement)) if statement.argument.is_none())
            {
                body.statements.pop();
                self.changed = true;
            }
        }
        for (index, field) in fields.into_iter().enumerate() {
            class.body.body.insert(index, field);
        }
        class.body.body.retain(|element| !matches!(element, ClassElement::MethodDefinition(method) if class.super_class.is_none() && method.kind == MethodDefinitionKind::Constructor && method.value.params.items.is_empty() && method.value.body.as_ref().is_some_and(|body| body.statements.is_empty())));
    }
}

struct DirectThis<'a, 'n> {
    ast: AstBuilder<'a>,
    alias: &'n str,
}
impl<'a> VisitMut<'a> for DirectThis<'a, '_> {
    fn visit_expression(&mut self, expression: &mut Expression<'a>) {
        if matches!(expression, Expression::Identifier(identifier) if identifier.name == self.alias)
        {
            *expression = self.ast.expression_this(SPAN);
        } else {
            walk_mut::walk_expression(self, expression);
        }
    }
    fn visit_function(
        &mut self,
        function: &mut Function<'a>,
        flags: oxc::syntax::scope::ScopeFlags,
    ) {
        let _ = (function, flags);
    }
    fn visit_class(&mut self, class: &mut Class<'a>) {
        let _ = class;
    }
    fn visit_assignment_target(&mut self, target: &mut AssignmentTarget<'a>) {
        // Member receivers are expression positions; binding stores are not.
        walk_mut::walk_assignment_target(self, target);
    }
}

#[derive(Default)]
struct EagerReads(std::collections::BTreeSet<String>);
impl<'a> Visit<'a> for EagerReads {
    fn visit_identifier_reference(&mut self, identifier: &IdentifierReference<'a>) {
        self.0.insert(identifier.name.to_string());
    }
    fn visit_function(&mut self, function: &Function<'a>, flags: oxc::syntax::scope::ScopeFlags) {
        let _ = (function, flags);
    }
    fn visit_class(&mut self, class: &Class<'a>) {
        if let Some(base) = &class.super_class {
            self.visit_expression(base);
        }
        for element in &class.body.body {
            match element {
                ClassElement::StaticBlock(block) => self.visit_statements(&block.body),
                ClassElement::PropertyDefinition(property) => {
                    if property.computed {
                        self.visit_property_key(&property.key);
                    }
                    if property.r#static {
                        if let Some(value) = &property.value {
                            self.visit_expression(value);
                        }
                    }
                }
                ClassElement::MethodDefinition(method) if method.computed => {
                    self.visit_property_key(&method.key)
                }
                _ => {}
            }
        }
    }
}

struct Alias<'a, 'n> {
    ast: AstBuilder<'a>,
    aliases: &'n BTreeMap<String, String>,
    shadowed: std::collections::BTreeSet<String>,
}
impl<'a> VisitMut<'a> for Alias<'a, '_> {
    fn visit_statement(&mut self, statement: &mut Statement<'a>) {
        if assignment(statement).is_some_and(|(name, _)| {
            self.aliases.contains_key(name) && !self.shadowed.contains(name)
        }) {
            *statement = self.ast.statement_empty(SPAN);
        } else {
            walk_mut::walk_statement(self, statement);
        }
    }
    fn visit_variable_declaration(&mut self, declaration: &mut VariableDeclaration<'a>) {
        declaration.declarations.retain(|declarator| !matches!(&declarator.id.kind, BindingPatternKind::BindingIdentifier(identifier) if self.aliases.contains_key(identifier.name.as_str()) && !self.shadowed.contains(identifier.name.as_str()) && declarator.init.is_none()));
        walk_mut::walk_variable_declaration(self, declaration);
    }
    fn visit_identifier_reference(&mut self, identifier: &mut IdentifierReference<'a>) {
        if !self.shadowed.contains(identifier.name.as_str()) {
            if let Some(name) = self.aliases.get(identifier.name.as_str()) {
                identifier.name = self.ast.atom(name);
            }
        }
    }
    fn visit_function(
        &mut self,
        function: &mut Function<'a>,
        flags: oxc::syntax::scope::ScopeFlags,
    ) {
        let mut locals = Locals::default();
        locals.visit_formal_parameters(&function.params);
        if let Some(body) = &function.body {
            locals.visit_function_body(body);
        }
        let before = self.shadowed.clone();
        self.shadowed.extend(locals.0);
        walk_mut::walk_function(self, function, flags);
        self.shadowed = before;
    }
}

fn definition<'n, 'a>(
    call: &'n CallExpression<'a>,
) -> Option<(&'n Expression<'a>, &'n str, &'n ObjectExpression<'a>)> {
    let member = call.callee.get_member_expr()?;
    if member.static_property_name() != Some("defineProperty")
        || !matches!(member.object(), Expression::Identifier(identifier) if identifier.name == "Object")
        || call.arguments.len() != 3
    {
        return None;
    }
    let object = call.arguments[0].as_expression()?;
    let Expression::StringLiteral(key) = call.arguments[1].as_expression()? else {
        return None;
    };
    let Expression::ObjectExpression(descriptor) = call.arguments[2].as_expression()? else {
        return None;
    };
    Some((object, key.value.as_str(), descriptor))
}

fn descriptor<'n, 'a>(
    object: &'n ObjectExpression<'a>,
) -> Option<BTreeMap<String, &'n Expression<'a>>> {
    let mut properties = BTreeMap::new();
    for property in &object.properties {
        let ObjectPropertyKind::ObjectProperty(property) = property else {
            return None;
        };
        properties.insert(property.key.static_name()?.to_string(), &property.value);
    }
    for name in ["writable", "enumerable", "configurable"] {
        if properties
            .get(name)
            .is_some_and(|value| !matches!(value, Expression::BooleanLiteral(value) if value.value))
        {
            return None;
        }
    }
    Some(properties)
}

fn field_value<'n, 'a>(object: &'n ObjectExpression<'a>) -> Option<&'n Expression<'a>> {
    descriptor(object)?.get("value").copied()
}

fn literal_initializer(expression: &Expression<'_>) -> bool {
    pure(expression)
        && Usage::expression(expression)
            .reads
            .keys()
            .all(|name| name == "undefined")
}

fn class_receiver<'n>(expression: &'n Expression<'_>) -> Option<(&'n str, bool)> {
    if let Expression::Identifier(identifier) = expression {
        return Some((identifier.name.as_str(), true));
    }
    let member = expression.get_member_expr()?;
    if member.static_property_name() != Some("prototype") {
        return None;
    }
    let Expression::Identifier(identifier) = member.object() else {
        return None;
    };
    Some((identifier.name.as_str(), false))
}

fn movable(statement: &Statement<'_>) -> bool {
    matches!(
        statement,
        Statement::EmptyStatement(_) | Statement::VariableDeclaration(_)
    ) || assignment(statement).is_some_and(|(name, value)| {
        temporary(name)
            && (pure(value)
                || value
                    .get_member_expr()
                    .is_some_and(|member| member.static_property_name() == Some("prototype")))
    })
}
