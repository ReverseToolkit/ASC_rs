use oxc::allocator::Allocator;
use oxc::ast_visit::VisitMut;
use oxc::codegen::{Codegen, CodegenOptions};
use oxc::minifier::{CompressOptions, Compressor};
use oxc::parser::{ParseOptions, Parser};
use oxc::span::SourceType;

use crate::{Error, Result, SizeBudget};

mod analysis;
mod branches;
mod classes;
mod factories;
mod finally;
mod globals;
mod initialized;
mod lexical;
mod objects;
mod polish;
mod syntax;
mod temps;

#[cfg(test)]
pub(crate) mod tests;

pub(crate) fn source(source: &str, has_entry: bool) -> Result<String> {
    let header = source
        .lines()
        .take(2)
        .collect::<std::vec::Vec<_>>()
        .join("\n");
    let mut current = source.to_string();
    let mut records = None;
    for round in 0..48 {
        // Releasing each arena bounds the memory used by cloning AST templates.
        let allocator = Allocator::default();
        let parsed = Parser::new(&allocator, &current, SourceType::mjs())
            .with_options(ParseOptions {
                preserve_parens: false,
                ..ParseOptions::default()
            })
            .parse();
        if let Some(error) = parsed.errors.first() {
            let offset = error
                .labels
                .as_ref()
                .and_then(|labels| labels.first())
                .map_or(0, |label| label.offset());
            let context: String = current
                .chars()
                .skip(
                    current
                        .char_indices()
                        .take_while(|(byte, _)| *byte < offset)
                        .count()
                        .saturating_sub(80),
                )
                .take(160)
                .collect();
            return Err(Error::invalid(format!("generated JavaScript at optimization round {round}, byte {offset}: {error}; near {context:?}")));
        }
        let mut program = parsed.program;
        let records = records.get_or_insert_with(|| globals::records(&program));
        globals::Globals::new(&allocator, records, &program, round == 0)
            .visit_program(&mut program);
        let mut lexical = lexical::Lexical::new(&allocator, &program);
        lexical.visit_program(&mut program);
        let mut factories = factories::Factories::new(&allocator, &program, has_entry);
        factories.visit_program(&mut program);
        let mut syntax = syntax::Syntax::new(&allocator, &program);
        syntax.visit_program(&mut program);
        let mut branches = branches::Branches::new(&allocator, &program);
        branches.visit_program(&mut program);
        let mut classes = classes::Classes::new(&allocator);
        classes.visit_program(&mut program);
        let mut initialized = initialized::Initialized::new(&allocator, &program);
        initialized.visit_program(&mut program);
        let mut finally = finally::Finally::new(&allocator);
        finally.visit_program(&mut program);
        let mut objects = objects::Objects::new(&allocator, &program);
        objects.visit_program(&mut program);
        let mut temps = temps::Temps::new(&allocator);
        temps.visit_program(&mut program);
        Compressor::new(&allocator, CompressOptions::safest()).dead_code_elimination(&mut program);
        let changed = temps.changed
            || syntax.changed
            || branches.changed
            || lexical.changed
            || factories.changed
            || classes.changed
            || initialized.changed
            || finally.changed
            || objects.changed;
        syntax::Syntax::new(&allocator, &program).visit_program(&mut program);
        let output = Codegen::new().build(&program).code;
        SizeBudget::new("optimized source").charge(output.len())?;
        if !changed || output == current {
            current = output;
            break;
        }
        current = output;
    }
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, &current, SourceType::mjs())
        .with_options(ParseOptions {
            preserve_parens: false,
            ..ParseOptions::default()
        })
        .parse();
    if let Some(error) = parsed.errors.first() {
        return Err(Error::invalid(format!("optimized JavaScript: {error}")));
    }
    let mut program = parsed.program;
    polish::Polish::new(&allocator).visit_program(&mut program);
    current = Codegen::new()
        .with_options(CodegenOptions {
            annotation_comments: false,
            ..CodegenOptions::default()
        })
        .build(&program)
        .code;
    SizeBudget::new("formatted source").charge(current.len())?;
    if !current.starts_with("// ABC record:") && header.starts_with("// ABC record:") {
        current.insert_str(0, &format!("{header}\n"));
    }
    Ok(current)
}
