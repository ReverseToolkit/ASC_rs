//! On-demand Ark bytecode disassembly and JavaScript reconstruction.
//!
//! The necessary parser, instruction semantics, and control-flow pipeline are
//! adapted from xpanda-core (asmjmp0/xpanda, Apache-2.0). No JavaScript runtime,
//! Babel optimizer, archive reader, or UI is required by this crate.

mod cfg;
mod codegen;
mod decode;
mod file;
mod lower;
mod optimize;

pub use codegen::Decompiler;
pub use decode::{decode, Instruction, Opcode, Operand};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum OutputMode {
    #[default]
    Source,
    Assembly,
}

impl OutputMode {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Source => "js",
            Self::Assembly => "pa",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Abc(#[from] asc_abc::Error),
    #[error("invalid ABC data: {0}")]
    Invalid(String),
    #[error("unsupported instruction {name} at pc {pc:#x}")]
    UnsupportedInstruction { name: String, pc: u32 },
    #[error("class {0} not found in ABC")]
    ClassNotFound(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) struct SizeBudget {
    remaining: usize,
    resource: &'static str,
}

impl SizeBudget {
    pub fn new(resource: &'static str) -> Self {
        Self {
            remaining: 64 * 1024 * 1024,
            resource,
        }
    }

    pub fn charge(&mut self, bytes: usize) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(|| Error::invalid(format!("{} exceeds 64 MiB", self.resource)))?;
        Ok(())
    }
}

impl Error {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}
