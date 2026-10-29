use crate::{Error, Result};

pub(crate) const TYPE_ID: u32 = 1;
pub(crate) const FIELD_ID: u32 = 0x10;
pub(crate) const JUMP: u32 = 0x200;
pub(crate) const CONDITIONAL: u32 = 0x400;

#[derive(Clone, Copy, Debug)]
pub struct Opcode {
    pub name: &'static str,
    pub format: &'static str,
    pub flags: u32,
}

include!(concat!(env!("OUT_DIR"), "/opcodes.rs"));

#[derive(Clone, Debug, PartialEq)]
pub enum Operand {
    Immediate(i64),
    Float(f64),
    Register(u32),
    Id(u32),
}

#[derive(Clone, Debug)]
pub struct Instruction {
    pub pc: u32,
    pub next_pc: u32,
    pub opcode: Opcode,
    pub operands: Vec<Operand>,
}

impl Instruction {
    pub fn jump_target(&self) -> Result<Option<u32>> {
        if self.opcode.flags & JUMP == 0 {
            return Ok(None);
        }
        let displacement = self
            .operands
            .iter()
            .rev()
            .find_map(|operand| match operand {
                Operand::Immediate(value) => Some(*value),
                Operand::Float(_) | Operand::Register(_) | Operand::Id(_) => None,
            })
            .ok_or_else(|| Error::invalid("jump has no displacement"))?;
        let target = i64::from(self.pc)
            .checked_add(displacement)
            .and_then(|target| u32::try_from(target).ok())
            .ok_or_else(|| Error::invalid(format!("jump target out of range at {:#x}", self.pc)))?;
        Ok(Some(target))
    }

    pub(crate) fn imm(&self, index: usize) -> Result<i64> {
        match self.operands.get(index) {
            Some(Operand::Immediate(value)) => Ok(*value),
            _ => Err(Error::invalid(format!(
                "{} expects immediate {index}",
                self.opcode.name
            ))),
        }
    }

    pub(crate) fn reg(&self, index: usize) -> Result<u32> {
        match self.operands.get(index) {
            Some(Operand::Register(value)) => Ok(*value),
            _ => Err(Error::invalid(format!(
                "{} expects register {index}",
                self.opcode.name
            ))),
        }
    }

    pub(crate) fn id(&self, index: usize) -> Result<u32> {
        match self.operands.get(index) {
            Some(Operand::Id(value)) => Ok(*value),
            _ => Err(Error::invalid(format!(
                "{} expects id {index}",
                self.opcode.name
            ))),
        }
    }
}

/// Decode the full instruction stream, including wide/deprecated/runtime prefixes.
pub fn decode(bytes: &[u8]) -> Result<Vec<Instruction>> {
    let mut instructions = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let pc = u32::try_from(pos).map_err(|_| Error::invalid("method exceeds u32"))?;
        let first = bytes[pos];
        pos += 1;
        let code = if first >= 251 {
            let second = *bytes
                .get(pos)
                .ok_or_else(|| Error::invalid("truncated opcode prefix"))?;
            pos += 1;
            u16::from(first) | (u16::from(second) << 8)
        } else {
            u16::from(first)
        };
        let opcode = opcode(code)
            .ok_or_else(|| Error::invalid(format!("unknown opcode {code:#x} at {pc:#x}")))?;
        let mut operands = Vec::new();
        let mut nibble = 0;
        for part in opcode
            .format
            .strip_prefix("PREF_")
            .unwrap_or(opcode.format)
            .split('_')
        {
            if part == "NONE" {
                continue;
            }
            let (kind, width) = if let Some(width) = part.strip_prefix("IMM") {
                ("imm", width)
            } else if let Some(width) = part.strip_prefix("ID") {
                ("id", width)
            } else if let Some(width) = part.strip_prefix('V') {
                ("reg", width)
            } else {
                return Err(Error::invalid(format!("unknown operand format {part}")));
            };
            let width: usize = width
                .parse()
                .map_err(|_| Error::invalid("invalid operand width"))?;
            let raw = if width == 4 {
                let byte = *bytes
                    .get(pos)
                    .ok_or_else(|| Error::invalid(format!("truncated operands at {pc:#x}")))?;
                let value = u64::from((byte >> nibble) & 15);
                nibble += 4;
                if nibble == 8 {
                    nibble = 0;
                    pos += 1;
                }
                value
            } else {
                if nibble != 0 {
                    return Err(Error::invalid("unaligned packed operand"));
                }
                let size = width / 8;
                let end = pos
                    .checked_add(size)
                    .ok_or_else(|| Error::invalid("operand overflow"))?;
                let bytes = bytes
                    .get(pos..end)
                    .ok_or_else(|| Error::invalid(format!("truncated operands at {pc:#x}")))?;
                let mut value = [0; 8];
                value[..size].copy_from_slice(bytes);
                pos = end;
                u64::from_le_bytes(value)
            };
            let operand = match kind {
                "reg" => Operand::Register(
                    u32::try_from(raw).map_err(|_| Error::invalid("register exceeds u32"))?,
                ),
                "id" => {
                    Operand::Id(u32::try_from(raw).map_err(|_| Error::invalid("id exceeds u32"))?)
                }
                "imm" if width == 64 => Operand::Float(f64::from_bits(raw)),
                "imm" => {
                    let value = if width != 4 && (opcode.flags & JUMP != 0 || opcode.name == "ldai")
                    {
                        let shift = 64 - width;
                        i64::from_le_bytes((raw << shift).to_le_bytes()) >> shift
                    } else {
                        i64::try_from(raw).map_err(|_| Error::invalid("immediate exceeds i64"))?
                    };
                    Operand::Immediate(value)
                }
                _ => return Err(Error::invalid("invalid operand kind")),
            };
            operands.push(operand);
        }
        if nibble != 0 {
            return Err(Error::invalid("incomplete packed operand"));
        }
        instructions.push(Instruction {
            pc,
            next_pc: u32::try_from(pos).map_err(|_| Error::invalid("method exceeds u32"))?,
            opcode,
            operands,
        });
    }
    Ok(instructions)
}
