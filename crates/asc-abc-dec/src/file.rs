use crate::{Error, Result, SizeBudget};

pub(crate) struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], offset: u32) -> Result<Self> {
        let pos = usize::try_from(offset).map_err(|_| Error::invalid("offset exceeds usize"))?;
        if pos > data.len() {
            return Err(Error::invalid("offset exceeds file"));
        }
        Ok(Self { data, pos })
    }
    pub fn bytes(&mut self, size: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(size)
            .ok_or_else(|| Error::invalid("offset overflow"))?;
        let bytes = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| Error::invalid(format!("truncated read at {:#x}", self.pos)))?;
        self.pos = end;
        Ok(bytes)
    }
    pub fn byte(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        let bytes = self.bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
    pub fn u32(&mut self) -> Result<u32> {
        let bytes = self.bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    pub fn u64(&mut self) -> Result<u64> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(self.bytes(8)?);
        Ok(u64::from_le_bytes(bytes))
    }
    pub fn uleb(&mut self) -> Result<u32> {
        let mut value = 0;
        for shift in (0..35).step_by(7) {
            let byte = self.byte()?;
            let part = u32::from(byte & 127);
            if part > u32::MAX >> shift {
                return Err(Error::invalid("ULEB128 overflow"));
            }
            value |= part << shift;
            if byte & 128 == 0 {
                return Ok(value);
            }
        }
        Err(Error::invalid("ULEB128 too long"))
    }
    fn sleb(&mut self) -> Result<i64> {
        let mut value = 0i64;
        for shift in (0..35).step_by(7) {
            let byte = self.byte()?;
            value |= i64::from(byte & 127) << shift;
            if byte & 128 == 0 {
                if byte & 64 != 0 {
                    value |= !0 << (shift + 7);
                }
                return Ok(value);
            }
        }
        Err(Error::invalid("SLEB128 too long"))
    }
    pub fn string(&mut self) -> Result<String> {
        self.uleb()?;
        let tail = &self.data[self.pos..];
        let len = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| Error::invalid("unterminated MUTF-8 string"))?;
        if len > 4 * 1024 * 1024 {
            return Err(Error::invalid("MUTF-8 string exceeds 4 MiB"));
        }
        let raw = self.bytes(len + 1)?;
        let mut units = Vec::new();
        let mut pos = 0;
        while pos < len {
            let first = raw[pos];
            let (count, mut unit) = if first < 128 {
                (1, u16::from(first))
            } else if first & 224 == 192 {
                (2, u16::from(first & 31))
            } else if first & 240 == 224 {
                (3, u16::from(first & 15))
            } else {
                return Err(Error::invalid("invalid MUTF-8 lead byte"));
            };
            for step in 1..count {
                let byte = *raw
                    .get(pos + step)
                    .filter(|_| pos + step < len)
                    .ok_or_else(|| Error::invalid("truncated MUTF-8"))?;
                if byte & 192 != 128 {
                    return Err(Error::invalid("invalid MUTF-8 continuation"));
                }
                unit = unit << 6 | u16::from(byte & 63);
            }
            units.push(unit);
            pos += count;
        }
        Ok(String::from_utf16_lossy(&units))
    }
    pub fn count(&mut self, stride: usize) -> Result<usize> {
        let count =
            usize::try_from(self.u32()?).map_err(|_| Error::invalid("count exceeds usize"))?;
        if count > (self.data.len() - self.pos) / stride {
            return Err(Error::invalid("count exceeds buffer"));
        }
        Ok(count)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Method<'a> {
    pub offset: u32,
    pub name: String,
    pub code: Option<Code<'a>>,
}

impl Method<'_> {
    fn charge(&self, budget: &mut SizeBudget) -> Result<()> {
        budget.charge(std::mem::size_of::<Self>())?;
        budget.charge(self.name.len())?;
        if let Some(code) = &self.code {
            for block in &code.tries {
                budget.charge(std::mem::size_of::<TryBlock>())?;
                budget.charge(block.handlers.len() * std::mem::size_of::<Handler>())?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Code<'a> {
    pub registers: u32,
    pub arguments: u32,
    pub bytes: &'a [u8],
    pub tries: Vec<TryBlock>,
}

#[derive(Clone, Debug)]
pub(crate) struct TryBlock {
    pub start: u32,
    pub end: u32,
    pub handlers: Vec<Handler>,
}

#[derive(Clone, Debug)]
pub(crate) struct Handler {
    pub type_index: u32,
    pub pc: u32,
    pub end: u32,
}

#[derive(Default)]
pub(crate) struct Module {
    pub requests: Vec<String>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
}

pub(crate) struct Import {
    pub path: String,
    pub local: String,
    pub imported: Option<String>,
}

pub(crate) struct Export {
    pub path: Option<String>,
    pub local: Option<String>,
    pub exported: Option<String>,
}

pub(crate) struct Class<'a> {
    pub name: String,
    pub methods: Vec<Method<'a>>,
    pub module: Module,
}

#[derive(Clone, Debug)]
pub(crate) enum Literal {
    Value(String),
    String(String),
    Method { offset: u32, tag: u8 },
    Affiliate(u16),
    Array(u32),
}

impl Literal {
    fn charge(&self, budget: &mut SizeBudget) -> Result<()> {
        budget.charge(std::mem::size_of::<Self>())?;
        match self {
            Self::Value(text) | Self::String(text) => budget.charge(text.len()),
            Self::Method { .. } | Self::Affiliate(_) | Self::Array(_) => Ok(()),
        }
    }
}

pub(crate) struct File<'a> {
    abc: asc_abc::Abc<'a>,
}

impl<'a> File<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        Ok(Self {
            abc: asc_abc::Abc::parse(data)?,
        })
    }
    pub fn data(&self) -> &'a [u8] {
        self.abc.data()
    }
    pub fn string(&self, offset: u32) -> Result<String> {
        Reader::new(self.data(), offset)?.string()
    }
    pub fn reference(&self, method: u32, index: u32, flags: u32) -> Result<u32> {
        let mut header = Reader::new(self.data(), 52)?;
        let count = header.u32()?;
        let offset = header.u32()?;
        let mut regions = Reader::new(self.data(), offset)?;
        for _ in 0..count {
            let start = regions.u32()?;
            let end = regions.u32()?;
            let tables = [
                regions.u32()?,
                regions.u32()?,
                regions.u32()?,
                regions.u32()?,
                regions.u32()?,
                regions.u32()?,
                regions.u32()?,
                regions.u32()?,
            ];
            if method < start || method >= end {
                continue;
            }
            let pair = if flags & crate::decode::TYPE_ID != 0 {
                0
            } else if flags & crate::decode::FIELD_ID != 0 && tables[5] != u32::MAX {
                4
            } else {
                2
            };
            let size = tables[pair];
            let off = tables[pair + 1];
            if index >= size || off == u32::MAX {
                return Err(Error::invalid("reference index exceeds table"));
            }
            let at = index
                .checked_mul(4)
                .and_then(|index| off.checked_add(index))
                .ok_or_else(|| Error::invalid("reference offset overflow"))?;
            return Reader::new(self.data(), at)?.u32();
        }
        Err(Error::invalid(format!(
            "no index region covers method {method:#x}"
        )))
    }
    pub fn method(&self, offset: u32) -> Result<Method<'a>> {
        let mut reader = Reader::new(self.data(), offset)?;
        reader.bytes(4)?;
        let name = self.string(reader.u32()?)?;
        reader.uleb()?;
        let mut code = None;
        loop {
            match reader.byte()? {
                0 => break,
                1 => code = Some(self.code(reader.u32()?)?),
                2 => {
                    reader.byte()?;
                }
                3..=9 => {
                    reader.u32()?;
                }
                tag => return Err(Error::invalid(format!("unknown method tag {tag:#x}"))),
            }
        }
        Ok(Method { offset, name, code })
    }
    fn code(&self, offset: u32) -> Result<Code<'a>> {
        let mut reader = Reader::new(self.data(), offset)?;
        let registers = reader.uleb()?;
        let arguments = reader.uleb()?;
        if registers
            .checked_add(arguments)
            .is_none_or(|count| count > 65536)
        {
            return Err(Error::invalid("method register count exceeds 65536"));
        }
        let size = reader.uleb()?;
        let count = reader.uleb()?;
        let bytes = reader
            .bytes(usize::try_from(size).map_err(|_| Error::invalid("code size exceeds usize"))?)?;
        let mut tries = Vec::new();
        let mut budget = SizeBudget::new("exception table");
        for _ in 0..count {
            budget.charge(std::mem::size_of::<TryBlock>())?;
            let start = reader.uleb()?;
            let end = start
                .checked_add(reader.uleb()?)
                .filter(|end| *end <= size)
                .ok_or_else(|| Error::invalid("try range exceeds method"))?;
            let count = reader.uleb()?;
            let mut handlers = Vec::new();
            for _ in 0..count {
                budget.charge(std::mem::size_of::<Handler>())?;
                let type_index = reader.uleb()?;
                let pc = reader.uleb()?;
                let end = pc
                    .checked_add(reader.uleb()?)
                    .filter(|end| *end <= size)
                    .ok_or_else(|| Error::invalid("catch range exceeds method"))?;
                handlers.push(Handler {
                    type_index,
                    pc,
                    end,
                });
            }
            tries.push(TryBlock {
                start,
                end,
                handlers,
            });
        }
        Ok(Code {
            registers,
            arguments,
            bytes,
            tries,
        })
    }
    pub fn class(&self, query: &str) -> Result<Option<Class<'a>>> {
        let Some(offset) = self.abc.class_offset(query)? else {
            return Ok(None);
        };
        let mut reader = Reader::new(self.data(), offset)?;
        let name = reader.string()?;
        let foreign_off = Reader::new(self.data(), 20)?.u32()?;
        let foreign_size = Reader::new(self.data(), 24)?.u32()?;
        if offset >= foreign_off && offset < foreign_off.saturating_add(foreign_size) {
            return Ok(Some(Class {
                name,
                methods: Vec::new(),
                module: Module::default(),
            }));
        }
        reader.u32()?;
        reader.uleb()?;
        let fields = reader.uleb()?;
        let methods = reader.uleb()?;
        loop {
            match reader.byte()? {
                0 => break,
                1 => {
                    let count = reader.uleb()?;
                    reader.bytes(
                        usize::try_from(count)
                            .map_err(|_| Error::invalid("interface count exceeds usize"))?
                            * 2,
                    )?;
                }
                2 => {
                    reader.byte()?;
                }
                3..=7 => {
                    reader.u32()?;
                }
                tag => return Err(Error::invalid(format!("unknown class tag {tag:#x}"))),
            }
        }
        let mut module = Module::default();
        for _ in 0..fields {
            reader.bytes(4)?;
            let field_name = self.string(reader.u32()?)?;
            reader.uleb()?;
            loop {
                match reader.byte()? {
                    0 => break,
                    1 => {
                        reader.sleb()?;
                    }
                    2 => {
                        let offset = reader.u32()?;
                        if field_name == "moduleRecordIdx" {
                            module = self.module(offset)?;
                        }
                    }
                    3..=6 => {
                        reader.u32()?;
                    }
                    tag => return Err(Error::invalid(format!("unknown field tag {tag:#x}"))),
                }
            }
        }
        let mut result = Vec::new();
        let mut budget = SizeBudget::new("class method metadata");
        for _ in 0..methods {
            let offset = u32::try_from(reader.pos)
                .map_err(|_| Error::invalid("method offset exceeds u32"))?;
            reader.bytes(8)?;
            reader.uleb()?;
            loop {
                match reader.byte()? {
                    0 => break,
                    2 => {
                        reader.byte()?;
                    }
                    1 | 3..=9 => {
                        reader.u32()?;
                    }
                    tag => return Err(Error::invalid(format!("unknown method tag {tag:#x}"))),
                }
            }
            let method = self.method(offset)?;
            method.charge(&mut budget)?;
            result.push(method);
        }
        Ok(Some(Class {
            name,
            methods: result,
            module,
        }))
    }
    fn module(&self, offset: u32) -> Result<Module> {
        let mut reader = Reader::new(self.data(), offset)?;
        reader.u32()?;
        let mut module = Module::default();
        let mut budget = SizeBudget::new("module metadata");
        for _ in 0..reader.count(4)? {
            let path = self.string(reader.u32()?)?;
            budget.charge(std::mem::size_of::<String>() + path.len())?;
            module.requests.push(path);
        }
        let request = |index: u16| -> Result<String> {
            module
                .requests
                .get(usize::from(index))
                .cloned()
                .ok_or_else(|| Error::invalid("module request out of range"))
        };
        for _ in 0..reader.count(10)? {
            let local = self.string(reader.u32()?)?;
            let imported = Some(self.string(reader.u32()?)?);
            let import = Import {
                path: request(reader.u16()?)?,
                local,
                imported,
            };
            budget.charge(std::mem::size_of::<Import>())?;
            budget.charge(import.path.len() + import.local.len())?;
            budget.charge(import.imported.as_ref().map_or(0, String::len))?;
            module.imports.push(import);
        }
        for _ in 0..reader.count(6)? {
            let local = self.string(reader.u32()?)?;
            let import = Import {
                path: request(reader.u16()?)?,
                local,
                imported: None,
            };
            budget
                .charge(std::mem::size_of::<Import>() + import.path.len() + import.local.len())?;
            module.imports.push(import);
        }
        for _ in 0..reader.count(8)? {
            let local = self.string(reader.u32()?)?;
            let exported = self.string(reader.u32()?)?;
            budget.charge(std::mem::size_of::<Export>() + local.len() + exported.len())?;
            module.exports.push(Export {
                path: None,
                local: Some(local),
                exported: Some(exported),
            });
        }
        for _ in 0..reader.count(10)? {
            let exported = self.string(reader.u32()?)?;
            let local = self.string(reader.u32()?)?;
            let path = request(reader.u16()?)?;
            budget.charge(
                std::mem::size_of::<Export>() + local.len() + exported.len() + path.len(),
            )?;
            module.exports.push(Export {
                path: Some(path),
                local: Some(local),
                exported: Some(exported),
            });
        }
        for _ in 0..reader.count(2)? {
            let path = request(reader.u16()?)?;
            budget.charge(std::mem::size_of::<Export>() + path.len())?;
            module.exports.push(Export {
                path: Some(path),
                local: None,
                exported: None,
            });
        }
        Ok(module)
    }
    pub fn literals(&self, offset: u32) -> Result<Vec<Literal>> {
        let mut reader = Reader::new(self.data(), offset)?;
        let entries = reader.u32()?;
        if entries % 2 != 0 {
            return Err(Error::invalid("literal array has an odd element count"));
        }
        let count = entries / 2;
        let mut values = Vec::new();
        let mut budget = SizeBudget::new("literal buffer");
        for _ in 0..count {
            let tag = reader.byte()?;
            let value = match tag {
                0x00 => Literal::Value(reader.byte()?.to_string()),
                0x08 | 0x19 => {
                    reader.byte()?;
                    Literal::Value("undefined".into())
                }
                0x01 => Literal::Value((reader.byte()? != 0).to_string()),
                0x02 => Literal::Value(i32::from_le_bytes(reader.u32()?.to_le_bytes()).to_string()),
                0x03 => Literal::Value(number(f64::from(f32::from_bits(reader.u32()?)))),
                0x04 => Literal::Value(number(f64::from_bits(reader.u64()?))),
                0x05 => Literal::String(self.string(reader.u32()?)?),
                0x06 | 0x07 | 0x16 | 0x1a | 0x1b => Literal::Method {
                    offset: reader.u32()?,
                    tag,
                },
                0x09 => Literal::Affiliate(reader.u16()?),
                0x18 => Literal::Array(reader.u32()?),
                0x17 => Literal::Value(reader.u32()?.to_string()),
                0xff => {
                    reader.byte()?;
                    Literal::Value("null".into())
                }
                0x0a..=0x15 => {
                    let pointer = reader.u32()?;
                    values.extend(self.typed_array(pointer, tag, &mut budget)?);
                    break;
                }
                _ => return Err(Error::invalid(format!("unknown literal tag {tag:#x}"))),
            };
            value.charge(&mut budget)?;
            values.push(value);
        }
        Ok(values)
    }
    fn typed_array(&self, offset: u32, tag: u8, budget: &mut SizeBudget) -> Result<Vec<Literal>> {
        let mut reader = Reader::new(self.data(), offset)?;
        let stride = match tag {
            0x0a..=0x0c => 1,
            0x0d..=0x0e => 2,
            0x0f..=0x10 | 0x13 | 0x15 => 4,
            _ => 8,
        };
        let count = reader.count(stride)?;
        let mut values = Vec::new();
        for _ in 0..count {
            let value = match tag {
                0x0a => (reader.byte()? != 0).to_string(),
                0x0b => reader.byte()?.to_string(),
                0x0c => i8::from_le_bytes([reader.byte()?]).to_string(),
                0x0d => reader.u16()?.to_string(),
                0x0e => i16::from_le_bytes(reader.u16()?.to_le_bytes()).to_string(),
                0x0f => reader.u32()?.to_string(),
                0x10 => i32::from_le_bytes(reader.u32()?.to_le_bytes()).to_string(),
                0x11 => reader.u64()?.to_string(),
                0x12 => i64::from_le_bytes(reader.u64()?.to_le_bytes()).to_string(),
                0x13 => number(f64::from(f32::from_bits(reader.u32()?))),
                0x14 => number(f64::from_bits(reader.u64()?)),
                0x15 => {
                    let value = Literal::String(self.string(reader.u32()?)?);
                    value.charge(budget)?;
                    values.push(value);
                    continue;
                }
                _ => return Err(Error::invalid("invalid typed array tag")),
            };
            let value = Literal::Value(value);
            value.charge(budget)?;
            values.push(value);
        }
        Ok(values)
    }
}

pub(crate) fn number(value: f64) -> String {
    if value.is_nan() {
        "NaN".into()
    } else if value == f64::INFINITY {
        "Infinity".into()
    } else if value == f64::NEG_INFINITY {
        "-Infinity".into()
    } else {
        value.to_string()
    }
}
