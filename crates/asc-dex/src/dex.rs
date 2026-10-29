//! On-demand DEX reader. Section bytes stay in the original buffer; ids are
//! decoded only when a query needs them.

use crate::bytes::{decode_mutf8, read_uleb, read_until_nul, u16_at, u32_at, uleb_len};
use crate::Result;

/// Bounds `encoded_value` recursion. Real annotations and static values nest a
/// handful of levels; anything deeper is crafted and would overflow the stack.
const MAX_ENCODED_DEPTH: usize = 64;

#[derive(Clone, Debug)]
pub struct Header {
    pub string_ids_off: u32,
    pub string_ids_size: u32,
    pub type_ids_off: u32,
    pub type_ids_size: u32,
    pub proto_ids_off: u32,
    pub proto_ids_size: u32,
    pub field_ids_off: u32,
    pub field_ids_size: u32,
    pub method_ids_off: u32,
    pub method_ids_size: u32,
    pub class_defs_off: u32,
    pub class_defs_size: u32,
    pub map_off: u32,
}

pub struct Dex<'a> {
    pub data: &'a [u8],
    pub header: Header,
}

#[derive(Clone, Debug)]
pub struct ClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

#[derive(Clone, Debug)]
pub struct EncodedField {
    pub field_idx: u32,
    pub access_flags: u32,
    pub is_static: bool,
}

#[derive(Clone, Debug)]
pub struct EncodedMethod {
    pub method_idx: u32,
    pub access_flags: u32,
    pub code_off: u32,
    pub is_direct: bool,
}

#[derive(Clone, Debug)]
pub struct ClassData {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

impl ClassData {
    pub fn fields(&self) -> impl Iterator<Item = &EncodedField> {
        self.static_fields.iter().chain(self.instance_fields.iter())
    }

    pub fn methods(&self) -> impl Iterator<Item = &EncodedMethod> {
        self.direct_methods
            .iter()
            .chain(self.virtual_methods.iter())
    }
}

#[derive(Clone, Debug)]
pub struct MethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

#[derive(Clone, Debug)]
pub struct FieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

#[derive(Clone, Debug)]
pub struct Proto {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub params: Vec<u32>,
}

pub struct CodeItem<'a> {
    pub registers_size: u16,
    pub ins_size: u16,
    pub insns: &'a [u8],
}

#[derive(Clone, Debug)]
pub struct MapItem {
    pub type_: u16,
    pub size: u32,
    pub offset: u32,
}

impl<'a> Dex<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if data.len() < 0x70 || &data[..3] != b"dex" {
            bail!("invalid DEX header");
        }
        let header = Header {
            string_ids_size: u32_at(data, 0x38)?,
            string_ids_off: u32_at(data, 0x3c)?,
            type_ids_size: u32_at(data, 0x40)?,
            type_ids_off: u32_at(data, 0x44)?,
            proto_ids_size: u32_at(data, 0x48)?,
            proto_ids_off: u32_at(data, 0x4c)?,
            field_ids_size: u32_at(data, 0x50)?,
            field_ids_off: u32_at(data, 0x54)?,
            method_ids_size: u32_at(data, 0x58)?,
            method_ids_off: u32_at(data, 0x5c)?,
            class_defs_size: u32_at(data, 0x60)?,
            class_defs_off: u32_at(data, 0x64)?,
            map_off: u32_at(data, 0x34)?,
        };
        Ok(Self { data, header })
    }

    pub fn string_bytes(&self, idx: u32) -> Result<&'a [u8]> {
        if idx >= self.header.string_ids_size {
            bail!("bad string idx {idx}");
        }
        let off = u32_at(
            self.data,
            self.header.string_ids_off as usize + idx as usize * 4,
        )? as usize;
        if off >= self.data.len() {
            bail!("bad string_data_off");
        }
        let len = uleb_len(self.data, off)?;
        read_until_nul(self.data, off + len)
    }

    pub fn string(&self, idx: u32) -> Result<String> {
        Ok(decode_mutf8(self.string_bytes(idx)?))
    }

    pub fn type_string_idx(&self, type_idx: u32) -> Result<u32> {
        if type_idx >= self.header.type_ids_size {
            bail!("bad type idx {type_idx}");
        }
        u32_at(
            self.data,
            self.header.type_ids_off as usize + type_idx as usize * 4,
        )
    }

    pub fn type_desc(&self, type_idx: u32) -> Result<String> {
        self.string(self.type_string_idx(type_idx)?)
    }

    pub fn find_type_idx(&self, desc: &[u8]) -> Result<Option<u32>> {
        if self.header.type_ids_size == 0 || self.header.string_ids_size == 0 {
            return Ok(None);
        }
        let mut left: i64 = 0;
        let mut right: i64 = self.header.type_ids_size as i64 - 1;
        while left <= right {
            let mid = ((left + right) >> 1) as u32;
            let bytes = self.string_bytes(self.type_string_idx(mid)?)?;
            match bytes.cmp(desc) {
                std::cmp::Ordering::Equal => return Ok(Some(mid)),
                std::cmp::Ordering::Less => left = mid as i64 + 1,
                std::cmp::Ordering::Greater => right = mid as i64 - 1,
            }
        }
        Ok(None)
    }

    pub fn defines_class(&self, desc: &[u8]) -> Result<bool> {
        let Some(type_idx) = self.find_type_idx(desc)? else {
            return Ok(false);
        };
        let needle = type_idx.to_le_bytes();
        let start = self.header.class_defs_off as usize;
        let count = self.header.class_defs_size as usize;
        let end = start + count * 32;
        if end > self.data.len() {
            bail!("bad class_defs range");
        }
        for off in (start..end).step_by(32) {
            if self.data[off..off + 4] == needle {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn class_def(&self, index: u32) -> Result<ClassDef> {
        if index >= self.header.class_defs_size {
            bail!("bad class def index");
        }
        let off = self.header.class_defs_off as usize + index as usize * 32;
        if off + 32 > self.data.len() {
            bail!("bad class_defs range");
        }
        Ok(ClassDef {
            class_idx: u32_at(self.data, off)?,
            access_flags: u32_at(self.data, off + 4)?,
            superclass_idx: u32_at(self.data, off + 8)?,
            interfaces_off: u32_at(self.data, off + 12)?,
            source_file_idx: u32_at(self.data, off + 16)?,
            class_data_off: u32_at(self.data, off + 24)?,
            static_values_off: u32_at(self.data, off + 28)?,
        })
    }

    pub fn class_descriptors(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let prefix_bytes = prefix.filter(|value| value.is_ascii()).map(str::as_bytes);
        let mut names = Vec::new();
        for index in 0..self.header.class_defs_size {
            let def = self.class_def(index)?;
            if def.class_idx >= self.header.type_ids_size {
                bail!("bad class_def->type_idx");
            }
            let raw = self.string_bytes(self.type_string_idx(def.class_idx)?)?;
            if let Some(bytes) = prefix_bytes {
                if raw.starts_with(bytes) {
                    names.push(decode_mutf8(raw));
                }
            } else if let Some(text) = prefix {
                let name = decode_mutf8(raw);
                if name.starts_with(text) {
                    names.push(name);
                }
            } else {
                names.push(decode_mutf8(raw));
            }
        }
        Ok(names)
    }

    pub fn find_class_def(&self, desc: &str) -> Result<Option<ClassDef>> {
        let Some(type_idx) = self.find_type_idx(desc.as_bytes())? else {
            return Ok(None);
        };
        for index in 0..self.header.class_defs_size {
            let def = self.class_def(index)?;
            if def.class_idx == type_idx {
                return Ok(Some(def));
            }
        }
        Ok(None)
    }

    pub fn class_data_at(&self, off: u32) -> Result<(ClassData, usize)> {
        parse_class_data(self.data, off as usize)
    }

    pub fn method_id(&self, idx: u32) -> Result<MethodId> {
        if idx >= self.header.method_ids_size {
            bail!("bad method idx {idx}");
        }
        let off = self.header.method_ids_off as usize + idx as usize * 8;
        Ok(MethodId {
            class_idx: u16_at(self.data, off)?,
            proto_idx: u16_at(self.data, off + 2)?,
            name_idx: u32_at(self.data, off + 4)?,
        })
    }

    pub fn field_id(&self, idx: u32) -> Result<FieldId> {
        if idx >= self.header.field_ids_size {
            bail!("bad field idx {idx}");
        }
        let off = self.header.field_ids_off as usize + idx as usize * 8;
        Ok(FieldId {
            class_idx: u16_at(self.data, off)?,
            type_idx: u16_at(self.data, off + 2)?,
            name_idx: u32_at(self.data, off + 4)?,
        })
    }

    pub fn proto(&self, idx: u32) -> Result<Proto> {
        if idx >= self.header.proto_ids_size {
            bail!("bad proto idx {idx}");
        }
        let off = self.header.proto_ids_off as usize + idx as usize * 12;
        let shorty_idx = u32_at(self.data, off)?;
        let return_type_idx = u32_at(self.data, off + 4)?;
        let parameters_off = u32_at(self.data, off + 8)?;
        let params = if parameters_off == 0 {
            Vec::new()
        } else {
            read_type_list(self.data, parameters_off as usize)?
        };
        Ok(Proto {
            shorty_idx,
            return_type_idx,
            params,
        })
    }

    pub fn interfaces(&self, off: u32) -> Result<Vec<String>> {
        if off == 0 {
            return Ok(Vec::new());
        }
        let idxs = read_type_list(self.data, off as usize)?;
        idxs.into_iter().map(|idx| self.type_desc(idx)).collect()
    }

    pub fn code(&self, off: u32) -> Result<CodeItem<'a>> {
        if off == 0 {
            bail!("method has no code");
        }
        let at = off as usize;
        let registers_size = u16_at(self.data, at)?;
        let ins_size = u16_at(self.data, at + 2)?;
        let insns_size = u32_at(self.data, at + 12)? as usize;
        let start = at + 16;
        let end = start + insns_size * 2;
        let insns = self
            .data
            .get(start..end)
            .ok_or_else(|| crate::Error::new(format!("code item out of range at {off:#x}")))?;
        Ok(CodeItem {
            registers_size,
            ins_size,
            insns,
        })
    }

    pub fn format_method(&self, idx: u32) -> Result<String> {
        let method = self.method_id(idx)?;
        let class_name = self.type_desc(u32::from(method.class_idx))?;
        let name = self.string(method.name_idx)?;
        Ok(format!("{class_name}->{name}"))
    }

    pub fn format_field(&self, idx: u32) -> Result<String> {
        let field = self.field_id(idx)?;
        let class_name = self.type_desc(u32::from(field.class_idx))?;
        let name = self.string(field.name_idx)?;
        Ok(format!("{class_name}->{name}"))
    }

    pub fn static_literals(&self, off: u32) -> Result<Vec<String>> {
        if off == 0 {
            return Ok(Vec::new());
        }
        let (values, _) = self.encoded_array(off as usize, 0)?;
        Ok(values)
    }

    fn encoded_array(&self, mut pos: usize, depth: usize) -> Result<(Vec<String>, usize)> {
        if depth > MAX_ENCODED_DEPTH {
            bail!("encoded value nesting is too deep");
        }
        let start = pos;
        let (size, n) = read_uleb(self.data, pos)?;
        pos += n;
        let count = bounded_count(size, self.data.len().saturating_sub(pos), 1)?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..size {
            let (value, n) = self.encoded_value(pos, depth)?;
            pos += n;
            values.push(value);
        }
        Ok((values, pos - start))
    }

    fn encoded_value(&self, pos: usize, depth: usize) -> Result<(String, usize)> {
        let header = *self
            .data
            .get(pos)
            .ok_or_else(|| crate::Error::new("truncated encoded value"))?;
        let value_type = header & 0x1f;
        let value_arg = usize::from(header >> 5);
        let max_arg = match value_type {
            0x00 | 0x1c | 0x1d | 0x1e => 0,
            0x02 | 0x03 | 0x1f => 1,
            0x04 | 0x10 | 0x15..=0x1b => 3,
            0x06 | 0x11 => 7,
            _ => bail!("invalid encoded value type {value_type:#x}"),
        };
        if value_arg > max_arg {
            bail!("invalid value_arg {value_arg} for encoded value type {value_type:#x}");
        }
        let body = pos + 1;
        let unsigned = |nbytes: usize| -> Result<u64> {
            let raw = self
                .data
                .get(body..body + nbytes)
                .ok_or_else(|| crate::Error::new("truncated encoded value"))?;
            let mut buf = [0u8; 8];
            buf[..nbytes].copy_from_slice(raw);
            Ok(u64::from_le_bytes(buf))
        };
        let unsigned32 = |nbytes: usize| -> Result<u32> {
            u32::try_from(unsigned(nbytes)?)
                .map_err(|_| crate::Error::new("encoded value exceeds u32"))
        };
        let signed = |nbytes: usize| -> Result<i64> {
            let raw = self
                .data
                .get(body..body + nbytes)
                .ok_or_else(|| crate::Error::new("truncated encoded value"))?;
            let mut buf = [0u8; 8];
            buf[..nbytes].copy_from_slice(raw);
            if nbytes < 8 && raw[nbytes - 1] & 0x80 != 0 {
                for byte in &mut buf[nbytes..] {
                    *byte = 0xff;
                }
            }
            Ok(i64::from_le_bytes(buf))
        };
        match value_type {
            0x00 => Ok((format!("{}", signed(1)?), 2)),
            0x02 | 0x04 | 0x06 => {
                let nbytes = value_arg + 1;
                Ok((format!("{}", signed(nbytes)?), 1 + nbytes))
            }
            0x03 => {
                let nbytes = value_arg + 1;
                Ok((format!("{}", unsigned(nbytes)?), 1 + nbytes))
            }
            0x10 => {
                let nbytes = value_arg + 1;
                let bits = unsigned32(nbytes)? << (8 * (4 - nbytes));
                Ok((format!("{}", f32::from_bits(bits)), 1 + nbytes))
            }
            0x11 => {
                let nbytes = value_arg + 1;
                let bits = unsigned(nbytes)? << (8 * (8 - nbytes));
                Ok((format!("{}", f64::from_bits(bits)), 1 + nbytes))
            }
            0x17 => {
                let nbytes = value_arg + 1;
                let idx = unsigned32(nbytes)?;
                Ok((java_quote(&self.string(idx)?), 1 + nbytes))
            }
            0x15 => {
                let nbytes = value_arg + 1;
                let idx = unsigned32(nbytes)?;
                let proto = self.proto(idx)?;
                Ok((self.string(proto.shorty_idx)?, 1 + nbytes))
            }
            0x18 => {
                let nbytes = value_arg + 1;
                let idx = unsigned32(nbytes)?;
                Ok((
                    format!("{}.class", java_type(&self.type_desc(idx)?)),
                    1 + nbytes,
                ))
            }
            0x1e => Ok(("null".to_string(), 1)),
            0x1f => Ok((
                if value_arg == 0 {
                    "false".to_string()
                } else {
                    "true".to_string()
                },
                1,
            )),
            0x1c => {
                let (values, n) = self.encoded_array(body, depth + 1)?;
                Ok((format!("{{{}}}", values.join(", ")), 1 + n))
            }
            0x1d => {
                let (text, n) = self.encoded_annotation(body, depth + 1)?;
                Ok((text, 1 + n))
            }
            _ => {
                let nbytes = value_arg + 1;
                Ok((format!("#{}", unsigned(nbytes)?), 1 + nbytes))
            }
        }
    }

    fn encoded_annotation(&self, mut pos: usize, depth: usize) -> Result<(String, usize)> {
        if depth > MAX_ENCODED_DEPTH {
            bail!("encoded value nesting is too deep");
        }
        let start = pos;
        let (type_idx, n) = read_uleb(self.data, pos)?;
        pos += n;
        let (size, n) = read_uleb(self.data, pos)?;
        pos += n;
        let mut parts = Vec::new();
        for _ in 0..size {
            let (name_idx, n) = read_uleb(self.data, pos)?;
            pos += n;
            let (value, n) = self.encoded_value(pos, depth)?;
            pos += n;
            parts.push(format!("{}={value}", self.string(name_idx)?));
        }
        let name = java_type(&self.type_desc(type_idx)?);
        let simple = name.rsplit('.').next().unwrap_or(&name);
        let text = if parts.is_empty() {
            format!("@{simple}")
        } else {
            format!("@{simple}({})", parts.join(", "))
        };
        Ok((text, pos - start))
    }

    pub fn map_items(&self) -> Result<Vec<MapItem>> {
        if self.header.map_off == 0 {
            return Ok(Vec::new());
        }
        let map_off = self.header.map_off as usize;
        let count = u32_at(self.data, map_off)?;
        let mut pos = map_off + 4;
        let count = bounded_count(count, self.data.len().saturating_sub(pos), 12)?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            if pos + 12 > self.data.len() {
                bail!("truncated map list");
            }
            items.push(MapItem {
                type_: u16_at(self.data, pos)?,
                size: u32_at(self.data, pos + 4)?,
                offset: u32_at(self.data, pos + 8)?,
            });
            pos += 12;
        }
        Ok(items)
    }
}

pub fn parse_class_data(data: &[u8], mut pos: usize) -> Result<(ClassData, usize)> {
    let (static_fields_size, n) = read_uleb(data, pos)?;
    pos += n;
    let (instance_fields_size, n) = read_uleb(data, pos)?;
    pos += n;
    let (direct_methods_size, n) = read_uleb(data, pos)?;
    pos += n;
    let (virtual_methods_size, n) = read_uleb(data, pos)?;
    pos += n;
    let remaining = data.len().saturating_sub(pos);
    let min_bytes = checked_span(&[
        (static_fields_size, 2),
        (instance_fields_size, 2),
        (direct_methods_size, 3),
        (virtual_methods_size, 3),
    ])?;
    if min_bytes > remaining {
        bail!("class data exceeds the buffer");
    }

    let mut static_fields = Vec::with_capacity(static_fields_size as usize);
    let mut field_idx = 0u32;
    for _ in 0..static_fields_size {
        let (diff, n) = read_uleb(data, pos)?;
        pos += n;
        field_idx += diff;
        let (access_flags, n) = read_uleb(data, pos)?;
        pos += n;
        static_fields.push(EncodedField {
            field_idx,
            access_flags,
            is_static: true,
        });
    }
    let mut instance_fields = Vec::with_capacity(instance_fields_size as usize);
    field_idx = 0;
    for _ in 0..instance_fields_size {
        let (diff, n) = read_uleb(data, pos)?;
        pos += n;
        field_idx += diff;
        let (access_flags, n) = read_uleb(data, pos)?;
        pos += n;
        instance_fields.push(EncodedField {
            field_idx,
            access_flags,
            is_static: false,
        });
    }

    let read_methods = |count: u32, direct: bool, pos: &mut usize| -> Result<Vec<EncodedMethod>> {
        let mut methods = Vec::with_capacity(count as usize);
        let mut method_idx = 0u32;
        for _ in 0..count {
            let (diff, n) = read_uleb(data, *pos)?;
            *pos += n;
            method_idx += diff;
            let (access_flags, n) = read_uleb(data, *pos)?;
            *pos += n;
            let (code_off, n) = read_uleb(data, *pos)?;
            *pos += n;
            methods.push(EncodedMethod {
                method_idx,
                access_flags,
                code_off,
                is_direct: direct,
            });
        }
        Ok(methods)
    };
    let direct_methods = read_methods(direct_methods_size, true, &mut pos)?;
    let virtual_methods = read_methods(virtual_methods_size, false, &mut pos)?;
    Ok((
        ClassData {
            static_fields,
            instance_fields,
            direct_methods,
            virtual_methods,
        },
        pos,
    ))
}

fn read_type_list(data: &[u8], off: usize) -> Result<Vec<u32>> {
    let size = u32_at(data, off)?;
    let count = bounded_count(size, data.len().saturating_sub(off.saturating_add(4)), 2)?;
    let mut params = Vec::with_capacity(count);
    for index in 0..count {
        params.push(u32::from(u16_at(data, off + 4 + index * 2)?));
    }
    Ok(params)
}

fn bounded_count(count: u32, remaining: usize, stride: usize) -> Result<usize> {
    let count = count as usize;
    if stride == 0 || remaining / stride < count {
        bail!("count {count} exceeds the remaining {remaining} bytes");
    }
    Ok(count)
}

fn checked_span(parts: &[(u32, usize)]) -> Result<usize> {
    let mut total = 0usize;
    for (count, stride) in parts {
        let part = (*count as usize)
            .checked_mul(*stride)
            .ok_or_else(|| crate::Error::new("class data is too large"))?;
        total = total
            .checked_add(part)
            .ok_or_else(|| crate::Error::new("class data is too large"))?;
    }
    Ok(total)
}

pub fn java_type(desc: &str) -> String {
    let mut dims = 0usize;
    let mut rest = desc;
    while let Some(next) = rest.strip_prefix('[') {
        dims += 1;
        rest = next;
    }
    let base = match rest {
        "V" => "void".to_string(),
        "Z" => "boolean".to_string(),
        "B" => "byte".to_string(),
        "S" => "short".to_string(),
        "C" => "char".to_string(),
        "I" => "int".to_string(),
        "J" => "long".to_string(),
        "F" => "float".to_string(),
        "D" => "double".to_string(),
        other if other.starts_with('L') && other.ends_with(';') => {
            other[1..other.len() - 1].replace(['/', '$'], ".")
        }
        other => other.to_string(),
    };
    format!("{base}{}", "[]".repeat(dims))
}

pub fn java_quote(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub fn normalize_prefix(prefix: &str) -> Result<String> {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        bail!("Class prefix cannot be empty");
    }
    if prefix.starts_with('L') {
        Ok(prefix.to_string())
    } else {
        Ok(format!("L{}", prefix.replace('.', "/")))
    }
}

pub fn normalize_dalvik_class(name: &str) -> Result<String> {
    if name.is_empty() {
        bail!("Class name cannot be empty");
    }
    if name.starts_with('L') && name.ends_with(';') && name.contains('/') {
        return Ok(name.to_string());
    }
    let mut name = name.replace('.', "/");
    if !name.starts_with('L') {
        name.insert(0, 'L');
    }
    if !name.ends_with(';') {
        name.push(';');
    }
    Ok(name)
}
