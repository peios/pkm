// Minimal msgpack parser and encoder. Just enough for KMES payloads (which
// the kernel validator requires to be valid msgpack) and for the validation
// tools' expanded display.
//
// Coverage: nil, bool, positive/negative fixint, int8/16/32/64, uint8/16/32/64,
// float32/64, fixstr/str8/16/32, bin8/16/32, fixarray/array16/32,
// fixmap/map16/32, fixext1/2/4/8/16 and ext8/16/32.

use crate::parse::ParseError;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;

/// A decoded msgpack value tree.
#[derive(Debug)]
pub enum Value {
    Nil,
    Bool(bool),
    UInt(u64),
    Int(i64),
    F32(f32),
    F64(f64),
    Str(String),
    Bin(Vec<u8>),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Ext { ty: i8, data: Vec<u8> },
}

impl Value {
    /// True for values that render on a single line (no children).
    pub fn is_primitive(&self) -> bool {
        !matches!(self, Value::Array(_) | Value::Map(_))
    }

    /// Render this value (only valid for primitives) as a compact single-line
    /// string. For containers, returns a short `array(N)` / `map(N)` summary.
    pub fn one_line(&self) -> String {
        match self {
            Value::Nil => String::from("nil"),
            Value::Bool(v) => format!("{v}"),
            Value::UInt(v) => format!("uint({v})"),
            Value::Int(v) => format!("int({v})"),
            Value::F32(v) => format!("float32({v})"),
            Value::F64(v) => format!("float64({v})"),
            Value::Str(s) => format!("str({:?})", s),
            Value::Bin(b) => {
                let cap = b.len().min(24);
                let mut h = String::from("0x");
                for byte in &b[..cap] {
                    h.push_str(&format!("{byte:02x}"));
                }
                if b.len() > cap {
                    h.push_str("..");
                }
                format!("bin({} bytes, {h})", b.len())
            }
            Value::Ext { ty, data } => format!("ext({ty}, {} bytes)", data.len()),
            Value::Array(items) => format!("array({})", items.len()),
            Value::Map(items) => format!("map({})", items.len()),
        }
    }

    /// Pretty-print this value to stdout at the given column indent. Arrays
    /// and maps expand recursively. Caller is responsible for printing any
    /// "payload:" label first. Available only with the `std` feature since
    /// it uses `println!`.
    #[cfg(feature = "std")]
    pub fn render(&self, indent: usize) {
        let pre = " ".repeat(indent);
        match self {
            Value::Array(items) => {
                std::println!("{pre}array({}):", items.len());
                for (i, v) in items.iter().enumerate() {
                    let line_pre = format!("{}[{}]", " ".repeat(indent + 2), i);
                    if v.is_primitive() {
                        std::println!("{line_pre} = {}", v.one_line());
                    } else {
                        std::println!("{line_pre}:");
                        v.render(indent + 4);
                    }
                }
            }
            Value::Map(items) => {
                std::println!("{pre}map({}):", items.len());
                for (k, v) in items {
                    let key = k.one_line();
                    let key_pre = format!("{}{}", " ".repeat(indent + 2), key);
                    if v.is_primitive() {
                        std::println!("{key_pre} = {}", v.one_line());
                    } else {
                        std::println!("{key_pre}:");
                        v.render(indent + 4);
                    }
                }
            }
            _ => std::println!("{pre}{}", self.one_line()),
        }
    }
}

/// Parse one msgpack value from `buf`. Returns the value plus any trailing
/// bytes that weren't consumed.
pub fn parse(buf: &[u8]) -> Result<(Value, &[u8]), ParseError> {
    let mut p = Parser { buf, pos: 0 };
    let v = p.value()?;
    Ok((v, &buf[p.pos..]))
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn read_u8(&mut self) -> Result<u8, ParseError> {
        let b = *self.buf.get(self.pos).ok_or(ParseError::MsgpackTruncated)?;
        self.pos += 1;
        Ok(b)
    }
    fn read_slice(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(ParseError::MsgpackTruncated)?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or(ParseError::MsgpackTruncated)?;
        self.pos = end;
        Ok(s)
    }
    fn read_be<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        let s = self.read_slice(N)?;
        Ok(s.try_into().unwrap())
    }
    fn value(&mut self) -> Result<Value, ParseError> {
        let t = self.read_u8()?;
        Ok(match t {
            0xc0 => Value::Nil,
            0xc2 => Value::Bool(false),
            0xc3 => Value::Bool(true),
            0x00..=0x7f => Value::UInt(t as u64),
            0xe0..=0xff => Value::Int(t as i8 as i64),
            0xcc => Value::UInt(self.read_u8()? as u64),
            0xcd => Value::UInt(u16::from_be_bytes(self.read_be::<2>()?) as u64),
            0xce => Value::UInt(u32::from_be_bytes(self.read_be::<4>()?) as u64),
            0xcf => Value::UInt(u64::from_be_bytes(self.read_be::<8>()?)),
            0xd0 => Value::Int(self.read_u8()? as i8 as i64),
            0xd1 => Value::Int(i16::from_be_bytes(self.read_be::<2>()?) as i64),
            0xd2 => Value::Int(i32::from_be_bytes(self.read_be::<4>()?) as i64),
            0xd3 => Value::Int(i64::from_be_bytes(self.read_be::<8>()?)),
            0xca => Value::F32(f32::from_be_bytes(self.read_be::<4>()?)),
            0xcb => Value::F64(f64::from_be_bytes(self.read_be::<8>()?)),
            0xa0..=0xbf => self.read_str((t & 0x1f) as usize)?,
            0xd9 => {
                let n = self.read_u8()? as usize;
                self.read_str(n)?
            }
            0xda => {
                let n = u16::from_be_bytes(self.read_be::<2>()?) as usize;
                self.read_str(n)?
            }
            0xdb => {
                let n = u32::from_be_bytes(self.read_be::<4>()?) as usize;
                self.read_str(n)?
            }
            0xc4 => {
                let n = self.read_u8()? as usize;
                Value::Bin(self.read_slice(n)?.to_vec())
            }
            0xc5 => {
                let n = u16::from_be_bytes(self.read_be::<2>()?) as usize;
                Value::Bin(self.read_slice(n)?.to_vec())
            }
            0xc6 => {
                let n = u32::from_be_bytes(self.read_be::<4>()?) as usize;
                Value::Bin(self.read_slice(n)?.to_vec())
            }
            0x90..=0x9f => self.read_array((t & 0x0f) as usize)?,
            0xdc => {
                let n = u16::from_be_bytes(self.read_be::<2>()?) as usize;
                self.read_array(n)?
            }
            0xdd => {
                let n = u32::from_be_bytes(self.read_be::<4>()?) as usize;
                self.read_array(n)?
            }
            0x80..=0x8f => self.read_map((t & 0x0f) as usize)?,
            0xde => {
                let n = u16::from_be_bytes(self.read_be::<2>()?) as usize;
                self.read_map(n)?
            }
            0xdf => {
                let n = u32::from_be_bytes(self.read_be::<4>()?) as usize;
                self.read_map(n)?
            }
            0xd4 => self.read_fixext(1)?,
            0xd5 => self.read_fixext(2)?,
            0xd6 => self.read_fixext(4)?,
            0xd7 => self.read_fixext(8)?,
            0xd8 => self.read_fixext(16)?,
            0xc7 => {
                let n = self.read_u8()? as usize;
                let ty = self.read_u8()? as i8;
                Value::Ext {
                    ty,
                    data: self.read_slice(n)?.to_vec(),
                }
            }
            0xc8 => {
                let n = u16::from_be_bytes(self.read_be::<2>()?) as usize;
                let ty = self.read_u8()? as i8;
                Value::Ext {
                    ty,
                    data: self.read_slice(n)?.to_vec(),
                }
            }
            0xc9 => {
                let n = u32::from_be_bytes(self.read_be::<4>()?) as usize;
                let ty = self.read_u8()? as i8;
                Value::Ext {
                    ty,
                    data: self.read_slice(n)?.to_vec(),
                }
            }
            _ => return Err(ParseError::MsgpackUnknownType(t)),
        })
    }
    fn read_str(&mut self, n: usize) -> Result<Value, ParseError> {
        let bytes = self.read_slice(n)?.to_vec();
        match String::from_utf8(bytes) {
            Ok(s) => Ok(Value::Str(s)),
            Err(_) => Err(ParseError::MsgpackInvalidUtf8),
        }
    }
    fn read_array(&mut self, n: usize) -> Result<Value, ParseError> {
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            items.push(self.value()?);
        }
        Ok(Value::Array(items))
    }
    fn read_map(&mut self, n: usize) -> Result<Value, ParseError> {
        let mut items = Vec::with_capacity(n);
        for _ in 0..n {
            let k = self.value()?;
            let v = self.value()?;
            items.push((k, v));
        }
        Ok(Value::Map(items))
    }
    fn read_fixext(&mut self, n: usize) -> Result<Value, ParseError> {
        let ty = self.read_u8()? as i8;
        let data = self.read_slice(n)?.to_vec();
        Ok(Value::Ext { ty, data })
    }
}

// ---------------------------------------------------------------------------
// Encoders.
// ---------------------------------------------------------------------------

/// Encode a UTF-8 string as the smallest fitting msgpack str variant.
pub fn encode_str(s: &[u8]) -> Vec<u8> {
    let n = s.len();
    let mut out = Vec::with_capacity(n + 5);
    if n <= 31 {
        out.push(0xa0 | (n as u8));
    } else if n <= 0xff {
        out.push(0xd9);
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xda);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(0xdb);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    out.extend_from_slice(s);
    out
}

/// Encode an unsigned int in the smallest fitting variant.
pub fn encode_uint(v: u64) -> Vec<u8> {
    if v <= 0x7f {
        vec![v as u8]
    } else if v <= 0xff {
        vec![0xcc, v as u8]
    } else if v <= 0xffff {
        let mut b = vec![0xcd];
        b.extend_from_slice(&(v as u16).to_be_bytes());
        b
    } else if v <= 0xffff_ffff {
        let mut b = vec![0xce];
        b.extend_from_slice(&(v as u32).to_be_bytes());
        b
    } else {
        let mut b = vec![0xcf];
        b.extend_from_slice(&v.to_be_bytes());
        b
    }
}

/// Encode a signed int in the smallest fitting variant.
pub fn encode_int(v: i64) -> Vec<u8> {
    if (-32..=127).contains(&v) {
        vec![v as u8]
    } else if (i8::MIN as i64..=i8::MAX as i64).contains(&v) {
        vec![0xd0, v as i8 as u8]
    } else if (i16::MIN as i64..=i16::MAX as i64).contains(&v) {
        let mut b = vec![0xd1];
        b.extend_from_slice(&(v as i16).to_be_bytes());
        b
    } else if (i32::MIN as i64..=i32::MAX as i64).contains(&v) {
        let mut b = vec![0xd2];
        b.extend_from_slice(&(v as i32).to_be_bytes());
        b
    } else {
        let mut b = vec![0xd3];
        b.extend_from_slice(&v.to_be_bytes());
        b
    }
}

/// Encode an array-of-msgpack-bytes prefix. Append the pre-encoded items.
pub fn encode_array_prefix(n: usize) -> Vec<u8> {
    if n <= 15 {
        vec![0x90 | n as u8]
    } else if n <= 0xffff {
        let mut b = vec![0xdc];
        b.extend_from_slice(&(n as u16).to_be_bytes());
        b
    } else {
        let mut b = vec![0xdd];
        b.extend_from_slice(&(n as u32).to_be_bytes());
        b
    }
}

/// Encode a map-of-(key,value)-pairs prefix. Append the pre-encoded pairs.
pub fn encode_map_prefix(n: usize) -> Vec<u8> {
    if n <= 15 {
        vec![0x80 | n as u8]
    } else if n <= 0xffff {
        let mut b = vec![0xde];
        b.extend_from_slice(&(n as u16).to_be_bytes());
        b
    } else {
        let mut b = vec![0xdf];
        b.extend_from_slice(&(n as u32).to_be_bytes());
        b
    }
}

pub const NIL: u8 = 0xc0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_str() {
        let enc = encode_str(b"hello");
        let (v, rest) = parse(&enc).unwrap();
        assert!(rest.is_empty());
        match v {
            Value::Str(s) => assert_eq!(s, "hello"),
            _ => panic!("expected str"),
        }
    }

    #[test]
    fn roundtrip_uint() {
        for &v in &[
            0u64,
            127,
            128,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let enc = encode_uint(v);
            let (val, _) = parse(&enc).unwrap();
            match val {
                Value::UInt(got) => assert_eq!(got, v, "uint roundtrip mismatch for {v}"),
                _ => panic!("expected uint for {v}"),
            }
        }
    }

    #[test]
    fn parse_nil_and_bool() {
        let (v, _) = parse(&[NIL]).unwrap();
        assert!(matches!(v, Value::Nil));
        let (v, _) = parse(&[0xc3]).unwrap();
        assert!(matches!(v, Value::Bool(true)));
    }

    #[test]
    fn parse_fixmap() {
        // {"a": 1}: 0x81 0xa1 'a' 0x01
        let bytes = [0x81, 0xa1, b'a', 0x01];
        let (v, _) = parse(&bytes).unwrap();
        match v {
            Value::Map(items) => {
                assert_eq!(items.len(), 1);
                match (&items[0].0, &items[0].1) {
                    (Value::Str(k), Value::UInt(n)) => {
                        assert_eq!(k, "a");
                        assert_eq!(*n, 1);
                    }
                    _ => panic!("unexpected map shape"),
                }
            }
            _ => panic!("expected map"),
        }
    }

    #[test]
    fn rejects_unknown_tag() {
        // 0xc1 is the explicitly-reserved msgpack byte.
        let err = parse(&[0xc1]).unwrap_err();
        assert_eq!(err, ParseError::MsgpackUnknownType(0xc1));
    }
}
