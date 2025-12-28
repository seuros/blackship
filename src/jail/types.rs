//! Jail parameter types and configuration structures

use crate::error::Error;
use byteorder::{LittleEndian, NetworkEndian, WriteBytesExt};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Jail parameter value types
#[derive(Debug, Clone, PartialEq)]
pub enum ParamValue {
    /// Integer value (maps to C int)
    Int(i32),
    /// String value
    String(String),
    /// Boolean value (stored as int: 0 or 1)
    Bool(bool),
    /// List of IPv4 addresses
    Ipv4(Vec<Ipv4Addr>),
    /// List of IPv6 addresses
    Ipv6(Vec<Ipv6Addr>),
}

impl ParamValue {
    /// Convert the parameter value to bytes for FFI
    pub fn as_bytes(&self) -> Result<Vec<u8>, Error> {
        match self {
            ParamValue::Int(v) => {
                let mut buf = Vec::with_capacity(4);
                buf.write_i32::<LittleEndian>(*v)
                    .map_err(Error::Io)?;
                Ok(buf)
            }
            ParamValue::String(s) => {
                let cstring = std::ffi::CString::new(s.clone())?;
                Ok(cstring.into_bytes_with_nul())
            }
            ParamValue::Bool(b) => {
                let v = if *b { 1i32 } else { 0i32 };
                let mut buf = Vec::with_capacity(4);
                buf.write_i32::<LittleEndian>(v).map_err(Error::Io)?;
                Ok(buf)
            }
            ParamValue::Ipv4(addrs) => {
                let mut buf = Vec::with_capacity(addrs.len() * 4);
                for addr in addrs {
                    buf.write_u32::<NetworkEndian>(u32::from(*addr))
                        .map_err(Error::Io)?;
                }
                Ok(buf)
            }
            ParamValue::Ipv6(addrs) => {
                let mut buf = Vec::with_capacity(addrs.len() * 16);
                for addr in addrs {
                    buf.extend_from_slice(&addr.octets());
                }
                Ok(buf)
            }
        }
    }
}

impl From<i32> for ParamValue {
    fn from(v: i32) -> Self {
        ParamValue::Int(v)
    }
}

impl From<bool> for ParamValue {
    fn from(v: bool) -> Self {
        ParamValue::Bool(v)
    }
}

impl From<String> for ParamValue {
    fn from(v: String) -> Self {
        ParamValue::String(v)
    }
}

impl From<&str> for ParamValue {
    fn from(v: &str) -> Self {
        ParamValue::String(v.to_string())
    }
}

impl From<Ipv4Addr> for ParamValue {
    fn from(v: Ipv4Addr) -> Self {
        ParamValue::Ipv4(vec![v])
    }
}

impl From<Vec<Ipv4Addr>> for ParamValue {
    fn from(v: Vec<Ipv4Addr>) -> Self {
        ParamValue::Ipv4(v)
    }
}

impl From<Ipv6Addr> for ParamValue {
    fn from(v: Ipv6Addr) -> Self {
        ParamValue::Ipv6(vec![v])
    }
}

impl From<Vec<Ipv6Addr>> for ParamValue {
    fn from(v: Vec<Ipv6Addr>) -> Self {
        ParamValue::Ipv6(v)
    }
}

/// Convert a TOML value to a ParamValue
impl TryFrom<&toml::Value> for ParamValue {
    type Error = Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        match value {
            toml::Value::Integer(i) => Ok(ParamValue::Int(*i as i32)),
            toml::Value::Boolean(b) => Ok(ParamValue::Bool(*b)),
            toml::Value::String(s) => Ok(ParamValue::String(s.clone())),
            _ => Err(Error::ConfigValidation(format!(
                "Unsupported parameter type: {:?}",
                value
            ))),
        }
    }
}
