//! Jail parameter types and configuration structures

use crate::error::Error;
use byteorder::{LittleEndian, NetworkEndian, WriteBytesExt};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Jail parameter value types
#[derive(Debug, Clone, PartialEq, Eq)]
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
            Self::Int(v) => {
                let mut buf = Vec::with_capacity(4);
                buf.write_i32::<LittleEndian>(*v).map_err(Error::Io)?;
                Ok(buf)
            }
            Self::String(s) => {
                let cstring = std::ffi::CString::new(s.clone())?;
                Ok(cstring.into_bytes_with_nul())
            }
            Self::Bool(b) => {
                let v = i32::from(*b);
                let mut buf = Vec::with_capacity(4);
                buf.write_i32::<LittleEndian>(v).map_err(Error::Io)?;
                Ok(buf)
            }
            Self::Ipv4(addrs) => {
                let mut buf = Vec::with_capacity(addrs.len() * 4);
                for addr in addrs {
                    buf.write_u32::<NetworkEndian>(u32::from(*addr))
                        .map_err(Error::Io)?;
                }
                Ok(buf)
            }
            Self::Ipv6(addrs) => {
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
        Self::Int(v)
    }
}

impl From<bool> for ParamValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}

impl From<String> for ParamValue {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for ParamValue {
    fn from(v: &str) -> Self {
        Self::String(v.to_string())
    }
}

impl From<Ipv4Addr> for ParamValue {
    fn from(v: Ipv4Addr) -> Self {
        Self::Ipv4(vec![v])
    }
}

impl From<Vec<Ipv4Addr>> for ParamValue {
    fn from(v: Vec<Ipv4Addr>) -> Self {
        Self::Ipv4(v)
    }
}

impl From<Ipv6Addr> for ParamValue {
    fn from(v: Ipv6Addr) -> Self {
        Self::Ipv6(vec![v])
    }
}

impl From<Vec<Ipv6Addr>> for ParamValue {
    fn from(v: Vec<Ipv6Addr>) -> Self {
        Self::Ipv6(v)
    }
}

/// Convert a TOML value to a `ParamValue`
impl TryFrom<&toml::Value> for ParamValue {
    type Error = Error;

    fn try_from(value: &toml::Value) -> Result<Self, Self::Error> {
        match value {
            toml::Value::Integer(i) => i32::try_from(*i).map(Self::Int).map_err(|_| {
                Error::ConfigValidation(format!("Integer parameter out of range: {i}"))
            }),
            toml::Value::Boolean(b) => Ok(Self::Bool(*b)),
            toml::Value::String(s) => Ok(Self::String(s.clone())),
            _ => Err(Error::ConfigValidation(format!(
                "Unsupported parameter type: {value:?}"
            ))),
        }
    }
}
