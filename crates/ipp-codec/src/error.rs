//! Codec error types.

use std::fmt;

/// Errors produced while decoding or encoding an IPP message.
#[derive(Debug)]
pub enum CodecError {
    /// Ran out of input before a complete element was read.
    Truncated { needed: usize, at: usize },
    /// `0x00` on the wire, or a second `operation-attributes` group tag.
    InvalidGroupTag { tag: u8, at: usize },
    /// A delimiter group tag appeared inside a collection.
    GroupTagInCollection { tag: u8, at: usize },
    /// A named attribute appeared inside a collection (names only travel
    /// via `memberAttrName` there).
    NamedAttributeInCollection { at: usize },
    /// A zero-length name arrived with no current attribute to extend.
    ValueWithoutAttribute { at: usize },
    /// `memberAttrName` used outside a collection.
    MemberNameOutsideCollection { at: usize },
    /// `memberAttrName` with a non-empty name field.
    MemberNameNotEmpty { at: usize },
    /// `memberAttrName` with an empty value (the member's name).
    MemberNameEmptyValue { at: usize },
    /// Attribute or member name fails the RFC 8011 §5.1.4 keyword check
    /// (alphanumeric plus `-`, `.`, `_`; max 255 bytes).
    InvalidName { at: usize },
    /// A `1setOf` mixes incompatible value tags.
    IncompatibleSetOf { attr_tag: u8, tag: u8, at: usize },
    /// A value's byte length doesn't match what its tag requires.
    BadValueLength {
        tag: u8,
        expected: usize,
        got: usize,
        at: usize,
    },
    /// Name or value exceeds the 32767-byte wire limit.
    LengthOverflow {
        field: &'static str,
        len: usize,
        at: usize,
    },
    /// `begCollection`/`endCollection` carried a non-empty value.
    CollectionValueNotEmpty { at: usize },
    /// Collection nesting deeper than libcups' limit of 10.
    CollectionTooDeep,
    /// Encoding was asked to write something that can't go on the wire.
    Encode(String),
}

impl CodecError {
    pub(crate) fn truncated(needed: usize, at: usize) -> Self {
        Self::Truncated { needed, at }
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, at } => {
                write!(f, "truncated input: need {needed} byte(s) at offset {at}")
            }
            Self::InvalidGroupTag { tag, at } => {
                write!(f, "invalid group tag 0x{tag:02x} at offset {at}")
            }
            Self::GroupTagInCollection { tag, at } => {
                write!(f, "group tag 0x{tag:02x} inside collection at offset {at}")
            }
            Self::NamedAttributeInCollection { at } => {
                write!(f, "named attribute inside collection at offset {at}")
            }
            Self::ValueWithoutAttribute { at } => {
                write!(f, "attribute value without a name at offset {at}")
            }
            Self::MemberNameOutsideCollection { at } => {
                write!(f, "memberAttrName outside of collection at offset {at}")
            }
            Self::MemberNameNotEmpty { at } => {
                write!(f, "memberAttrName with non-empty name at offset {at}")
            }
            Self::MemberNameEmptyValue { at } => {
                write!(f, "memberAttrName with empty value at offset {at}")
            }
            Self::InvalidName { at } => {
                write!(f, "invalid attribute/member name at offset {at}")
            }
            Self::IncompatibleSetOf { attr_tag, tag, at } => write!(
                f,
                "1setOf tag mismatch: attribute tag 0x{attr_tag:02x} vs 0x{tag:02x} at offset {at}"
            ),
            Self::BadValueLength {
                tag,
                expected,
                got,
                at,
            } => write!(
                f,
                "bad value length for tag 0x{tag:02x}: expected {expected}, got {got} at offset {at}"
            ),
            Self::LengthOverflow { field, len, at } => {
                write!(f, "{field} length {len} exceeds limit at offset {at}")
            }
            Self::CollectionValueNotEmpty { at } => {
                write!(f, "collection delimiter with non-empty value at offset {at}")
            }
            Self::CollectionTooDeep => write!(f, "collections nested more than 10 deep"),
            Self::Encode(msg) => write!(f, "encode error: {msg}"),
        }
    }
}

impl std::error::Error for CodecError {}
