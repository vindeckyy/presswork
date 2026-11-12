//! IPP message model: messages, groups, attributes, and values.

use crate::tags;

/// A length-prefixed byte string used for IPP text-ish values.
///
/// The wire format is opaque bytes; IPP requires UTF-8 when
/// `attributes-charset` is `utf-8` but real-world traffic can contain
/// anything. Storing bytes keeps decode→encode round-trips exact.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Text(pub Vec<u8>);

impl Text {
    #[must_use]
    pub fn new() -> Self {
        Self(Vec::new())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Lossy UTF-8 view for display and comparisons.
    #[must_use]
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.0)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&str> for Text {
    fn from(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }
}

impl From<String> for Text {
    fn from(s: String) -> Self {
        Self(s.into_bytes())
    }
}

impl From<Vec<u8>> for Text {
    fn from(b: Vec<u8>) -> Self {
        Self(b)
    }
}

impl AsRef<[u8]> for Text {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq<str> for Text {
    fn eq(&self, other: &str) -> bool {
        self.0 == other.as_bytes()
    }
}

impl PartialEq<&str> for Text {
    fn eq(&self, other: &&str) -> bool {
        self.0 == other.as_bytes()
    }
}

impl std::fmt::Display for Text {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// One IPP value. Which variant is legal is determined by the owning
/// attribute's `tag`; see [`Attribute::tag`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    // Out-of-band values (always zero-length on the wire).
    Unsupported,
    Default,
    Unknown,
    NoValue,
    NotSettable,
    DeleteAttr,
    AdminDefine,

    Integer(i32),
    Boolean(bool),
    Enum(i32),
    OctetString(Vec<u8>),
    /// The raw 11-byte IPP dateTime (year, month, day, hour, min, sec,
    /// deci-sec, sign, tz-hours, tz-mins).
    DateTime([u8; 11]),
    Resolution {
        x: i32,
        y: i32,
        units: u8,
    },
    Range {
        low: i32,
        high: i32,
    },
    /// A `begCollection` value: the member attributes of the collection.
    Collection(Vec<Attribute>),
    TextWithLanguage {
        lang: Text,
        text: Text,
    },
    NameWithLanguage {
        lang: Text,
        text: Text,
    },
    Text(Text),
    Name(Text),
    ReservedString(Vec<u8>),
    Keyword(Text),
    Uri(Text),
    UriScheme(Text),
    Charset(Text),
    NaturalLanguage(Text),
    MimeMediaType(Text),
    /// A `memberAttrName` value — only meaningful while decoding; never
    /// stored on a decoded attribute.
    MemberName(Text),
    /// Any unrecognized or extension value tag; payload kept verbatim.
    UnknownValue {
        tag: u8,
        data: Vec<u8>,
    },
}

impl Value {
    /// The wire value tag that encodes this variant.
    #[must_use]
    pub fn tag(&self) -> u8 {
        match self {
            Self::Unsupported => tags::UNSUPPORTED,
            Self::Default => tags::DEFAULT,
            Self::Unknown => tags::UNKNOWN,
            Self::NoValue => tags::NOVALUE,
            Self::NotSettable => tags::NOTSETTABLE,
            Self::DeleteAttr => tags::DELETEATTR,
            Self::AdminDefine => tags::ADMINDEFINE,
            Self::Integer(_) => tags::INTEGER,
            Self::Boolean(_) => tags::BOOLEAN,
            Self::Enum(_) => tags::ENUM,
            Self::OctetString(_) => tags::STRING,
            Self::DateTime(_) => tags::DATE,
            Self::Resolution { .. } => tags::RESOLUTION,
            Self::Range { .. } => tags::RANGE,
            Self::Collection(_) => tags::BEGIN_COLLECTION,
            Self::TextWithLanguage { .. } => tags::TEXTLANG,
            Self::NameWithLanguage { .. } => tags::NAMELANG,
            Self::Text(_) => tags::TEXT,
            Self::Name(_) => tags::NAME,
            Self::ReservedString(_) => tags::RESERVED_STRING,
            Self::Keyword(_) => tags::KEYWORD,
            Self::Uri(_) => tags::URI,
            Self::UriScheme(_) => tags::URISCHEME,
            Self::Charset(_) => tags::CHARSET,
            Self::NaturalLanguage(_) => tags::LANGUAGE,
            Self::MimeMediaType(_) => tags::MIMETYPE,
            Self::MemberName(_) => tags::MEMBERNAME,
            Self::UnknownValue { tag, .. } => *tag,
        }
    }
}

/// A single IPP attribute: name, value tag, and one or more values.
///
/// A *separator* (libcups `ippAddSeparator`) is represented as an
/// attribute with `tag == tags::ZERO` and an empty `name`; it re-emits
/// the enclosing group's delimiter byte when encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute {
    pub name: Text,
    pub tag: u8,
    pub values: Vec<Value>,
}

impl Attribute {
    #[must_use]
    pub fn new(name: impl Into<Text>, tag: u8, values: Vec<Value>) -> Self {
        Self {
            name: name.into(),
            tag,
            values,
        }
    }

    /// An in-group separator (re-emits the group delimiter on encode).
    #[must_use]
    pub fn separator() -> Self {
        Self {
            name: Text::new(),
            tag: tags::ZERO,
            values: Vec::new(),
        }
    }

    #[must_use]
    pub fn is_separator(&self) -> bool {
        self.tag == tags::ZERO && self.name.is_empty()
    }

    /// First value's typed view, if present.
    #[must_use]
    pub fn first(&self) -> Option<&Value> {
        self.values.first()
    }

    /// Convenience: first integer-ish value (integer, enum, or boolean).
    #[must_use]
    pub fn int(&self) -> Option<i32> {
        match self.first() {
            Some(Value::Integer(v) | Value::Enum(v)) => Some(*v),
            Some(Value::Boolean(b)) => Some(i32::from(*b)),
            _ => None,
        }
    }

    /// Convenience: first text-ish value as a lossy string.
    #[must_use]
    pub fn text(&self) -> Option<std::borrow::Cow<'_, str>> {
        match self.first() {
            Some(
                Value::Text(t)
                | Value::Name(t)
                | Value::Keyword(t)
                | Value::Uri(t)
                | Value::UriScheme(t)
                | Value::Charset(t)
                | Value::NaturalLanguage(t)
                | Value::MimeMediaType(t)
                | Value::MemberName(t),
            ) => Some(t.as_str()),
            Some(Value::TextWithLanguage { text, .. } | Value::NameWithLanguage { text, .. }) => {
                Some(text.as_str())
            }
            _ => None,
        }
    }
}

/// One delimiter group in an IPP message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub tag: u8,
    pub attributes: Vec<Attribute>,
}

impl Group {
    #[must_use]
    pub fn new(tag: u8) -> Self {
        Self {
            tag,
            attributes: Vec::new(),
        }
    }

    /// First attribute with `name` in this group.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.name == *name)
    }
}

/// A complete IPP message (request or response).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IppMessage {
    /// IPP version as `(major, minor)` — CUPS writes `2.0` by default.
    pub version: (u8, u8),
    /// Operation-id on requests, status-code on responses.
    pub code: u16,
    pub request_id: i32,
    pub groups: Vec<Group>,
    /// Document payload appended after the attribute groups on the wire
    /// (`Send-Document` requests, `Get-Document`/`Get-Presets` responses).
    pub document: Vec<u8>,
}

impl IppMessage {
    #[must_use]
    pub fn new(code: u16) -> Self {
        Self {
            version: (2, 0),
            code,
            request_id: 1,
            groups: Vec::new(),
            document: Vec::new(),
        }
    }

    /// The operation group (`tag::OPERATION`), created on demand.
    pub fn operation_group(&mut self) -> &mut Group {
        self.group_mut(tags::OPERATION)
    }

    /// Group with `tag`, creating and appending it if absent.
    pub fn group_mut(&mut self, tag: u8) -> &mut Group {
        let pos = self
            .groups
            .iter()
            .position(|g| g.tag == tag)
            .unwrap_or_else(|| {
                self.groups.push(Group::new(tag));
                self.groups.len() - 1
            });
        &mut self.groups[pos]
    }

    /// Append a *new* group with `tag` and return it — for repeated group
    /// types (event-notification, document, job) where each occurrence is
    /// a distinct group on the wire, unlike `group_mut` which reuses the
    /// first match.
    pub fn new_group_mut(&mut self, tag: u8) -> &mut Group {
        self.groups.push(Group::new(tag));
        self.groups.last_mut().unwrap()
    }

    /// First group with `tag`.
    #[must_use]
    pub fn group(&self, tag: u8) -> Option<&Group> {
        self.groups.iter().find(|g| g.tag == tag)
    }

    /// First attribute with `name` anywhere in `tag` group.
    #[must_use]
    pub fn find(&self, group_tag: u8, name: &str) -> Option<&Attribute> {
        self.group(group_tag)?.find(name)
    }

    /// All attributes with `name` across every group, in wire order.
    pub fn find_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Attribute> + 'a {
        self.groups
            .iter()
            .flat_map(|g| g.attributes.iter())
            .filter(move |a| a.name == *name)
    }

    /// Append `attr` to the group `tag` (creating the group if needed).
    pub fn push(&mut self, group_tag: u8, attr: Attribute) {
        self.group_mut(group_tag).attributes.push(attr);
    }
}
