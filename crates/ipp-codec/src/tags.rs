//! IPP delimiter and value tag constants, mirroring `cups/ipp.h`.

/// Group separator (in-memory only; never valid on the wire).
pub const ZERO: u8 = 0x00;
/// `operation-attributes` group.
pub const OPERATION: u8 = 0x01;
/// `job-attributes` group.
pub const JOB: u8 = 0x02;
/// `end-of-attributes` terminator.
pub const END: u8 = 0x03;
/// `printer-attributes` group.
pub const PRINTER: u8 = 0x04;
/// `unsupported-attributes` group.
pub const UNSUPPORTED_GROUP: u8 = 0x05;
/// `subscription-attributes` group.
pub const SUBSCRIPTION: u8 = 0x06;
/// `event-notification-attributes` group.
pub const EVENT_NOTIFICATION: u8 = 0x07;
/// `resource-attributes` group.
pub const RESOURCE: u8 = 0x08;
/// `document-attributes` group.
pub const DOCUMENT: u8 = 0x09;
/// `system-attributes` group.
pub const SYSTEM: u8 = 0x0a;

pub const UNSUPPORTED: u8 = 0x10;
pub const DEFAULT: u8 = 0x11;
pub const UNKNOWN: u8 = 0x12;
pub const NOVALUE: u8 = 0x13;
pub const NOTSETTABLE: u8 = 0x15;
pub const DELETEATTR: u8 = 0x16;
pub const ADMINDEFINE: u8 = 0x17;

pub const INTEGER: u8 = 0x21;
pub const BOOLEAN: u8 = 0x22;
pub const ENUM: u8 = 0x23;
pub const STRING: u8 = 0x30;
pub const DATE: u8 = 0x31;
pub const RESOLUTION: u8 = 0x32;
pub const RANGE: u8 = 0x33;
pub const BEGIN_COLLECTION: u8 = 0x34;
pub const TEXTLANG: u8 = 0x35;
pub const NAMELANG: u8 = 0x36;
pub const END_COLLECTION: u8 = 0x37;
pub const TEXT: u8 = 0x41;
pub const NAME: u8 = 0x42;
pub const RESERVED_STRING: u8 = 0x43;
pub const KEYWORD: u8 = 0x44;
pub const URI: u8 = 0x45;
pub const URISCHEME: u8 = 0x46;
pub const CHARSET: u8 = 0x47;
pub const LANGUAGE: u8 = 0x48;
pub const MIMETYPE: u8 = 0x49;
pub const MEMBERNAME: u8 = 0x4a;
pub const EXTENSION: u8 = 0x7f;

/// `true` for tags in `0x01..=0x0a` (delimiter group tags).
#[must_use]
pub const fn is_group_tag(tag: u8) -> bool {
    tag >= OPERATION && tag <= SYSTEM
}

/// `true` for out-of-band value tags `0x10..=0x17`.
#[must_use]
pub const fn is_out_of_band(tag: u8) -> bool {
    (tag >= UNSUPPORTED && tag <= NOVALUE) || (tag >= NOTSETTABLE && tag <= ADMINDEFINE)
}

/// `true` for the text-like tags libcups allows mixing within a `1setOf`
/// (`textWithLanguage`, `nameWithLanguage`, and `text..=mimeMediaType`).
#[must_use]
pub const fn is_textlike(tag: u8) -> bool {
    tag == TEXTLANG || tag == NAMELANG || (tag >= TEXT && tag <= MIMETYPE)
}

/// Human-readable tag name, mirroring `ippTagString()`.
#[must_use]
pub fn name(tag: u8) -> &'static str {
    match tag {
        ZERO => "zero",
        OPERATION => "operation-attributes-tag",
        JOB => "job-attributes-tag",
        END => "end-of-attributes-tag",
        PRINTER => "printer-attributes-tag",
        UNSUPPORTED_GROUP => "unsupported-attributes-tag",
        SUBSCRIPTION => "subscription-attributes-tag",
        EVENT_NOTIFICATION => "event-notification-attributes-tag",
        RESOURCE => "resource-attributes-tag",
        DOCUMENT => "document-attributes-tag",
        SYSTEM => "system-attributes-tag",
        UNSUPPORTED => "unsupported",
        DEFAULT => "default",
        UNKNOWN => "unknown",
        NOVALUE => "no-value",
        NOTSETTABLE => "not-settable",
        DELETEATTR => "delete-attribute",
        ADMINDEFINE => "admin-define",
        INTEGER => "integer",
        BOOLEAN => "boolean",
        ENUM => "enum",
        STRING => "octetString",
        DATE => "dateTime",
        RESOLUTION => "resolution",
        RANGE => "rangeOfInteger",
        BEGIN_COLLECTION => "begCollection",
        TEXTLANG => "textWithLanguage",
        NAMELANG => "nameWithLanguage",
        END_COLLECTION => "endCollection",
        TEXT => "textWithoutLanguage",
        NAME => "nameWithoutLanguage",
        RESERVED_STRING => "reserved-for-future-string",
        KEYWORD => "keyword",
        URI => "uri",
        URISCHEME => "uriScheme",
        CHARSET => "charset",
        LANGUAGE => "naturalLanguage",
        MIMETYPE => "mimeMediaType",
        MEMBERNAME => "memberAttrName",
        EXTENSION => "extension",
        _ => "(unknown-tag)",
    }
}
