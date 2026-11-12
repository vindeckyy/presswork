//! # ipp-codec
//!
//! IPP (Internet Printing Protocol) wire codec and message model with
//! libcups-compatible encoding semantics.
//!
//! This crate is the foundation of the cupsd rewrite: every HTTP request
//! body on port 631 is an IPP message, and the byte-level details matter —
//! delimiter-group ordering, separator re-emission, `memberAttrName`
//! collection framing, out-of-band tags, `1setOf` value-tag coercion, and
//! the CUPS-private operation IDs are all preserved exactly.
//!
//! ```rust
//! use ipp_codec::{decode, encode, Attribute, Group, IppMessage, Text, Value, tags, ops};
//!
//! let mut msg = IppMessage::new(ops::status::OK);
//! msg.request_id = 42;
//! let mut op = Group::new(tags::OPERATION);
//! op.attributes.push(Attribute::new(
//!     "attributes-charset",
//!     tags::CHARSET,
//!     vec![Value::Charset(Text::from("utf-8"))],
//! ));
//! msg.groups.push(op);
//!
//! let bytes = encode(&msg).unwrap();
//! let (back, doc_offset) = decode(&bytes).unwrap();
//! assert_eq!(doc_offset, bytes.len());
//! assert_eq!(back.code, ops::status::OK);
//! ```

pub mod codec;
pub mod error;
pub mod model;
pub mod ops;
pub mod tags;

pub use codec::{decode, encode, MAX_COLLECTION_DEPTH, MAX_NAME_LEN, MAX_VALUE_LEN};
pub use error::CodecError;
pub use model::{Attribute, Group, IppMessage, Text, Value};

#[cfg(test)]
mod tests {
    use super::*;

    fn op_attr(name: &str, tag: u8, values: Vec<Value>) -> Attribute {
        Attribute::new(name, tag, values)
    }

    #[test]
    fn header_only_message() {
        let mut msg = IppMessage::new(ops::op::GET_PRINTER_ATTRIBUTES);
        msg.request_id = 7;
        let bytes = encode(&msg).unwrap();
        assert_eq!(bytes.len(), 9);
        assert_eq!(&bytes[..8], &[2, 0, 0, 0x0b, 0, 0, 0, 7]);
        assert_eq!(bytes[8], tags::END);

        let (back, off) = decode(&bytes).unwrap();
        assert_eq!(off, 9);
        assert_eq!(back.version, (2, 0));
        assert_eq!(back.code, ops::op::GET_PRINTER_ATTRIBUTES);
        assert_eq!(back.request_id, 7);
        assert_eq!(back.groups, [] as [model::Group; 0]);
    }

    #[test]
    fn simple_roundtrip() {
        let mut msg = IppMessage::new(ops::op::GET_PRINTER_ATTRIBUTES);
        msg.request_id = 1;
        let mut op = Group::new(tags::OPERATION);
        op.attributes.extend([
            op_attr(
                "attributes-charset",
                tags::CHARSET,
                vec![Value::Charset("utf-8".into())],
            ),
            op_attr(
                "attributes-natural-language",
                tags::LANGUAGE,
                vec![Value::NaturalLanguage("en".into())],
            ),
            op_attr(
                "printer-uri",
                tags::URI,
                vec![Value::Uri("ipp://localhost/printers/x".into())],
            ),
            op_attr(
                "requested-attributes",
                tags::KEYWORD,
                vec![
                    Value::Keyword("all".into()),
                    Value::Keyword("media-col-database".into()),
                ],
            ),
            op_attr("limit", tags::INTEGER, vec![Value::Integer(50)]),
            op_attr("first-value", tags::BOOLEAN, vec![Value::Boolean(true)]),
        ]);
        msg.groups.push(op);

        let bytes = encode(&msg).unwrap();
        let (back, off) = decode(&bytes).unwrap();
        assert_eq!(off, bytes.len());
        assert_eq!(back, msg);
    }

    #[test]
    fn byte_exact_known_packet() {
        // A minimal Get-Printer-Attributes request, hand-encoded per
        // RFC 8010 to verify exact byte layout.
        let mut expected = vec![
            2,
            0, // version 2.0
            0,
            0x0b, // Get-Printer-Attributes
            0,
            0,
            0,
            1, // request-id 1
            tags::OPERATION,
            tags::CHARSET,
            0,
            18, // namelen 18
        ];
        expected.extend_from_slice(b"attributes-charset");
        expected.extend_from_slice(&[0, 5]); // vallen 5
        expected.extend_from_slice(b"utf-8");
        expected.push(tags::END);

        let (msg, off) = decode(&expected).unwrap();
        assert_eq!(off, expected.len());
        assert_eq!(msg.code, ops::op::GET_PRINTER_ATTRIBUTES);
        let attr = msg.find(tags::OPERATION, "attributes-charset").unwrap();
        assert_eq!(attr.values, vec![Value::Charset("utf-8".into())]);
    }

    #[test]
    fn collection_roundtrip() {
        // media-col={media-size={x-dimension=21000 y-dimension=29700} media-type=stationery}
        let mut msg = IppMessage::new(ops::op::PRINT_JOB);
        let media_size = Attribute::new(
            "media-size",
            tags::BEGIN_COLLECTION,
            vec![Value::Collection(vec![
                Attribute::new("x-dimension", tags::INTEGER, vec![Value::Integer(21000)]),
                Attribute::new("y-dimension", tags::INTEGER, vec![Value::Integer(29700)]),
            ])],
        );
        let media_col = Attribute::new(
            "media-col",
            tags::BEGIN_COLLECTION,
            vec![Value::Collection(vec![
                media_size,
                Attribute::new(
                    "media-type",
                    tags::KEYWORD,
                    vec![Value::Keyword("stationery".into())],
                ),
            ])],
        );
        let mut job = Group::new(tags::JOB);
        job.attributes.push(media_col);
        msg.groups.push(job);

        let bytes = encode(&msg).unwrap();
        let (back, off) = decode(&bytes).unwrap();
        assert_eq!(off, bytes.len());
        assert_eq!(back, msg);
    }

    #[test]
    fn collection_wire_layout() {
        // Verify memberAttrName/endCollection framing byte-for-byte.
        let mut msg = IppMessage::new(ops::op::PRINT_JOB);
        let col = Attribute::new(
            "col",
            tags::BEGIN_COLLECTION,
            vec![Value::Collection(vec![Attribute::new(
                "member",
                tags::INTEGER,
                vec![Value::Integer(1)],
            )])],
        );
        let mut g = Group::new(tags::JOB);
        g.attributes.push(col);
        msg.groups.push(g);

        let bytes = encode(&msg).unwrap();
        // ...job group, begCollection, "col", vallen 0,
        // memberAttrName, namelen 0, vallen 6, "member",
        // integer, namelen 0, vallen 4, 0,0,0,1,
        // endCollection + 4 zeros, END
        let tail = &bytes[bytes.len() - 26..];
        assert_eq!(
            tail,
            &[
                tags::MEMBERNAME,
                0,
                0,
                0,
                6,
                b'm',
                b'e',
                b'm',
                b'b',
                b'e',
                b'r',
                tags::INTEGER,
                0,
                0,
                0,
                4,
                0,
                0,
                0,
                1,
                tags::END_COLLECTION,
                0,
                0,
                0,
                0,
                tags::END,
            ]
        );
    }

    #[test]
    fn multivalue_collection_roundtrip() {
        // 1setOf collections: multiple Collection values on one attribute.
        let mut msg = IppMessage::new(ops::op::PRINT_JOB);
        let attr = Attribute::new(
            "cols",
            tags::BEGIN_COLLECTION,
            vec![
                Value::Collection(vec![Attribute::new(
                    "a",
                    tags::INTEGER,
                    vec![Value::Integer(1)],
                )]),
                Value::Collection(vec![Attribute::new(
                    "b",
                    tags::INTEGER,
                    vec![Value::Integer(2)],
                )]),
            ],
        );
        let mut g = Group::new(tags::JOB);
        g.attributes.push(attr);
        msg.groups.push(g);

        let bytes = encode(&msg).unwrap();
        let (back, _) = decode(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn separator_repeated_group() {
        // Two job-groups on the wire = separator within the job group.
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1];
        for _ in 0..2 {
            bytes.push(tags::JOB);
            bytes.extend_from_slice(&[tags::KEYWORD, 0, 4]);
            bytes.extend_from_slice(b"attr");
            bytes.extend_from_slice(&[0, 1]);
            bytes.extend_from_slice(b"x");
        }
        bytes.push(tags::END);

        let (msg, _) = decode(&bytes).unwrap();
        let job = msg.group(tags::JOB).unwrap();
        assert_eq!(job.attributes.len(), 3);
        assert!(job.attributes[1].is_separator());

        // Re-encoding emits the repeated group tag → same bytes.
        assert_eq!(encode(&msg).unwrap(), bytes);
    }

    #[test]
    fn second_operation_group_rejected() {
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::OPERATION];
        bytes.extend_from_slice(&[tags::KEYWORD, 0, 1, b'a', 0, 1, b'x']);
        bytes.push(tags::OPERATION);
        let err = decode(&bytes).unwrap_err();
        assert!(matches!(err, CodecError::InvalidGroupTag { .. }));
    }

    #[test]
    fn zero_tag_rejected() {
        let bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::ZERO, tags::END];
        assert!(matches!(
            decode(&bytes),
            Err(CodecError::InvalidGroupTag { .. })
        ));
    }

    #[test]
    fn out_of_band_values() {
        let mut msg = IppMessage::new(ops::status::OK);
        let mut g = Group::new(tags::JOB);
        g.attributes
            .push(op_attr("unset", tags::NOVALUE, vec![Value::NoValue]));
        g.attributes
            .push(op_attr("del", tags::DELETEATTR, vec![Value::DeleteAttr]));
        msg.groups.push(g);
        let bytes = encode(&msg).unwrap();
        let (back, _) = decode(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn brother_oob_quirk() {
        // A no-value attribute carrying a non-empty payload is remapped
        // to a text value (libcups compat for buggy vendors).
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::NOVALUE, 0, 3]);
        bytes.extend_from_slice(b"oob");
        bytes.extend_from_slice(&[0, 5]);
        bytes.extend_from_slice(b"junk!");
        bytes.push(tags::END);

        let (msg, _) = decode(&bytes).unwrap();
        let attr = msg.group(tags::JOB).unwrap().find("oob").unwrap();
        assert_eq!(attr.tag, tags::TEXT);
        assert_eq!(attr.values, vec![Value::Text("junk!".into())]);
    }

    #[test]
    fn textlike_mixed_setof_coerces() {
        // nameWithLanguage + nameWithoutLanguage in one 1setOf is legal;
        // the attribute adopts the later tag.
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::NAMELANG, 0, 4]);
        bytes.extend_from_slice(b"name");
        // value: lang "en" + text "hello"
        bytes.extend_from_slice(&[0, 11, 0, 2, b'e', b'n', 0, 5]);
        bytes.extend_from_slice(b"hello");
        bytes.extend_from_slice(&[tags::NAME, 0, 0, 0, 5]);
        bytes.extend_from_slice(b"world");
        bytes.push(tags::END);

        let (msg, _) = decode(&bytes).unwrap();
        let attr = msg.group(tags::JOB).unwrap().find("name").unwrap();
        assert_eq!(attr.tag, tags::NAME);
        assert_eq!(
            attr.values[0],
            Value::NameWithLanguage {
                lang: "en".into(),
                text: "hello".into()
            }
        );
        assert_eq!(attr.values[1], Value::Name("world".into()));
    }

    #[test]
    fn incompatible_setof_rejected() {
        // integer attr then a uri value → client-error.
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::INTEGER, 0, 3]);
        bytes.extend_from_slice(b"num");
        bytes.extend_from_slice(&[0, 4, 0, 0, 0, 5]);
        bytes.extend_from_slice(&[tags::URI, 0, 0, 0, 3]);
        bytes.extend_from_slice(b"uri");
        bytes.push(tags::END);
        assert!(matches!(
            decode(&bytes),
            Err(CodecError::IncompatibleSetOf { .. })
        ));
    }

    #[test]
    fn integer_range_promotion() {
        // integer value then rangeOfInteger value → whole attr becomes range.
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::INTEGER, 0, 4]);
        bytes.extend_from_slice(b"nums");
        bytes.extend_from_slice(&[0, 4, 0, 0, 0, 5]);
        bytes.extend_from_slice(&[tags::RANGE, 0, 0, 0, 8, 0, 0, 0, 10, 0, 0, 0, 20]);
        bytes.push(tags::END);

        let (msg, _) = decode(&bytes).unwrap();
        let attr = msg.group(tags::JOB).unwrap().find("nums").unwrap();
        assert_eq!(attr.tag, tags::RANGE);
        assert_eq!(
            attr.values,
            vec![
                Value::Range { low: 5, high: 5 },
                Value::Range { low: 10, high: 20 }
            ]
        );
    }

    #[test]
    fn document_data_offset() {
        // Send-Document: IPP message followed by document bytes.
        let mut msg = IppMessage::new(ops::op::SEND_DOCUMENT);
        let mut g = Group::new(tags::OPERATION);
        g.attributes.push(op_attr(
            "last-document",
            tags::BOOLEAN,
            vec![Value::Boolean(true)],
        ));
        msg.groups.push(g);
        let mut bytes = encode(&msg).unwrap();
        let msg_len = bytes.len();
        bytes.extend_from_slice(b"%PDF-1.7 fake document bytes");

        let (decoded, off) = decode(&bytes).unwrap();
        assert_eq!(off, msg_len);
        assert_eq!(&bytes[off..], b"%PDF-1.7 fake document bytes");
        assert_eq!(decoded, msg);
    }

    #[test]
    fn datetime_resolution_range() {
        let mut msg = IppMessage::new(ops::op::GET_JOBS);
        let mut g = Group::new(tags::JOB);
        g.attributes.push(op_attr(
            "date",
            tags::DATE,
            vec![Value::DateTime([
                0x07, 0xe9, 11, 11, 12, 30, 0, 5, b'+', 1, 0,
            ])],
        ));
        g.attributes.push(op_attr(
            "res",
            tags::RESOLUTION,
            vec![Value::Resolution {
                x: 600,
                y: 600,
                units: 3,
            }],
        ));
        g.attributes.push(op_attr(
            "rng",
            tags::RANGE,
            vec![Value::Range { low: 1, high: 99 }],
        ));
        msg.groups.push(g);
        let bytes = encode(&msg).unwrap();
        let (back, _) = decode(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn named_attr_in_collection_rejected() {
        // memberAttrName with non-empty name field → error.
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::BEGIN_COLLECTION, 0, 3]);
        bytes.extend_from_slice(b"col");
        bytes.extend_from_slice(&[0, 0]); // vallen 0
                                          // membername with a non-empty *name* (illegal):
        bytes.extend_from_slice(&[tags::MEMBERNAME, 0, 4]);
        bytes.extend_from_slice(b"oops");
        bytes.extend_from_slice(&[0, 1, b'x']);
        bytes.push(tags::END);
        assert!(matches!(
            decode(&bytes),
            Err(CodecError::MemberNameNotEmpty { .. })
        ));
    }

    #[test]
    fn invalid_attribute_name_rejected() {
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::KEYWORD, 0, 3]);
        bytes.extend_from_slice(b"a b"); // space is invalid
        bytes.extend_from_slice(&[0, 1, b'x']);
        bytes.push(tags::END);
        assert!(matches!(
            decode(&bytes),
            Err(CodecError::InvalidName { .. })
        ));
    }

    #[test]
    fn value_without_attribute_rejected() {
        let mut bytes = vec![2, 0, 0, 0x0b, 0, 0, 0, 1, tags::JOB];
        bytes.extend_from_slice(&[tags::KEYWORD, 0, 0, 0, 1, b'x']);
        bytes.push(tags::END);
        assert!(matches!(
            decode(&bytes),
            Err(CodecError::ValueWithoutAttribute { .. })
        ));
    }

    #[test]
    fn truncated_header_rejected() {
        assert!(matches!(
            decode(&[2, 0, 0]),
            Err(CodecError::Truncated { .. })
        ));
    }

    #[test]
    fn fuzz_smoke_no_panics() {
        // Cheap determinism: feed byte permutations; must error, not panic.
        let mut state = 0x1234_5678u64;
        let mut rng = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..20_000 {
            let len = usize::try_from(rng() % 64).unwrap_or(0);
            let mut buf = Vec::with_capacity(len);
            for _ in 0..len {
                buf.push(u8::try_from(rng() % 256).unwrap_or(0));
            }
            let _ = decode(&buf);
        }
    }
}
