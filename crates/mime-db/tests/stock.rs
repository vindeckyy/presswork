use mime_db::MimeDb;
use std::path::PathBuf;

fn db() -> MimeDb {
    MimeDb::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")).unwrap()
}

#[test]
fn loads_stock_types() {
    let d = db();
    eprintln!("{d}");
    assert!(d.types.len() > 30, "types={}", d.types.len());
    assert!(d.get("application/pdf").is_some());
    assert!(d.get("image/jpeg").is_some());
    assert!(d.get("text/plain").is_some());
}

#[test]
fn detects_pdf() {
    let d = db();
    let t = d.detect("doc.pdf", b"%PDF-1.7 blah").unwrap();
    assert_eq!(t.name(), "application/pdf");
}

#[test]
fn detects_png_jpeg() {
    let d = db();
    assert_eq!(
        d.detect("a.png", b"\x89PNG\r\n\x1a\n").unwrap().name(),
        "image/png"
    );
    assert_eq!(
        d.detect("p.jpg", b"\xff\xd8\xff\xe0JFIF").unwrap().name(),
        "image/jpeg"
    );
}

#[test]
fn detects_text() {
    let d = db();
    assert_eq!(
        d.detect("f.txt", b"hello world\n").unwrap().name(),
        "text/plain"
    );
}

#[test]
fn conv_chain() {
    let d = db();
    let chain = d
        .filter_chain(
            "application/postscript",
            "application/vnd.cups-postscript",
            0,
        )
        .unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].program, "pstops");
}
