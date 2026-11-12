//! `file` backend — writes the job to `file:///path` (`backend/file.c`-
//! equivalent; upstream handles this virtually but a real program keeps the
//! contract uniform for third-party queues).
use backend_common as bc;

fn main() {
    bc::run(
        || bc::code::OK, // file has no discoverable devices
        |inv| {
            let uri = &inv.device_uri;
            let Some(path) = uri.strip_prefix("file://") else {
                bc::error(format_args!("Bad device URI: {uri}"));
                return bc::code::FAILED;
            };
            let path = if path.is_empty() { "/dev/null" } else { path };
            let mut out = match std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
            {
                Ok(f) => f,
                Err(e) => {
                    bc::error(format_args!("Cannot open {path}: {e}"));
                    return bc::code::FAILED;
                }
            };
            let mut doc = match bc::document(&inv) {
                Ok(d) => d,
                Err(e) => {
                    bc::error(format_args!("Cannot open document: {e}"));
                    return bc::code::FAILED;
                }
            };
            match std::io::copy(&mut doc, &mut out) {
                Ok(n) => {
                    bc::info(format_args!("Wrote {n} bytes to {path}"));
                    bc::code::OK
                }
                Err(e) => {
                    bc::error(format_args!("Write to {path} failed: {e}"));
                    bc::code::FAILED
                }
            }
        },
    );
}
