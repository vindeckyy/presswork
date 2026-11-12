//! cups-driverd — the PPD/driver database helper, the `scheduler/cups-driverd.cxx`
//! counterpart. `cupsd` runs it under `{ServerBin}/daemon/` and consumes its
//! output:
//!
//!   * `list <req-id> <limit> <options>` — emit one `ppd` record per line:
//!     `ppd-name "make-and-model" "device-id" "product" "psversion" "type"`.
//!   * `cat <ppd-name>` — emit the PPD file bytes for `ppd-name`.
//!
//! Driverless-first: the built-in `everywhere` IPP Everywhere model plus any
//! `.ppd` files found under `PPDDIR`/`{datadir}/ppd`. The `drv` scheme maps to
//! the driver-database entries (IPP Everywhere + a generic model) — this is the
//! P7 surface that `CUPS-Get-PPDs`/`CUPS-Get-PPD` exercise.

use std::path::{Path, PathBuf};

/// One driver/PPD database entry.
struct Ppd {
    name: String,
    make_and_model: String,
    device_id: String,
    product: String,
    psversion: String,
    scheme: String, // "drv" or "ppd"
}

fn everywhere_entry() -> Ppd {
    Ppd {
        name: "everywhere".into(),
        make_and_model: "IPP Everywhere".into(),
        device_id: "MFG:;MDL:IPP Everywhere;DES:IPP Everywhere;CMD:PWGRaster,AppleRaster,JPEG,PDF;".into(),
        product: "(IPP Everywhere)".into(),
        psversion: "(3010.00) 0".into(),
        scheme: "drv".into(),
    }
}

/// The generic driverless model — a catch-all for `ppd`/`drv` listings.
fn generic_entry() -> Ppd {
    Ppd {
        name: "lsb/usr/cupsfilters/Generic-IPP-Everywhere-Printer.ppd".into(),
        make_and_model: "Generic IPP Everywhere Printer".into(),
        device_id: "MFG:Generic;MDL:IPP Everywhere Printer;DES:Generic IPP Everywhere Printer;CMD:PWGRaster,AppleRaster,JPEG,PDF;".into(),
        product: "(Generic IPP Everywhere Printer)".into(),
        psversion: "(3010.00) 0".into(),
        scheme: "drv".into(),
    }
}

/// Scan `dir` (recursively, shallow) for `.ppd` files → `ppd`-scheme entries.
fn scan_ppd_dir(dir: &Path, out: &mut Vec<Ppd>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            scan_ppd_dir(&p, out);
        } else if p.extension().is_some_and(|x| x == "ppd") {
            let name = p.strip_prefix(dir).unwrap_or(&p).to_string_lossy().replace('\\', "/");
            out.push(Ppd {
                name: name.clone(),
                make_and_model: name.clone(),
                device_id: String::new(),
                product: format!("({name})"),
                psversion: "(3010.00) 0".into(),
                scheme: "ppd".into(),
            });
        }
    }
}

fn collect(ppd_dirs: &[PathBuf]) -> Vec<Ppd> {
    let mut v = vec![everywhere_entry(), generic_entry()];
    for d in ppd_dirs {
        scan_ppd_dir(d, &mut v);
    }
    v
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    match mode {
        "list" => {
            // list <req-id> <limit> <options...>
            let limit: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
            let opts = args.get(4..).map(|o| o.join(" ")).unwrap_or_default();
            let want_drv = opts.is_empty() || opts.contains("include-schemes=drv") || !opts.contains("include-schemes");
            let ppd_dirs: Vec<PathBuf> = std::env::var("PPDDIR")
                .map(PathBuf::from)
                .into_iter()
                .collect();
            let mut n = 0usize;
            for p in collect(&ppd_dirs) {
                if limit != 0 && n >= limit {
                    break;
                }
                if !want_drv && p.scheme == "drv" {
                    continue;
                }
                if p.scheme == "ppd" && opts.contains("include-schemes=drv") {
                    continue;
                }
                // `ppd <name> "<m&m>" "<devid>" "<product>" "<psver>" "<scheme>"`
                println!(
                    "ppd \"{}\" \"{}\" \"{}\" \"{}\" \"{}\" \"{}\"",
                    p.name, p.make_and_model, p.device_id, p.product, p.psversion, p.scheme
                );
                n += 1;
            }
        }
        "cat" => {
            let name = args.get(2).map(String::as_str).unwrap_or("");
            match name {
                "everywhere" | "drv:///sample.drv/genericippeverywhere.ppd" => {
                    print!("{}", driverless_ppd());
                }
                _ => {
                    // Try a literal PPD path under the configured dirs.
                    let mut ok = false;
                    for d in std::env::var("PPDDIR").map(PathBuf::from).into_iter() {
                        let f = d.join(name);
                        if f.is_file() {
                            if let Ok(b) = std::fs::read(&f) {
                                use std::io::Write as _;
                                let _ = std::io::stdout().write_all(&b);
                                ok = true;
                            }
                            break;
                        }
                    }
                    if !ok {
                        eprintln!("ERROR: PPD \"{name}\" not found.");
                        std::process::exit(1);
                    }
                }
            }
        }
        _ => {
            eprintln!("Usage: cups-driverd cat ppd-name");
            eprintln!("Usage: cups-driverd list request_id limit options");
            std::process::exit(1);
        }
    }
}

/// A synthesized driverless PPD for the `everywhere` model — the minimal
/// PPD cupsd would generate from a printer's IPP Everywhere attributes.
fn driverless_ppd() -> &'static str {
    "*PPD-Adobe: \"4.3\"\n\
     *FormatVersion: \"4.3\"\n\
     *FileVersion: \"1.0\"\n\
     *LanguageVersion: English\n\
     *LanguageEncoding: ISOLatin1\n\
     *PCFileName: \"ippeve.ppd\"\n\
     *Manufacturer: \"Generic\"\n\
     *Product: \"(IPP Everywhere)\"\n\
     *ModelName: \"IPP Everywhere\"\n\
     *NickName: \"IPP Everywhere\"\n\
     *ShortNickName: \"IPP Everywhere\"\n\
     *DefaultColorSpace: Gray\n\
     *ColorDevice: True\n\
     *cupsFilter2: \"application/vnd.cups-pdf application/pdf 0 -\"\n\
     *cupsFilter2: \"image/jpeg image/jpeg 0 -\"\n\
     *cupsFilter2: \"image/pwg-raster image/pwg-raster 0 -\"\n\
     *cupsFilter2: \"image/urf image/urf 0 -\"\n\
     *OpenUI *PageSize/Media Size: PickOne\n\
     *OrderDependency: 10 AnySetup *PageSize\n\
     *DefaultPageSize: Letter\n\
     *PageSize Letter/US Letter: \"<</PageSize[612 792]>>setpagedevice\"\n\
     *PageSize Legal/US Legal: \"<</PageSize[612 1008]>>setpagedevice\"\n\
     *PageSize A4/A4: \"<</PageSize[595 842]>>setpagedevice\"\n\
     *CloseUI: *PageSize\n\
     *OpenUI *Duplex/2-Sided Printing: PickOne\n\
     *OrderDependency: 20 AnySetup *Duplex\n\
     *DefaultDuplex: None\n\
     *Duplex None/Off: \"<</Duplex false>>setpagedevice\"\n\
     *Duplex DuplexNoTumble/Long-Edge (Portrait): \"<</Duplex true/Tumble false>>setpagedevice\"\n\
     *Duplex DuplexTumble/Short-Edge (Landscape): \"<</Duplex true/Tumble true>>setpagedevice\"\n\
     *CloseUI: *Duplex\n"
}
