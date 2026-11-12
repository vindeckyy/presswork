//! cups-driverd — the PPD/driver database helper, the `scheduler/cups-driverd.cxx`
//! counterpart. `cupsd` runs it under `{ServerBin}/daemon/` and consumes its
//! output:
//!
//!   * `list <req-id> <limit> <options>` — emit one `ppd` record per line:
//!     `ppd "name" "make-and-model" "device-id" "product" "psversion" "scheme"`.
//!   * `cat <ppd-name>` — emit the PPD file bytes for `ppd-name`.
//!
//! Sources:
//!   * the built-in IPP Everywhere driverless model (`everywhere`)
//!   * `.drv` driver-database files under `DRVROOT`/`{datadir}/drv` — each
//!     `ModelName`/`PCFileName` block is a `drv:///<rel>.drv/<file>` entry
//!   * `.ppd` files under `PPDDIR`
//!
//! `cat` on a `drv://` name compiles a PPD from the model's `.drv` directives
//! (a focused subset of `ppdc`: `Manufacturer`, `MediaSize`/`HWMargins`,
//! `Resolution`, `ColorModel`, `Duplex`, `Filter`).

use std::path::{Path, PathBuf};

/// One driver/PPD database entry for `list` output.
struct Ppd {
    name: String,
    make_and_model: String,
    device_id: String,
    product: String,
    psversion: String,
    scheme: String, // "drv" or "ppd"
}

/// A parsed `.drv` model block.
#[derive(Default)]
struct DrvModel {
    model_name: String,
    pc_file_name: String,
    manufacturer: String,
    filters: Vec<String>, // "<mime> <cost> <cmd>"
    media_sizes: Vec<String>,
    resolutions: Vec<String>,
    color_models: Vec<String>,
    duplex: bool,
    version: String,
    drv_rel: String, // source .drv path relative to the drv root
}

fn everywhere_entry() -> Ppd {
    Ppd {
        name: "everywhere".into(),
        make_and_model: "IPP Everywhere".into(),
        device_id: "MFG:;MDL:IPP Everywhere;DES:IPP Everywhere;CMD:PWGRaster,AppleRaster,JPEG,PDF;"
            .into(),
        product: "(IPP Everywhere)".into(),
        psversion: "(3010.00) 0".into(),
        scheme: "drv".into(),
    }
}

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

/// The first quoted `"…"` or bare token after the directive keyword.
fn arg1(rest: &str) -> String {
    let rest = rest.trim();
    if let Some(inner) = rest.strip_prefix('"').and_then(|r| r.split('"').next()) {
        return inner.to_string();
    }
    rest.split_whitespace().next().unwrap_or("").to_string()
}

/// Parse a `.drv` file into its model blocks. Directives before the first
/// `ModelName` are shared context applied to every model in the file.
fn parse_drv(path: &Path, drv_root: &Path) -> Vec<DrvModel> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let rel = path
        .strip_prefix(drv_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let mut shared = DrvModel {
        drv_rel: rel.clone(),
        ..Default::default()
    };
    let mut models: Vec<DrvModel> = Vec::new();
    let mut cur: Option<DrvModel> = None;
    // Capability directives seen for the in-progress block (shared + per-model).
    let mut pending_media: Vec<String> = Vec::new();
    let mut pending_res: Vec<String> = Vec::new();
    let mut pending_color: Vec<String> = Vec::new();
    let mut pending_filters: Vec<String> = Vec::new();
    let mut pending_duplex = false;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        let (kw, rest) = line
            .split_once(|c: char| c.is_whitespace())
            .map_or((line, ""), |(k, r)| (k, r.trim()));
        match kw.trim_start_matches('*') {
            "Manufacturer" => shared.manufacturer = arg1(rest),
            "Version" => shared.version = arg1(rest),
            "ModelName" => {
                // Flush a previous block.
                if let Some(mut m) = cur.take() {
                    m.media_sizes.append(&mut pending_media);
                    m.resolutions.append(&mut pending_res);
                    m.color_models.append(&mut pending_color);
                    m.filters.append(&mut pending_filters);
                    m.duplex = pending_duplex;
                    models.push(m);
                }
                let mut m = shared.clone_shallow();
                m.model_name = arg1(rest);
                cur = Some(m);
                // Shared caps carry into the new model.
                pending_media.clone_from(&shared.media_sizes);
                pending_res.clone_from(&shared.resolutions);
                pending_color.clone_from(&shared.color_models);
                pending_filters.clone_from(&shared.filters);
                pending_duplex = shared.duplex;
            }
            "PCFileName" => {
                if let Some(m) = cur.as_mut() {
                    m.pc_file_name = arg1(rest);
                }
            }
            "MediaSize" => {
                let v = line.split_whitespace().nth(1).unwrap_or("").to_string();
                if cur.is_none() {
                    shared.media_sizes.push(v.clone());
                }
                pending_media.push(v);
            }
            "Resolution" => {
                if cur.is_none() {
                    shared.resolutions.push(line.to_string());
                }
                pending_res.push(line.to_string());
            }
            "ColorModel" => {
                if cur.is_none() {
                    shared.color_models.push(line.to_string());
                }
                pending_color.push(line.to_string());
            }
            "Filter" => {
                if cur.is_none() {
                    shared.filters.push(rest.to_string());
                }
                pending_filters.push(rest.to_string());
            }
            "Duplex" => {
                shared.duplex = true;
                pending_duplex = true;
            }
            _ => {}
        }
    }
    if let Some(mut m) = cur.take() {
        m.media_sizes.append(&mut pending_media);
        m.resolutions.append(&mut pending_res);
        m.color_models.append(&mut pending_color);
        m.filters.append(&mut pending_filters);
        m.duplex = pending_duplex;
        models.push(m);
    }
    models
}

impl DrvModel {
    fn clone_shallow(&self) -> DrvModel {
        DrvModel {
            manufacturer: self.manufacturer.clone(),
            version: self.version.clone(),
            drv_rel: self.drv_rel.clone(),
            ..Default::default()
        }
    }
}

/// Scan `dir` recursively for `.drv` files and emit a `drv://` `Ppd` per model.
fn scan_drv_dir(dir: &Path, out: &mut Vec<Ppd>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            scan_drv_dir(&p, out);
        } else if p.extension().is_some_and(|x| x == "drv") {
            for m in parse_drv(&p, dir) {
                if m.pc_file_name.is_empty() {
                    continue;
                }
                out.push(Ppd {
                    name: format!("drv:///{}/{}", m.drv_rel, m.pc_file_name),
                    make_and_model: m.model_name.clone(),
                    device_id: format!(
                        "MFG:{};MDL:{};DES:{};",
                        m.manufacturer, m.model_name, m.model_name
                    ),
                    product: format!("({})", m.model_name),
                    psversion: "(3010.00) 0".into(),
                    scheme: "drv".into(),
                });
            }
        }
    }
}

/// Scan `dir` recursively for `.ppd` files → `ppd`-scheme entries.
fn scan_ppd_dir(dir: &Path, out: &mut Vec<Ppd>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            scan_ppd_dir(&p, out);
        } else if p.extension().is_some_and(|x| x == "ppd") {
            let name = p
                .strip_prefix(dir)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
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

fn drv_roots() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::env::var("DRVROOT")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    // Also honor a `drv/` subdir next to the PPD dir.
    if let Ok(d) = std::env::var("PPDDIR").map(PathBuf::from) {
        v.push(d.join("drv"));
        v.push(d);
    }
    v
}

/// Compile a PPD from a `drv:///<rel>.drv/<file>` name's model directives.
fn drv_ppd(name: &str) -> Option<String> {
    let rest = name.strip_prefix("drv:///")?;
    let (rel_drv, pcfile) = rest.rsplit_once('/')?;
    for root in drv_roots() {
        let drv = root.join(rel_drv);
        if !drv.is_file() {
            continue;
        }
        for m in parse_drv(&drv, &root) {
            if m.pc_file_name == pcfile.replace('\\', "/") {
                return Some(compile_ppd(&m));
            }
        }
    }
    None
}

/// Emit a PPD for a parsed `.drv` model — the observable `ppdc` output shape:
/// header + PageSize/Resolution/ColorModel/Duplex options + cupsFilter chain.
fn compile_ppd(m: &DrvModel) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let mm = if m.model_name.is_empty() {
        "Unknown"
    } else {
        &m.model_name
    };
    s.push_str("*PPD-Adobe: \"4.3\"\n*FormatVersion: \"4.3\"\n*FileVersion: \"1.0\"\n");
    s.push_str("*LanguageVersion: English\n*LanguageEncoding: ISOLatin1\n");
    let _ = writeln!(s, "*PCFileName: \"{}\"", m.pc_file_name);
    let _ = writeln!(s, "*Manufacturer: \"{}\"", m.manufacturer);
    let _ = writeln!(
        s,
        "*Product: \"({mm})\"\n*ModelName: \"{mm}\"\n*NickName: \"{mm}\"\n*ShortNickName: \"{mm}\""
    );
    let _ = writeln!(
        s,
        "*DriverVersion: \"{}\"",
        if m.version.is_empty() {
            "1.0"
        } else {
            &m.version
        }
    );
    // Filter chain → cupsFilter lines.
    for f in &m.filters {
        let mut it = f.split_whitespace();
        if let (Some(mime), Some(cost), Some(cmd)) = (it.next(), it.next(), it.next()) {
            let _ = writeln!(s, "*cupsFilter: \"{mime} {cost} {cmd}\"");
        }
    }
    // MediaSize → PageSize options.
    if !m.media_sizes.is_empty() {
        s.push_str(
            "*OpenUI *PageSize/Media Size: PickOne\n*OrderDependency: 10 AnySetup *PageSize\n",
        );
        for (i, sz) in m.media_sizes.iter().enumerate() {
            if i == 0 {
                let _ = writeln!(s, "*DefaultPageSize: {sz}");
            }
            let _ = writeln!(
                s,
                "*PageSize {sz}/{sz}: \"<</PageSize[612 792]>>setpagedevice\""
            );
        }
        s.push_str("*CloseUI: *PageSize\n");
    }
    // Resolution options.
    if !m.resolutions.is_empty() {
        s.push_str(
            "*OpenUI *Resolution/Resolution: PickOne\n*OrderDependency: 20 AnySetup *Resolution\n",
        );
        for (i, r) in m.resolutions.iter().enumerate() {
            // `Resolution - 8 90 0 206 "720dpi/720 DPI"` → name from the quoted label.
            let label = r
                .split('"')
                .nth(1)
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("600dpi");
            if i == 0 {
                let _ = writeln!(s, "*DefaultResolution: {label}");
            }
            let _ = writeln!(
                s,
                "*Resolution {label}: \"<</HWResolution[600 600]>>setpagedevice\""
            );
        }
        s.push_str("*CloseUI: *Resolution\n");
    }
    // ColorModel → ColorModel options.
    if !m.color_models.is_empty() {
        s.push_str(
            "*OpenUI *ColorModel/Color Mode: PickOne\n*OrderDependency: 30 AnySetup *ColorModel\n",
        );
        for (i, c) in m.color_models.iter().enumerate() {
            let nm = c
                .split_whitespace()
                .nth(1)
                .unwrap_or("RGB")
                .split('/')
                .next()
                .unwrap_or("RGB");
            if i == 0 {
                let _ = writeln!(s, "*DefaultColorModel: {nm}");
            }
            let _ = writeln!(
                s,
                "*ColorModel {nm}: \"<</cupsColorSpace 0>>setpagedevice\""
            );
        }
        s.push_str("*CloseUI: *ColorModel\n");
    }
    if m.duplex {
        s.push_str("*OpenUI *Duplex/2-Sided Printing: PickOne\n*OrderDependency: 40 AnySetup *Duplex\n*DefaultDuplex: None\n");
        s.push_str("*Duplex None/Off: \"<</Duplex false>>setpagedevice\"\n*Duplex DuplexNoTumble/Long-Edge: \"<</Duplex true/Tumble false>>setpagedevice\"\n*CloseUI: *Duplex\n");
    }
    s
}

/// A synthesized driverless PPD for the `everywhere` model.
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

fn collect(drv_dirs: &[PathBuf], ppd_dirs: &[PathBuf]) -> Vec<Ppd> {
    let mut v = vec![everywhere_entry(), generic_entry()];
    for d in drv_dirs {
        scan_drv_dir(d, &mut v);
    }
    for d in ppd_dirs {
        scan_ppd_dir(d, &mut v);
    }
    v
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map_or("", String::as_str);
    match mode {
        "list" => {
            let limit: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
            let opts = args.get(4..).map(|o| o.join(" ")).unwrap_or_default();
            let drv_only = opts.contains("include-schemes=drv");
            let drv_dirs = drv_roots();
            let ppd_dirs: Vec<PathBuf> = std::env::var("PPDDIR")
                .map(PathBuf::from)
                .into_iter()
                .collect();
            let mut n = 0usize;
            for p in collect(&drv_dirs, &ppd_dirs) {
                if limit != 0 && n >= limit {
                    break;
                }
                if drv_only && p.scheme != "drv" {
                    continue;
                }
                println!(
                    "ppd \"{}\" \"{}\" \"{}\" \"{}\" \"{}\" \"{}\"",
                    p.name, p.make_and_model, p.device_id, p.product, p.psversion, p.scheme
                );
                n += 1;
            }
        }
        "cat" => {
            let name = args.get(2).map_or("", String::as_str);
            match name {
                "everywhere" => print!("{}", driverless_ppd()),
                _ if name.starts_with("drv://") => {
                    if let Some(p) = drv_ppd(name) {
                        print!("{p}");
                    } else {
                        eprintln!("ERROR: PPD \"{name}\" not found.");
                        std::process::exit(1);
                    }
                }
                _ => {
                    let ok = std::env::var("PPDDIR").map(PathBuf::from).is_ok_and(|d| {
                        let f = d.join(name);
                        f.is_file()
                            && std::fs::read(&f).is_ok_and(|b| {
                                use std::io::Write as _;
                                std::io::stdout().write_all(&b).is_ok()
                            })
                    });
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
