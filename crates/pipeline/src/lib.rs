//! Filter+backend pipeline — a port of `scheduler/job.c`'s `start_job` /
//! `cupsdStartProcess` machinery.
//!
//! For each job file, CUPS resolves a MIME filter chain (mime-db `filter_chain`)
//! from the document type to the printer's accept type, then forks:
//!   `[filter0] -> [filter1] -> ... -> [backend]`
//! Each stage gets the frozen contract:
//!   argv: `printer job-id user title copies options [filename]`
//!   env : `CONTENT_TYPE`, `FINAL_CONTENT_TYPE`, `DEVICE_URI`, `PRINTER`,
//!         `PPD`, `RIP_MAX_CACHE`, `CUPS_SERVERROOT`, ... plus `PassEnv`.
//! Stage `i`'s stdout is stage `i+1`'s stdin; the backend's stdout is a
//! side-channel logged to error_log, and its exit code controls job retry.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// One resolved pipeline stage.
#[derive(Debug)]
pub struct Stage {
    /// Filter program basename resolved under `filter_dir` (or absolute).
    pub program: PathBuf,
    /// `CONTENT_TYPE` for this stage's input.
    pub src_type: String,
    /// `FINAL_CONTENT_TYPE` target.
    pub dst_type: String,
}

/// A running pipeline — child handles in spawn order.
pub struct Pipeline {
    /// Filter stages (everything before the backend).
    pub filters: Vec<Child>,
    /// The backend child (writes to device-uri).
    pub backend: Child,
}

/// Spawn spec for a print job.
pub struct JobSpec {
    /// Queue name.
    pub printer: String,
    pub job_id: i32,
    pub username: String,
    pub title: String,
    pub copies: i32,
    /// `argv[5]` — the `name=value name2=value2 ...` option string.
    pub options: String,
    /// Spool data file fed to the first filter (`argv[6]`/stdin).
    pub data_file: PathBuf,
    /// `document-format` of the spool file.
    pub src_type: String,
    /// Printer's `document-format-supported` target (the backend's input).
    pub dst_type: String,
    /// `DEVICE_URI` — resolved printer device.
    pub device_uri: String,
    /// `CUPS_SERVERBIN/filter` dir.
    pub filter_dir: PathBuf,
    /// `CUPS_SERVERBIN/backend` dir.
    pub backend_dir: PathBuf,
    /// Backend program name derived from device-uri scheme (`ipp`, `socket`...).
    pub backend: String,
    /// Extra env merged into every stage (`PassEnv`/`SetEnv` results).
    pub env: HashMap<String, String>,
}

impl JobSpec {
    /// Build the standard environment for a stage (`cupsdStartProcess` envp).
    fn stage_env(&self, dst_type: &str) -> HashMap<String, String> {
        let mut e = HashMap::new();
        e.insert("CHARSET".into(), "utf-8".into());
        e.insert("CONTENT_TYPE".into(), self.src_type.clone());
        e.insert("DEVICE_URI".into(), self.device_uri.clone());
        e.insert("FINAL_CONTENT_TYPE".into(), dst_type.into());
        e.insert("LANG".into(), "en_US.UTF-8".into());
        e.insert(
            "PATH".into(),
            "/usr/local/sbin:/usr/local/bin:/usr/bin".into(),
        );
        e.insert("PRINTER".into(), self.printer.clone());
        e.insert("PRINTER_INFO".into(), self.printer.clone());
        e.insert("PRINTER_LOCATION".into(), String::new());
        e.insert("RIP_MAX_CACHE".into(), "128m".into());
        e.insert("USER".into(), self.username.clone());
        for (k, v) in &self.env {
            e.insert(k.clone(), v.clone());
        }
        e
    }

    fn argv(&self, with_file: bool) -> Vec<String> {
        // Backend argv is `[argv0, job-id, user, title, copies, options,
        // filename]` — `argv[0]` is the program name (set by `Command`),
        // so the job-id is the first element here. `backend_common`
        // expects the document path at `argv[6]`.
        let mut a = vec![
            self.job_id.to_string(),
            self.username.clone(),
            self.title.clone(),
            self.copies.to_string(),
            self.options.clone(),
        ];
        if with_file {
            a.push(self.data_file.to_string_lossy().into_owned());
        }
        a
    }

    /// Resolve the filter chain + spawn all stages (`start_job`).
    ///
    /// `chain` is the ordered conversion steps from `mime_db::MimeDb::
    /// filter_chain`. An empty chain feeds the data file straight to the
    /// backend. The backend's stdin is the last filter's stdout (or the data
    /// file). Returns the running pipeline.
    pub fn spawn(&self, chain: &[mime_db::Conv]) -> io::Result<Pipeline> {
        let data = std::fs::File::open(&self.data_file)?;
        let mut filters = Vec::new();
        // stdin for the next stage; starts as the spool file.
        let mut next_stdin: Stdio = data.into();
        let mut input_is_file = true;

        for conv in chain {
            let prog = resolve(&self.filter_dir, &conv.program);
            let mut cmd = Command::new(&prog);
            cmd.args(&self.argv(true))
                .env_clear()
                .envs(self.stage_env(&conv.dst))
                .stdin(next_stdin)
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit()); // filter log → our stderr for now
            let mut child = cmd
                .spawn()
                .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", prog.display())))?;
            next_stdin = child
                .stdout
                .take()
                .map(Into::into)
                .unwrap_or_else(Stdio::null);
            input_is_file = false;
            filters.push(child);
        }

        // Backend: reads last stage's output, writes to device-uri.
        let bprog = resolve(&self.backend_dir, &self.backend);
        let mut bc = Command::new(&bprog);
        bc.args(&self.argv(input_is_file))
            .env_clear()
            .envs(self.stage_env(&self.dst_type))
            .stdin(next_stdin)
            // Backend stdout is the backchannel — for now surface it.
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let backend = bc.spawn().map_err(|e| {
            io::Error::new(e.kind(), format!("{bprog}: {e}", bprog = bprog.display()))
        })?;

        Ok(Pipeline { filters, backend })
    }
}

/// `filter`/`beh`-style resolution: absolute path or `dir/program`.
fn resolve(dir: &Path, program: &str) -> PathBuf {
    if program.starts_with('/') {
        PathBuf::from(program)
    } else {
        dir.join(program)
    }
}

/// The backend name for a device URI: scheme part, with CUPS's historical
/// aliases (`http`→`ipp`, `lpd`→`lpd`, `socket`→`socket`, `usb`→`usb`).
pub fn backend_for_uri(device_uri: &str) -> String {
    let scheme = device_uri.split(':').next().unwrap_or("file");
    match scheme {
        "http" | "https" | "ipps" => "ipp".into(),
        "beh" | "smb" | "ncp" => scheme.into(),
        s => s.into(),
    }
}
