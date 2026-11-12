//! Print job model + spool persistence — a port of `scheduler/job.c`.
//!
//! Jobs live under `RequestRoot` (default `/var/spool/cups`):
//!   - `d%05d-%03d` — document data files (e.g. `d00012-001`)
//!   - `c%05d`      — IPP-serialized job-attribute control file
//! The control file stores the job's `ipp_t` attribute set (written by
//! `cupsdSaveJob`/`cupsdLoadAllJobs`), so a restart resumes queue state.

use ipp_codec::model::{Attribute, IppMessage, Text, Value};
use ipp_codec::tags;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// IPP `job-state` enum values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum JobState {
    Pending = 3,
    PendingHeld = 4,
    Processing = 5,
    ProcessingStopped = 6,
    Canceled = 7,
    Aborted = 8,
    Completed = 9,
}

impl JobState {
    pub fn from_i32(v: i32) -> Option<Self> {
        Some(match v {
            3 => Self::Pending,
            4 => Self::PendingHeld,
            5 => Self::Processing,
            6 => Self::ProcessingStopped,
            7 => Self::Canceled,
            8 => Self::Aborted,
            9 => Self::Completed,
            _ => return None,
        })
    }
    /// Whether the job is finished.
    pub fn is_final(self) -> bool {
        matches!(self, Self::Canceled | Self::Aborted | Self::Completed)
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::PendingHeld => "pending-held",
            Self::Processing => "processing",
            Self::ProcessingStopped => "processing-stopped",
            Self::Canceled => "canceled",
            Self::Aborted => "aborted",
            Self::Completed => "completed",
        }
    }
}

/// One document in a job (`job->files[i]` analogue).
#[derive(Debug, Clone)]
pub struct JobFile {
    /// File number (1-based; `d%05d-%03d`).
    pub num: u32,
    /// Detected/declared MIME type.
    pub filetype: String,
    /// Byte size on disk.
    pub size: u64,
    /// Filename the client supplied (`document-name`).
    pub name: String,
    /// `document-format` as submitted.
    pub format: String,
}

/// A queued print job (`cupsd_job_t` analogue).
#[derive(Debug)]
pub struct Job {
    pub id: i32,
    pub state: JobState,
    /// `job-state-reasons`.
    pub reasons: Vec<String>,
    pub priority: i32,
    /// Owning user.
    pub username: String,
    /// Target printer queue name.
    pub dest: String,
    /// Original IPP job-attributes (client-submitted + synthesized).
    pub attrs: Vec<Attribute>,
    pub files: Vec<JobFile>,
    pub created_at: i64,
    pub completed_at: Option<i64>,
    /// Running filter-pipeline backend pid, if any.
    pub backend_pid: Option<i32>,
    pub copies: i32,
    pub title: String,
    /// `document-format` of the primary file.
    pub format: String,
}

impl Job {
    pub fn new(id: i32, dest: impl Into<String>, username: impl Into<String>) -> Self {
        Self {
            id,
            state: JobState::Pending,
            reasons: vec!["job-incoming".into()],
            priority: 50,
            username: username.into(),
            dest: dest.into(),
            attrs: Vec::new(),
            files: Vec::new(),
            created_at: now(),
            completed_at: None,
            backend_pid: None,
            copies: 1,
            title: String::new(),
            format: "application/octet-stream".into(),
        }
    }

    /// Control-file path: `RequestRoot/c%05d`.
    pub fn control_path(root: &Path, id: i32) -> PathBuf {
        root.join(format!("c{id:05}"))
    }
    /// Data-file path: `RequestRoot/d%05d-%03d`.
    pub fn data_path(root: &Path, id: i32, num: u32) -> PathBuf {
        root.join(format!("d{id:05}-{num:03}"))
    }

    /// Serialize `job-attributes` to the control file (`cupsdSaveJob`).
    pub fn save(&self, root: &Path) -> io::Result<()> {
        let mut msg = IppMessage::new(ipp_codec::ops::op::PRINT_JOB);
        msg.request_id = self.id;
        let g = msg.group_mut(tags::JOB);
        g.attributes = self.attrs.clone();

        // Bookkeeping attrs live in the same set so a restart rebuilds the
        // job verbatim.
        upsert(&mut msg, "job-id", tags::ENUM, Value::Enum(self.id));
        upsert(
            &mut msg,
            "job-state",
            tags::ENUM,
            Value::Enum(self.state as i32),
        );
        upsert(
            &mut msg,
            "job-priority",
            tags::INTEGER,
            Value::Integer(self.priority),
        );
        upsert(
            &mut msg,
            "copies",
            tags::INTEGER,
            Value::Integer(self.copies),
        );
        upsert(
            &mut msg,
            "job-printer-uri",
            tags::URI,
            Value::Text(Text::from(format!(
                "ipp://localhost/printers/{}",
                self.dest
            ))),
        );
        upsert(
            &mut msg,
            "job-originating-user-name",
            tags::NAME,
            Value::Name(Text::from(self.username.as_str())),
        );
        upsert(
            &mut msg,
            "job-name",
            tags::NAME,
            Value::Name(Text::from(self.title.as_str())),
        );
        upsert(
            &mut msg,
            "document-format",
            tags::MIMETYPE,
            Value::Text(Text::from(self.format.as_str())),
        );
        upsert(
            &mut msg,
            "time-at-creation",
            tags::INTEGER,
            Value::Integer(self.created_at as i32),
        );
        if let Some(t) = self.completed_at {
            upsert(
                &mut msg,
                "time-at-completed",
                tags::INTEGER,
                Value::Integer(t as i32),
            );
        }
        upsert_n(
            &mut msg,
            "job-document-files",
            tags::MIMETYPE,
            self.files
                .iter()
                .map(|f| Value::Text(Text::from(f.filetype.as_str())))
                .collect(),
        );
        let bytes = ipp_codec::encode(&msg).map_err(|e| io::Error::other(e.to_string()))?;
        let tmp = Self::control_path(root, self.id).with_extension("tmp");
        fs::write(&tmp, bytes)?;
        fs::rename(&tmp, Self::control_path(root, self.id))
    }

    /// Load a job from its control file (`cupsdLoadAllJobs` per file).
    pub fn load(path: &Path) -> io::Result<Self> {
        let mut buf = Vec::new();
        File::open(path)?.read_to_end(&mut buf)?;
        let (msg, _) = ipp_codec::decode(&buf)
            .map_err(|e| io::Error::other(format!("bad control file: {e}")))?;
        let get_i = |name: &str| -> Option<i32> {
            find(&msg, name).and_then(|v| match v {
                Value::Integer(i) | Value::Enum(i) => Some(*i),
                _ => None,
            })
        };
        let get_t = |name: &str| -> Option<String> {
            find(&msg, name).and_then(|v| match v {
                Value::Text(t)
                | Value::Name(t)
                | Value::Keyword(t)
                | Value::Uri(t)
                | Value::UriScheme(t) => Some(t.to_string()),
                _ => None,
            })
        };
        let id = get_i("job-id").unwrap_or_else(|| {
            path.file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_prefix('c'))
                .and_then(|s| s.parse().ok())
                .unwrap_or(0)
        });
        let state =
            JobState::from_i32(get_i("job-state").unwrap_or(3)).unwrap_or(JobState::Pending);
        let dest_uri = get_t("job-printer-uri").unwrap_or_default();
        let dest = dest_uri.rsplit('/').next().unwrap_or("").to_string();
        let files = find_all(&msg, "job-document-files")
            .iter()
            .enumerate()
            .map(|(i, v)| JobFile {
                num: i as u32 + 1,
                filetype: match v {
                    Value::Text(t) => t.to_string(),
                    _ => "?".into(),
                },
                size: 0,
                name: String::new(),
                format: String::new(),
            })
            .collect();
        Ok(Self {
            id,
            state,
            reasons: vec![],
            priority: get_i("job-priority").unwrap_or(50),
            username: get_t("job-originating-user-name").unwrap_or_else(|| "anonymous".into()),
            dest,
            attrs: msg
                .groups
                .first()
                .map(|g| g.attributes.clone())
                .unwrap_or_default(),
            files,
            created_at: i64::from(get_i("time-at-creation").unwrap_or_else(|| now() as i32)),
            completed_at: get_i("time-at-completed").map(i64::from),
            backend_pid: None,
            copies: get_i("copies").unwrap_or(1),
            title: get_t("job-name").unwrap_or_default(),
            format: get_t("document-format").unwrap_or_else(|| "application/octet-stream".into()),
        })
    }
}

/// In-memory job table keyed by id (`cupsd_jobs` analogue).
#[derive(Debug, Default)]
pub struct Jobs {
    pub by_id: BTreeMap<i32, Job>,
    next_id: i32,
}

impl Jobs {
    /// Scan `RequestRoot` for `cNNNNN` files and rebuild the table.
    pub fn load_all(root: &Path) -> Self {
        let mut j = Jobs::default();
        let Ok(rd) = fs::read_dir(root) else { return j };
        let mut max = 0;
        for e in rd.flatten() {
            let p = e.path();
            let n = e.file_name();
            let n = n.to_str().unwrap_or("");
            if n.len() == 6 && n.starts_with('c') && n[1..].chars().all(|c| c.is_ascii_digit()) {
                if let Ok(job) = Job::load(&p) {
                    max = max.max(job.id);
                    j.by_id.insert(job.id, job);
                }
            }
        }
        j.next_id = max + 1;
        j
    }

    /// Allocate the next job-id (`cupsdNextJobId`).
    pub fn alloc_id(&mut self) -> i32 {
        let id = self.next_id.max(1);
        self.next_id = id + 1;
        id
    }

    /// Insert and persist a job.
    pub fn add(&mut self, root: &Path, job: Job) -> io::Result<i32> {
        let id = job.id;
        job.save(root)?;
        self.by_id.insert(id, job);
        Ok(id)
    }

    /// Persist an existing job's current state.
    pub fn save(&self, root: &Path, id: i32) -> io::Result<()> {
        if let Some(j) = self.by_id.get(&id) {
            j.save(root)
        } else {
            Ok(())
        }
    }

    /// Remove a job + its spool files (`cupsdDeleteJob`).
    pub fn remove(&mut self, root: &Path, id: i32) -> io::Result<()> {
        if let Some(j) = self.by_id.remove(&id) {
            for f in &j.files {
                let _ = fs::remove_file(Job::data_path(root, id, f.num));
            }
            let _ = fs::remove_file(Job::control_path(root, id));
        }
        Ok(())
    }

    pub fn get(&self, id: i32) -> Option<&Job> {
        self.by_id.get(&id)
    }
    pub fn get_mut(&mut self, id: i32) -> Option<&mut Job> {
        self.by_id.get_mut(&id)
    }

    /// Jobs targeting a printer.
    pub fn for_printer<'a>(&'a self, dest: &'a str) -> impl Iterator<Item = &'a Job> + 'a {
        self.by_id.values().filter(move |j| j.dest == dest)
    }
    /// Active (non-final) jobs in submission order.
    pub fn active(&self) -> impl Iterator<Item = &Job> {
        self.by_id.values().filter(|j| !j.state.is_final())
    }
}

// ---------- attribute helpers ----------

fn find<'a>(msg: &'a IppMessage, name: &str) -> Option<&'a Value> {
    msg.groups
        .iter()
        .flat_map(|g| &g.attributes)
        .find(|a| a.name == name)
        .and_then(|a| a.values.first())
}

fn find_all<'a>(msg: &'a IppMessage, name: &str) -> Vec<&'a Value> {
    msg.groups
        .iter()
        .flat_map(|g| &g.attributes)
        .find(|a| a.name == name)
        .map(|a| a.values.iter().collect())
        .unwrap_or_default()
}

fn upsert(msg: &mut IppMessage, name: &str, tag: u8, v: Value) {
    let g = msg.group_mut(tags::JOB);
    if let Some(a) = g.attributes.iter_mut().find(|a| a.name == name) {
        a.values = vec![v];
    } else {
        g.attributes.push(Attribute::new(name, tag, vec![v]));
    }
}

fn upsert_n(msg: &mut IppMessage, name: &str, tag: u8, vs: Vec<Value>) {
    let g = msg.group_mut(tags::JOB);
    if let Some(a) = g.attributes.iter_mut().find(|a| a.name == name) {
        a.values = vs;
    } else {
        g.attributes.push(Attribute::new(name, tag, vs));
    }
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
