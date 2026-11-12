//! MIME type database for the filter pipeline — a port of CUPS `mime/*.c`.
//!
//! `mime.types` maps `super/type` names to file-recognition rules
//! (`mime_readfile.c`/`mime_type_t`); `mime.convs` maps source→destination
//! type pairs to a cost + filter program (`mime_filter_t`). `filter_chain`
//! resolves a minimum-cost path through the conversion graph, mirroring
//! `mimeFilter2` semantics.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// A single primitive test in a rule (`mime_type_check_t` analogue).
#[derive(Debug, Clone)]
pub enum Rule {
    /// `string(offset, "lit")` — bytes identical to literal.
    Str { offset: i64, lit: Vec<u8> },
    /// `istring(...)` — case-insensitive `string`.
    IStr { offset: i64, lit: Vec<u8> },
    /// `char(offset, v)` — single byte equal.
    Char { offset: i64, v: u8 },
    /// `short(offset, v)` — big-endian 16-bit equal.
    Short { offset: i64, v: u16 },
    /// `int(offset, v)` — big-endian 32-bit equal.
    Int { offset: i64, v: u32 },
    /// `ascii(off,len)` — bytes are CR/NL/TAB/BS or 32..=126.
    Ascii { offset: i64, len: usize },
    /// `printable(off,len)` — ascii plus 128..=254.
    Printable { offset: i64, len: usize },
    /// `contains(off,range,"lit")` — literal found within range.
    Contains {
        offset: i64,
        range: usize,
        lit: Vec<u8>,
    },
    /// `regex(off,"pat")` — line starts with regex (subset: `^`-anchored).
    Regex { offset: i64, pat: String },
    /// `match("pat")` / bare `ext` — filename match (`*.ext`, substring).
    Match { pat: String },
    /// `locale("s")` — match the system locale (checked once at eval).
    Locale { s: String },
    /// `priority(n)` — not a test; sets `Type::priority`.
    Priority { n: i32 },
    /// `( expr )` — sub-expression.
    Group { expr: Expr },
}

/// How a rule joins the running (left-associative) result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Join {
    /// `,`/whitespace — `result || eval(rule)`.
    Or,
    /// `+` — `result && eval(rule)`.
    And,
}

/// A parenthesized sub-expression evaluated as one operand.
#[derive(Debug, Clone)]
pub struct Group(pub Vec<(Join, Rule)>);

/// A full recognition expression: operands + joiners, evaluated
/// left-to-right (`a b + c` = `(a || b) && c`, matching mime_checkrules).
pub type Expr = Vec<(Join, Rule)>;

/// One recognized MIME type (`mime_type_t`).
#[derive(Debug)]
pub struct Type {
    /// `super` component (e.g. `application`).
    pub sup: String,
    /// `type` component (e.g. `pdf`).
    pub typ: String,
    /// The parsed rule expression (appended on repeated defs).
    pub expr: Expr,
    /// `priority(n)` — higher wins ties (default 100).
    pub priority: i32,
}

impl Type {
    /// `application/pdf`-style display name.
    pub fn name(&self) -> String {
        format!("{}/{}", self.sup, self.typ)
    }
}

/// One `mime.convs` line (`mime_filter_t`).
#[derive(Debug, Clone)]
pub struct Conv {
    /// Source type (`super/type`).
    pub src: String,
    /// Destination type.
    pub dst: String,
    /// Relative cost (lower preferred).
    pub cost: u32,
    /// Filter program (basename under `CUPS_SERVERBIN/filter`), or `-`.
    pub program: String,
}

/// The loaded database.
#[derive(Debug, Default)]
pub struct MimeDb {
    /// Types, sorted by (priority desc, name asc) at load.
    pub types: Vec<Type>,
    /// Conversion table.
    pub convs: Vec<Conv>,
}

impl MimeDb {
    /// Load all `*.types` + `*.convs` under `dir` (`mimeLoad`).
    pub fn load(dir: &Path) -> std::io::Result<Self> {
        let mut db = MimeDb::default();
        for f in sorted_ext(dir, "types")? {
            db.load_types(&f)?;
        }
        for f in sorted_ext(dir, "convs")? {
            db.load_convs(&f)?;
        }
        db.types
            .sort_by(|a, b| b.priority.cmp(&a.priority).then(a.name().cmp(&b.name())));
        Ok(db)
    }

    /// Parse one `mime.types`-format file.
    pub fn load_types(&mut self, path: &Path) -> std::io::Result<()> {
        for line in logical_lines(BufReader::new(File::open(path)?)) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.splitn(2, char::is_whitespace);
            let Some(tname) = it.next() else { continue };
            let Some((sup, typ)) = tname.split_once('/') else {
                continue;
            };
            let rest = it.next().unwrap_or("").trim();
            let (expr, prio) = parse_rules(rest);
            // Merge into existing type (upstream: repeated defs append).
            match self
                .types
                .iter_mut()
                .find(|t| t.sup.eq_ignore_ascii_case(sup) && t.typ.eq_ignore_ascii_case(typ))
            {
                Some(t) => {
                    if !t.expr.is_empty() && !expr.is_empty() {
                        // append with Or joiner
                        let mut e = expr;
                        e[0].0 = Join::Or;
                        t.expr.extend(e);
                    } else {
                        t.expr = expr;
                    }
                }
                None => self.types.push(Type {
                    sup: sup.to_lowercase(),
                    typ: typ.to_lowercase(),
                    expr,
                    priority: prio,
                }),
            }
        }
        Ok(())
    }

    /// Parse one `mime.convs`-format file.
    pub fn load_convs(&mut self, path: &Path) -> std::io::Result<()> {
        for line in logical_lines(BufReader::new(File::open(path)?)) {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut it = line.split_whitespace();
            let (Some(src), Some(dst), Some(cost), Some(program)) =
                (it.next(), it.next(), it.next(), it.next())
            else {
                continue;
            };
            let Ok(cost) = cost.parse::<u32>() else {
                continue;
            };
            self.convs.push(Conv {
                src: src.to_lowercase(),
                dst: dst.to_lowercase(),
                cost,
                program: program.to_string(),
            });
        }
        Ok(())
    }

    /// Detect a file's MIME type from its name + first `head` bytes
    /// (`mimeFileType`). Returns `None` for unrecognized.
    pub fn detect(&self, filename: &str, head: &[u8]) -> Option<&Type> {
        self.types
            .iter()
            .find(|t| !t.expr.is_empty() && eval_expr(&t.expr, filename, head))
    }

    /// Look up a type by `super/type` name.
    pub fn get(&self, name: &str) -> Option<&Type> {
        let (s, t) = name.split_once('/')?;
        self.types
            .iter()
            .find(|x| x.sup.eq_ignore_ascii_case(s) && x.typ.eq_ignore_ascii_case(t))
    }

    /// Minimum-cost filter chain src→dst (`mimeFilter2` — Dijkstra over the
    /// conv graph). Returns the ordered conv steps; empty = direct.
    pub fn filter_chain(&self, src: &str, dst: &str, max_cost: u32) -> Option<Vec<&Conv>> {
        use std::cmp::Reverse;
        use std::collections::BinaryHeap;
        let src = src.to_lowercase();
        let dst = dst.to_lowercase();
        if src == dst {
            return Some(vec![]);
        }
        // dist[type] = (cost, path)
        let mut dist: HashMap<String, (u32, Vec<&Conv>)> = HashMap::new();
        let mut heap = BinaryHeap::new();
        dist.insert(src.clone(), (0, vec![]));
        heap.push(Reverse((0u32, src.clone())));
        while let Some(Reverse((cost, cur))) = heap.pop() {
            if cur == dst {
                return Some(dist[&dst].1.clone());
            }
            if dist.get(&cur).is_some_and(|(d, _)| cost > *d) {
                continue;
            }
            for c in self
                .convs
                .iter()
                .filter(|c| c.src == cur && c.program != "-")
            {
                let ncost = cost + c.cost;
                if ncost > max_cost && max_cost != 0 {
                    continue;
                }
                let better = dist.get(&c.dst).is_none_or(|(d, _)| ncost < *d);
                if better {
                    let mut path = dist[&cur].1.clone();
                    path.push(c);
                    dist.insert(c.dst.clone(), (ncost, path));
                    heap.push(Reverse((ncost, c.dst.clone())));
                }
            }
        }
        None
    }

    /// Does `dst` accept `src` directly or via convs (for `file_ready` checks)?
    pub fn can_convert(&self, src: &str, dst: &str) -> bool {
        src.eq_ignore_ascii_case(dst)
            || self.filter_chain(src, dst, 0).is_some_and(|_| true)
            || self.convs.iter().any(|c| c.src == src && c.dst == dst)
    }
}

fn sorted_ext(dir: &Path, ext: &str) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut v: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == ext))
        .collect();
    v.sort();
    Ok(v)
}

/// Join `\`-continuation lines, strip comments.
fn logical_lines<R: BufRead>(r: R) -> impl Iterator<Item = String> {
    let mut buf = String::new();
    let mut out = Vec::new();
    for line in r.lines().map_while(Result::ok) {
        let line = line.trim_end();
        if let Some(stripped) = line.strip_suffix('\\') {
            buf.push_str(stripped);
            buf.push(' ');
        } else {
            buf.push_str(line);
            out.push(std::mem::take(&mut buf));
        }
    }
    if !buf.is_empty() {
        out.push(buf);
    }
    out.into_iter()
}

// ---------- rule parsing ----------

fn parse_rules(s: &str) -> (Expr, i32) {
    // Recursive-descent fold: expr := operand (join operand)* where the
    // joiner is `+` (And) or `,`/whitespace (Or). Whitespace around `+` is
    // part of the And join — matching mime_checkrules' left-associative
    // evaluation (`a b + c` = `(a || b) && c`).
    let b = s.as_bytes();
    let mut i = 0usize;
    let mut expr: Expr = Vec::new();
    let mut pending_and = false;
    let mut priority = 100;

    fn skip_ws(b: &[u8], i: &mut usize) {
        while *i < b.len() && (b[*i] as char).is_whitespace() {
            *i += 1;
        }
    }

    skip_ws(b, &mut i);
    while i < b.len() {
        // Parse one operand.
        let r: Rule;
        if b[i] == b'(' {
            let mut depth = 1;
            let mut j = i + 1;
            let mut inq = false;
            while j < b.len() && depth > 0 {
                match b[j] as char {
                    '"' => inq = !inq,
                    '(' if !inq => depth += 1,
                    ')' if !inq => depth -= 1,
                    _ => {}
                }
                j += 1;
            }
            let (inner, _) = parse_rules(&s[i + 1..j.saturating_sub(1)]);
            r = Rule::Group { expr: inner };
            i = j;
        } else {
            let mut j = i;
            let mut depth = 0;
            let mut inq = false;
            while j < b.len() {
                let ch = b[j] as char;
                match ch {
                    '"' => inq = !inq,
                    '(' if !inq => depth += 1,
                    ')' if !inq => {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                    }
                    '+' | ' ' | '\t' | ',' if depth == 0 && !inq => break,
                    _ => {}
                }
                j += 1;
            }
            match parse_rule(&s[i..j]) {
                Some(parsed) => r = parsed,
                None => {
                    i = j.max(i + 1);
                    skip_ws(b, &mut i);
                    continue;
                }
            }
            i = j;
        }

        if let Rule::Priority { n } = r {
            priority = n;
            skip_ws(b, &mut i);
            pending_and = false;
            if i < b.len() && b[i] == b'+' {
                i += 1;
            } else if i < b.len() && b[i] == b',' {
                i += 1;
            }
            skip_ws(b, &mut i);
            continue;
        }
        let join = if pending_and { Join::And } else { Join::Or };
        expr.push((join, r));

        // Consume the joiner: whitespace, then optional `+` (And) or `,` (Or).
        skip_ws(b, &mut i);
        pending_and = false;
        if i < b.len() && b[i] == b'+' {
            pending_and = true;
            i += 1;
        } else if i < b.len() && b[i] == b',' {
            i += 1;
        }
        skip_ws(b, &mut i);
    }
    (expr, priority)
}

fn parse_rule(t: &str) -> Option<Rule> {
    // `fn(a, b, "c")` or bare extension/match.
    if let Some(open) = t.find('(') {
        let name = &t[..open];
        let args = t[open + 1..].trim_end_matches(')');
        let mut a = args.splitn(2, ',');
        let arg1 = a.next().unwrap_or("").trim();
        let arg2 = a.next().unwrap_or("").trim();
        match name {
            "string" => {
                return Some(Rule::Str {
                    offset: num(arg1),
                    lit: lit(arg2),
                })
            }
            "istring" => {
                return Some(Rule::IStr {
                    offset: num(arg1),
                    lit: lit(arg2),
                })
            }
            "char" => {
                return Some(Rule::Char {
                    offset: num(arg1),
                    v: num(arg2) as u8,
                })
            }
            "short" => {
                return Some(Rule::Short {
                    offset: num(arg1),
                    v: num(arg2) as u16,
                })
            }
            "int" => {
                return Some(Rule::Int {
                    offset: num(arg1),
                    v: num(arg2) as u32,
                })
            }
            "ascii" => {
                return Some(Rule::Ascii {
                    offset: num(arg1),
                    len: num(arg2) as usize,
                })
            }
            "printable" => {
                return Some(Rule::Printable {
                    offset: num(arg1),
                    len: num(arg2) as usize,
                })
            }
            "contains" => {
                let mut a2 = arg2.splitn(2, ',');
                return Some(Rule::Contains {
                    offset: num(arg1),
                    range: num(a2.next().unwrap_or("0")) as usize,
                    lit: lit(a2.next().unwrap_or("")),
                });
            }
            "regex" => {
                return Some(Rule::Regex {
                    offset: num(arg1),
                    pat: unquote(arg2).into_owned(),
                })
            }
            "match" => {
                return Some(Rule::Match {
                    pat: unquote(arg1).into_owned(),
                })
            }
            "locale" => {
                return Some(Rule::Locale {
                    s: unquote(arg1).into_owned(),
                })
            }
            "priority" => {
                return Some(Rule::Priority {
                    n: num(arg1) as i32,
                })
            }
            "true" => return Some(Rule::Char { offset: 0, v: 0 }), // never true; handled below
            _ => return None,
        }
    }
    // Bare token = filename extension match (`*.tok` semantics).
    if t.eq_ignore_ascii_case("true") {
        Some(Rule::Match { pat: String::new() })
    } else {
        Some(Rule::Match {
            pat: format!("*.{t}"),
        })
    }
}

fn num(s: &str) -> i64 {
    let s = s.trim().trim_matches('"');
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(h, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

fn lit(s: &str) -> Vec<u8> {
    let s = s.trim();
    let unq = unquote(s);
    // `<hex>` escapes inside the literal.
    let b = unq.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'<' {
            if let Some(end) = b[i..].iter().position(|&c| c == b'>') {
                let hex = &unq[i + 1..i + end];
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += end + 1;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn unquote(s: &str) -> std::borrow::Cow<'_, str> {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        s[1..s.len() - 1].into()
    } else {
        s.into()
    }
}

// ---------- rule evaluation ----------

fn eval_expr(expr: &Expr, filename: &str, head: &[u8]) -> bool {
    // Left-associative fold, mirroring mime_checkrules.
    let mut result = false;
    for (idx, (join, r)) in expr.iter().enumerate() {
        let v = eval_rule(r, filename, head);
        result = if idx == 0 {
            v
        } else {
            match join {
                Join::And => result && v,
                Join::Or => result || v,
            }
        };
    }
    result
}

fn eval_rule(r: &Rule, filename: &str, head: &[u8]) -> bool {
    match r {
        Rule::Str { offset, lit } => get(head, *offset, lit.len()) == lit.as_slice(),
        Rule::IStr { offset, lit } => get(head, *offset, lit.len())
            .iter()
            .zip(lit)
            .all(|(a, b)| a.eq_ignore_ascii_case(b)),
        Rule::Char { offset, v } => get(head, *offset, 1).first() == Some(v),
        Rule::Short { offset, v } => {
            u16::from_be_bytes(get(head, *offset, 2).try_into().unwrap_or([0; 2])) == *v
        }
        Rule::Int { offset, v } => {
            u32::from_be_bytes(get(head, *offset, 4).try_into().unwrap_or([0; 4])) == *v
        }
        Rule::Ascii { offset, len } => get(head, *offset, *len)
            .iter()
            .all(|c| matches!(c, b'\r' | b'\n' | b'\t' | 8 | 32..=126)),
        Rule::Printable { offset, len } => get(head, *offset, *len)
            .iter()
            .all(|c| matches!(c, b'\r' | b'\n' | b'\t' | 8 | 32..=126 | 128..=254)),
        Rule::Contains { offset, range, lit } => {
            let win = get(head, *offset, *range + lit.len());
            win.windows(lit.len()).any(|w| w == lit.as_slice())
        }
        Rule::Regex { offset, pat } => {
            // Upstream uses REG_EXTENDED on the first line. We support a
            // useful subset: `^`-anchored literal/escaped patterns.
            let text = String::from_utf8_lossy(get(head, *offset, head.len()));
            let line = text.lines().next().unwrap_or("");
            regex_match(pat, line)
        }
        Rule::Match { pat } => {
            if pat.is_empty() {
                return true;
            }
            let pat = pat.to_lowercase();
            let name = std::path::Path::new(filename)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(filename)
                .to_lowercase();
            if let Some(suf) = pat.strip_prefix('*') {
                name.ends_with(suf)
            } else {
                name.contains(&pat)
            }
        }
        Rule::Locale { s } => std::env::var("LANG")
            .unwrap_or_else(|_| "C".into())
            .to_lowercase()
            .contains(&s.to_lowercase()),
        Rule::Priority { .. } => true,
        Rule::Group { expr } => eval_expr(expr, filename, head),
    }
}

fn get(head: &[u8], offset: i64, len: usize) -> &[u8] {
    if offset < 0 {
        let o = head.len().saturating_sub((-offset) as usize);
        return head.get(o..o + len).unwrap_or(&[]);
    }
    head.get(offset as usize..(offset as usize).saturating_add(len))
        .unwrap_or(&[])
}

/// Minimal ERE subset for `regex()` — `^` anchor + literal/`[]`/`.`/`()`/`*`
/// matched against the start of line. Good enough for stock mime.types
/// (e.g. `^[\n\r]*%PDF`).
fn regex_match(pat: &str, line: &str) -> bool {
    let pat = pat.strip_prefix('^').unwrap_or(pat);
    let chars: Vec<char> = line.chars().collect();
    let mut ci = 0;
    let pc: Vec<char> = pat.chars().collect();
    let mut i = 0;
    while i < pc.len() {
        match pc[i] {
            '[' => {
                // char class with optional leading `*` after it
                let mut j = i + 1;
                let mut cls = Vec::new();
                let neg = pc.get(j) == Some(&'^');
                if neg {
                    j += 1;
                }
                while j < pc.len() && pc[j] != ']' {
                    cls.push(pc[j]);
                    j += 1;
                }
                let star = pc.get(j + 1) == Some(&'*');
                // consume matching chars
                while ci < chars.len() {
                    let m = cls_match(&cls, neg, chars[ci]);
                    if !m {
                        break;
                    }
                    ci += 1;
                    if !star {
                        break;
                    }
                }
                i = j + 1 + usize::from(star);
            }
            '(' => {
                // group: treat transparently — match contents literally
                let mut j = i;
                while j < pc.len() && pc[j] != ')' {
                    j += 1;
                }
                i = j + 1;
            }
            c => {
                if ci >= chars.len() || chars[ci] != c {
                    return false;
                }
                ci += 1;
                i += 1;
            }
        }
    }
    true
}

fn cls_match(cls: &[char], neg: bool, c: char) -> bool {
    let mut found = false;
    let mut i = 0;
    while i < cls.len() {
        if i + 2 < cls.len() && cls[i + 1] == '-' {
            if c >= cls[i] && c <= cls[i + 2] {
                found = true;
            }
            i += 3;
        } else {
            // escaped char like \n inside the class
            if cls[i] == '\\' && i + 1 < cls.len() {
                let e = match cls[i + 1] {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    x => x,
                };
                if c == e {
                    found = true;
                }
                i += 2;
                continue;
            }
            if c == cls[i] {
                found = true;
            }
            i += 1;
        }
    }
    if neg {
        !found
    } else {
        found
    }
}

impl std::fmt::Display for MimeDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        write!(s, "{} types, {} convs", self.types.len(), self.convs.len())?;
        f.write_str(&s)
    }
}
