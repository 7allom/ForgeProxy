//! Comparer: captured items and the two comparisons.
//!
//! Words: a two-phase diff. Phase one aligns the items line by line (Patience over the lines).
//! A line only item A has is a deletion, a line only item B has is an addition, and two lines
//! are a modification only when they are the same field with a changed value: the same header
//! name, two start lines, or body text that is mostly the same (see `pair_score`). Phase two
//! diffs the words of each such pair, so a token only one side has keeps its own kind instead
//! of being collapsed with whatever the other side put nearby.
//!
//! The result is two streams of rows of the same length: where one item has a line the other
//! has not, the other gets a filler row, so the two sides stay level all the way down and a
//! matching line is on the same horizontal plane in both panes.
//!
//! Bytes: the two buffers are compared offset by offset (shown as 16-byte hex dump rows); a
//! byte differs when the other item has a different byte, or none, at that offset.

#[derive(Clone, Debug, PartialEq)]
pub struct ComparerItem {
    pub id: usize,
    /// e.g. "Proxy history #3 (Response)", "Repeater request" or "Selection (142 bytes)".
    pub label: String,
    pub data: Vec<u8>,
    pub length: usize,
    pub is_text: bool,
}

impl ComparerItem {
    pub fn from_bytes(id: usize, label: impl Into<String>, data: &[u8]) -> Self {
        // text: valid UTF-8 without control characters other than tab/CR/LF
        let is_text = std::str::from_utf8(data).is_ok_and(|s| s.chars().all(|c| !c.is_control() || matches!(c, '\t' | '\r' | '\n')));
        ComparerItem { id, label: label.into(), data: data.to_vec(), length: data.len(), is_text }
    }

    pub fn from_text(id: usize, label: impl Into<String>, text: &str) -> Self {
        Self::from_bytes(id, label, text.as_bytes())
    }

    #[cfg(test)]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DiffMode {
    Words,
    Bytes,
}

/// How a span or byte compares with the other item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Same,
    /// Only in item B.
    Inserted,
    /// Only in item A.
    Deleted,
    /// Replaced: different content at this point in each item.
    Modified,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Span {
    pub change: Change,
    /// The difference this span belongs to, indexing [`WordDiff::hunks`]; `None` for unchanged
    /// text. The one the view is on is drawn differently from the rest.
    pub hunk: Option<usize>,
    pub text: String,
}

/// One row of the side-by-side view: the spans of one line, or nothing at all where this side
/// has no line and the other does, which the viewer draws as blank to keep the two level.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Row {
    /// The line this row shows, numbered (0-based) within its own item; `None` for a filler.
    pub line: Option<usize>,
    pub spans: Vec<Span>,
}

impl Row {
    /// Is this the blank that stands in for a line the other side has and this one does not?
    pub fn is_filler(&self) -> bool {
        self.line.is_none()
    }
}

/// What a span shows on its row: its text without the line terminator, which would otherwise
/// start a second row and put the two sides out of step. The terminator stays in `Span::text`
/// so the item can still be reproduced byte for byte, and so a changed one is still reported.
pub fn shown(span: &Span) -> &str {
    span.text.trim_end_matches(['\r', '\n'])
}

/// A side's spans end to end with the filler rows left out: the item's own text. Runs of the
/// same kind join across rows, as they do within one.
#[cfg_attr(not(test), allow(dead_code))]
pub fn spans(rows: &[Row]) -> Vec<Span> {
    let mut out = Vec::new();
    for row in rows.iter().filter(|r| !r.is_filler()) {
        for s in &row.spans {
            append(&mut out, s.change, s.hunk, &s.text);
        }
    }
    out
}

/// One difference, in document order: what it is, the row of the side-by-side view it starts
/// on — the same row in both panes, which is where "next/previous difference" scrolls to — and
/// the line (0-based) it starts on within each item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hunk {
    /// Never `Change::Same`.
    pub kind: Change,
    pub row: usize,
    pub line_a: usize,
    pub line_b: usize,
}

/// Word comparison: the two sides as rows of spans, the same number on each side, and the
/// differences between them in order.
#[derive(Clone, Debug, PartialEq)]
pub struct WordDiff {
    pub a: Vec<Row>,
    pub b: Vec<Row>,
    pub hunks: Vec<Hunk>,
}

/// Byte comparison: per-offset changes for each side, rows of 16, the number of differing
/// offsets, and the rows that contain a difference.
#[derive(Clone, Debug, PartialEq)]
pub struct ByteDiff {
    pub a: Vec<Change>,
    pub b: Vec<Change>,
    pub differing: usize,
    pub diff_rows: Vec<usize>,
}

/// Safety ceiling for word-level comparison (256 KB per item); beyond it, fall back to byte diff.
pub const MAX_WORD_DIFF_SIZE: usize = 256 * 1024;
/// Fallback message displayed when an item exceeds [`MAX_WORD_DIFF_SIZE`].
pub const WORD_DIFF_LIMIT_NOTE: &str = "Item exceeds 256 KB — byte diff active.";

// ---- tokens ---------------------------------------------------------------------------

/// Tokens whose concatenation is exactly `s`.
pub fn tokenize(s: &str) -> Vec<&str> {
    #[derive(PartialEq, Clone, Copy)]
    enum K { Word, Space, Punct }
    let kind = |c: char| if c.is_alphanumeric() || c == '_' { K::Word } else if c.is_whitespace() { K::Space } else { K::Punct };
    let mut out = Vec::new();
    let mut start = 0;
    let mut prev: Option<K> = None;
    for (i, c) in s.char_indices() {
        let k = kind(c);
        // words and whitespace form runs; every punctuation character is its own token
        let boundary = match prev { None => false, Some(p) => p != k || k == K::Punct };
        if boundary {
            out.push(&s[start..i]);
            start = i;
        }
        prev = Some(k);
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

// ---- word comparison (phase one: lines) --------------------------------------------------

/// How much two lines must share to count as one field whose value changed. Below it they have
/// too little in common to be read as a modification: they are a deletion and an addition that
/// happen to sit next to each other.
const PAIR_THRESHOLD: f32 = 0.5;

/// Region sizes beyond which looking at every pair of lines costs more than it is worth; past
/// it, lines are paired where they sit, which is all a positional diff could have done anyway.
const MAX_PAIR_SEARCH: usize = 4096;

/// The lines of `s`, each keeping its terminator, so their concatenation is exactly `s`.
fn split_lines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, _) in s.match_indices('\n') {
        out.push(&s[start..=i]);
        start = i + 1;
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// What a line says, without its terminator (which may be CRLF, LF or nothing at all).
fn content(line: &str) -> &str {
    let s = line.strip_suffix('\n').unwrap_or(line);
    s.strip_suffix('\r').unwrap_or(s)
}

/// What a line is, syntactically. Two lines are a modification of one another only when they
/// are the same kind — and, for a header, the same field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineKind<'a> {
    /// A request line ("GET /a HTTP/1.1") or a status line ("HTTP/1.1 200 OK").
    Start,
    /// "Name: value": the name is the field, the rest is its value.
    Header(&'a str),
    Empty,
    /// A body line, or any text that is none of the above.
    Other,
}

/// The field name of "Name: value", if the line is a header. The name has to be an HTTP token
/// (RFC 9110 §5.6.2) with nothing before the colon, so a body line such as `{"id":42}` or
/// `  "id": 42` is not taken for one.
fn header_name(s: &str) -> Option<&str> {
    let name = &s[..s.find(':')?];
    let token = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c);
    (!name.is_empty() && name.chars().all(token)).then_some(name)
}

/// Does the line read as the first line of a request or of a response?
fn is_start_line(s: &str) -> bool {
    if s.starts_with("HTTP/") {
        return true;
    }
    match (s.split(' ').next(), s.split(' ').nth(1), s.split(' ').nth(2), s.split(' ').nth(3)) {
        (Some(method), Some(_target), Some(version), None) => {
            !method.is_empty() && method.chars().all(|c| c.is_ascii_uppercase()) && version.starts_with("HTTP/")
        }
        _ => false,
    }
}

fn line_kind(line: &str) -> LineKind<'_> {
    let s = content(line);
    if s.is_empty() {
        LineKind::Empty
    } else if is_start_line(s) {
        LineKind::Start
    } else if let Some(name) = header_name(s) {
        LineKind::Header(name)
    } else {
        LineKind::Other
    }
}

/// What two lines have in common: twice the words they share over the words they have
/// (Sørensen-Dice over the word bags). 1.0 is the same words in any order, 0.0 nothing in
/// common. Whitespace and punctuation are left out, so `alpha beta` and `alpha gamma!` are
/// half the same rather than two fifths — punctuation is what a word diff sorts out, once the
/// two lines are known to belong together. Deliberately cheap: it only decides whether to pay
/// for that word diff.
fn similarity(a: &str, b: &str) -> f32 {
    fn words(s: &str) -> Vec<&str> {
        tokenize(s).into_iter().filter(|t| t.chars().any(char::is_alphanumeric)).collect()
    }
    let mut bag: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let wa = words(a);
    for t in &wa {
        *bag.entry(*t).or_default() += 1;
    }
    let wb = words(b);
    let mut shared = 0usize;
    for t in &wb {
        if let Some(n) = bag.get_mut(*t).filter(|n| **n > 0) {
            *n -= 1;
            shared += 1;
        }
    }
    // two lines with no words at all (`{` against `}`) have nothing to tell them apart
    if wa.len() + wb.len() == 0 {
        return 1.0;
    }
    2.0 * shared as f32 / (wa.len() + wb.len()) as f32
}

/// `Some(score)` when the two lines could be one field whose value changed, so they are worth
/// diffing word by word; `None` when they are unrelated and each stands on its own.
fn pair_score(a: &str, b: &str) -> Option<f32> {
    match (line_kind(a), line_kind(b)) {
        // the same field, whatever its value became. Two *different* fields fall through to
        // `None`: `User-Agent: Mozilla/5.0` becoming `Content-Length: 48` is one line gone
        // and another arrived, not one line edited.
        (LineKind::Header(x), LineKind::Header(y)) => x.eq_ignore_ascii_case(y).then_some(1.0),
        // a start line against a start line: method, target and version are the same fields
        (LineKind::Start, LineKind::Start) | (LineKind::Empty, LineKind::Empty) => Some(1.0),
        // body and plain text have no fields to match up, so go by how much is shared
        (LineKind::Other, LineKind::Other) => {
            let s = similarity(content(a), content(b));
            (s >= PAIR_THRESHOLD).then_some(s)
        }
        // a header is neither a start line nor a body line: nothing pairs across kinds
        _ => None,
    }
}

/// Match up the lines of a replaced region. `out[i] = Some(j)` reads A's `i`-th line and B's
/// `j`-th (both numbered within the region) as one field whose value changed; `None` leaves
/// the line as a whole-line deletion. Pairs are taken best first and never cross each other,
/// so both sides stay in order.
fn pair_lines(old: &[&str], new: &[&str]) -> Vec<Option<usize>> {
    if old.len().saturating_mul(new.len()) > MAX_PAIR_SEARCH {
        return (0..old.len())
            .map(|i| match new.get(i) {
                Some(b) if pair_score(old[i], b).is_some() => Some(i),
                _ => None,
            })
            .collect();
    }
    let mut best: Vec<(f32, usize, usize)> = Vec::new();
    for (i, a) in old.iter().enumerate() {
        for (j, b) in new.iter().enumerate() {
            if let Some(score) = pair_score(a, b) {
                best.push((score, i, j));
            }
        }
    }
    // the closest match first; between equally good ones (two identical header names, say) the
    // pair that moves the line the least, then the earliest
    best.sort_by(|x, y| {
        y.0.total_cmp(&x.0)
            .then_with(|| x.1.abs_diff(x.2).cmp(&y.1.abs_diff(y.2)))
            .then_with(|| (x.1, x.2).cmp(&(y.1, y.2)))
    });
    let mut paired: Vec<Option<usize>> = vec![None; old.len()];
    let mut used = vec![false; new.len()];
    for (_, i, j) in best {
        // a pair that crossed one already made would show the two sides out of order
        let crossing = paired.iter().enumerate().any(|(k, p)| match *p {
            Some(l) => (k < i) != (l < j),
            None => false,
        });
        if paired[i].is_none() && !used[j] && !crossing {
            paired[i] = Some(j);
            used[j] = true;
        }
    }
    paired
}

// ---- word comparison (phase two: words within a pair) ------------------------------------

/// Builds the two row streams and the list of differences as the phases walk the two items.
/// Every method leaves the two sides with the same number of rows, which is what keeps a line
/// and the line it was compared against on the same horizontal plane in the two panes.
struct Build {
    a: Vec<Row>,
    b: Vec<Row>,
    hunks: Vec<Hunk>,
    line_a: usize,
    line_b: usize,
}

/// The characters that structure data and addresses. Each is a token of its own, so a value
/// is compared against the next value rather than against the punctuation stuck to it: without
/// this, `101,` and `102,` are one token each and `true}` against `true, "debug": 1}` reads as
/// a change to the whole tail instead of an addition after `true`.
const DELIMITERS: [char; 17] =
    ['{', '}', '[', ']', '(', ')', ':', ';', ',', '"', '\'', '/', '?', '&', '=', '<', '>'];

/// Split a line into the tokens the word comparison comparison works on: a run of whitespace,
/// a run of anything else, or a single delimiter. Concatenating the tokens gives the line back
/// exactly, which is what lets the panes be rebuilt from them.
fn word_tokens(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    // whether the run being gathered is whitespace; None when no run is open
    let mut gathering: Option<bool> = None;
    for (i, c) in line.char_indices() {
        if DELIMITERS.contains(&c) {
            if start < i {
                out.push(&line[start..i]);
            }
            out.push(&line[i..i + c.len_utf8()]);
            start = i + c.len_utf8();
            gathering = None;
            continue;
        }
        let whitespace = c.is_whitespace();
        match gathering {
            // the run changed kind: close it here and start the next
            Some(was) if was != whitespace => {
                out.push(&line[start..i]);
                start = i;
            }
            Some(_) => {}
            None => start = i,
        }
        gathering = Some(whitespace);
    }
    if start < line.len() {
        out.push(&line[start..]);
    }
    out
}

/// Append `text` to `spans`, extending the last span when it is part of the same difference.
fn append(spans: &mut Vec<Span>, change: Change, hunk: Option<usize>, text: &str) {
    match spans.last_mut() {
        Some(last) if last.change == change && last.hunk == hunk => last.text.push_str(text),
        _ => spans.push(Span { change, hunk, text: text.to_string() }),
    }
}

impl Build {
    fn new() -> Self {
        Build { a: Vec::new(), b: Vec::new(), hunks: Vec::new(), line_a: 0, line_b: 0 }
    }

    /// Start a difference where both sides now stand, and return its index.
    fn open(&mut self, kind: Change) -> usize {
        debug_assert_eq!(self.a.len(), self.b.len(), "the two sides are level between rows");
        self.hunks.push(Hunk { kind, row: self.a.len(), line_a: self.line_a, line_b: self.line_b });
        self.hunks.len() - 1
    }

    /// One row on each side: a line of A against the line of B it was compared with.
    fn pair(&mut self, sa: Vec<Span>, sb: Vec<Span>) {
        self.a.push(Row { line: Some(self.line_a), spans: sa });
        self.b.push(Row { line: Some(self.line_b), spans: sb });
        self.line_a += 1;
        self.line_b += 1;
    }

    /// Lines both items have, unchanged.
    fn same(&mut self, old: &[&str], new: &[&str]) {
        for (ta, tb) in old.iter().zip(new) {
            let span = |t: &str| vec![Span { change: Change::Same, hunk: None, text: t.to_string() }];
            self.pair(span(ta), span(tb));
        }
    }

    /// A run of lines only item A has: one difference, however many lines it covers. B gets a
    /// filler row against each of them, so what comes after stays level.
    fn deleted(&mut self, lines: &[&str]) {
        if lines.is_empty() {
            return;
        }
        let h = self.open(Change::Deleted);
        for t in lines {
            let spans = vec![Span { change: Change::Deleted, hunk: Some(h), text: (*t).to_string() }];
            self.a.push(Row { line: Some(self.line_a), spans });
            self.b.push(Row::default());
            self.line_a += 1;
        }
    }

    /// A run of lines only item B has, against filler rows in A.
    fn inserted(&mut self, lines: &[&str]) {
        if lines.is_empty() {
            return;
        }
        let h = self.open(Change::Inserted);
        for t in lines {
            let spans = vec![Span { change: Change::Inserted, hunk: Some(h), text: (*t).to_string() }];
            self.b.push(Row { line: Some(self.line_b), spans });
            self.a.push(Row::default());
            self.line_b += 1;
        }
    }

    /// Phase two: one line against the line phase one paired it with, token by token. Each run
    /// of changed tokens is its own difference and keeps its own kind, so a token only A has
    /// stays a deletion even though the line around it was modified.
    fn modified(&mut self, ta: &str, tb: &str) {
        let (old, new) = (word_tokens(ta), word_tokens(tb));
        // one row each, however many token runs changed inside it
        let (mut sa, mut sb) = (Vec::new(), Vec::new());
        for op in similar::capture_diff_slices(similar::Algorithm::Patience, &old, &new) {
            match op {
                similar::DiffOp::Equal { old_index, new_index, len } => {
                    for k in 0..len {
                        append(&mut sa, Change::Same, None, old[old_index + k]);
                        append(&mut sb, Change::Same, None, new[new_index + k]);
                    }
                }
                similar::DiffOp::Delete { old_index, old_len, .. } => {
                    let h = self.open(Change::Deleted);
                    for &t in &old[old_index..old_index + old_len] {
                        append(&mut sa, Change::Deleted, Some(h), t);
                    }
                }
                similar::DiffOp::Insert { new_index, new_len, .. } => {
                    let h = self.open(Change::Inserted);
                    for &t in &new[new_index..new_index + new_len] {
                        append(&mut sb, Change::Inserted, Some(h), t);
                    }
                }
                similar::DiffOp::Replace { old_index, old_len, new_index, new_len } => {
                    let h = self.open(Change::Modified);
                    for &t in &old[old_index..old_index + old_len] {
                        append(&mut sa, Change::Modified, Some(h), t);
                    }
                    for &t in &new[new_index..new_index + new_len] {
                        append(&mut sb, Change::Modified, Some(h), t);
                    }
                }
            }
        }
        self.pair(sa, sb);
    }

    /// A region the line diff replaced wholesale: diff the lines that belong together, and
    /// keep the rest apart as the deletions and additions they are.
    fn replaced(&mut self, old: &[&str], new: &[&str]) {
        let paired = pair_lines(old, new);
        // the first A line of the run that has no counterpart, and how far B has been emitted
        let (mut orphans, mut j) = (0usize, 0usize);
        for (i, p) in paired.iter().enumerate() {
            let Some(k) = *p else { continue };
            self.deleted(&old[orphans..i]);
            orphans = i + 1;
            self.inserted(&new[j..k]);
            j = k + 1;
            self.modified(old[i], new[k]);
        }
        self.deleted(&old[orphans..]);
        self.inserted(&new[j..]);
    }
}

/// Compare two items word by word: Patience over the lines first, then over the words of each
/// line pair phase one read as the same field with a changed value.
/// Returns `Err(WORD_DIFF_LIMIT_NOTE)` when either input exceeds [`MAX_WORD_DIFF_SIZE`] (256 KB).
pub fn compute_patience_word_diff(a: &str, b: &str) -> Result<WordDiff, String> {
    if a.len() > MAX_WORD_DIFF_SIZE || b.len() > MAX_WORD_DIFF_SIZE {
        return Err(WORD_DIFF_LIMIT_NOTE.into());
    }
    let (la, lb) = (split_lines(a), split_lines(b));
    let mut out = Build::new();
    for op in similar::capture_diff_slices(similar::Algorithm::Patience, &la, &lb) {
        match op {
            similar::DiffOp::Equal { old_index, new_index, len } => {
                out.same(&la[old_index..old_index + len], &lb[new_index..new_index + len]);
            }
            similar::DiffOp::Delete { old_index, old_len, .. } => out.deleted(&la[old_index..old_index + old_len]),
            similar::DiffOp::Insert { new_index, new_len, .. } => out.inserted(&lb[new_index..new_index + new_len]),
            similar::DiffOp::Replace { old_index, old_len, new_index, new_len } => {
                out.replaced(&la[old_index..old_index + old_len], &lb[new_index..new_index + new_len]);
            }
        }
    }
    Ok(WordDiff { a: out.a, b: out.b, hunks: out.hunks })
}

/// None when either item exceeds `MAX_WORD_DIFF_SIZE` (256 KB).
#[cfg_attr(not(test), allow(dead_code))]
pub fn diff_words(a: &str, b: &str) -> Option<WordDiff> {
    compute_patience_word_diff(a, b).ok()
}

// ---- byte comparison ---------------------------------------------------------------------

pub const BYTES_PER_ROW: usize = 16;

/// Buffers up to this size (1 MiB each) are aligned with a sequence diff, so a byte inserted
/// in the middle shifts what follows instead of making every byte after it look changed.
/// Beyond it the comparison falls back to offset against offset, which is linear and keeps
/// the window responsive on payloads a sequence diff would labour over.
pub const MAX_BYTE_ALIGN_SIZE: usize = 1024 * 1024;

/// How long the aligned comparison may take before it settles for what it has. A sequence
/// diff over two buffers with little in common can cost far more than their length, and a
/// comparison window that stops drawing is worse than a coarser answer.
const BYTE_ALIGN_BUDGET: std::time::Duration = std::time::Duration::from_millis(250);

pub fn diff_bytes(a: &[u8], b: &[u8]) -> ByteDiff {
    if a.len() > MAX_BYTE_ALIGN_SIZE || b.len() > MAX_BYTE_ALIGN_SIZE {
        return diff_bytes_by_offset(a, b);
    }
    let mut out = ByteDiff { a: Vec::with_capacity(a.len()), b: Vec::with_capacity(b.len()), differing: 0, diff_rows: Vec::new() };
    let deadline = std::time::Instant::now() + BYTE_ALIGN_BUDGET;
    let ops = similar::capture_diff_slices_deadline(similar::Algorithm::Myers, a, b, Some(deadline));
    let mut rows: Vec<usize> = Vec::new();
    // a difference is noted at the row it falls on in each item, since one may sit further
    // down its own dump than the other once bytes have been added or taken away
    let note = |out: &ByteDiff, rows: &mut Vec<usize>| {
        for row in [out.a.len().saturating_sub(1) / BYTES_PER_ROW, out.b.len().saturating_sub(1) / BYTES_PER_ROW] {
            if rows.last() != Some(&row) {
                rows.push(row);
            }
        }
    };
    for op in ops {
        match op {
            similar::DiffOp::Equal { len, .. } => {
                out.a.extend(std::iter::repeat_n(Change::Same, len));
                out.b.extend(std::iter::repeat_n(Change::Same, len));
            }
            similar::DiffOp::Delete { old_len, .. } => {
                out.a.extend(std::iter::repeat_n(Change::Deleted, old_len));
                out.differing += old_len;
                note(&out, &mut rows);
            }
            similar::DiffOp::Insert { new_len, .. } => {
                out.b.extend(std::iter::repeat_n(Change::Inserted, new_len));
                out.differing += new_len;
                note(&out, &mut rows);
            }
            similar::DiffOp::Replace { old_len, new_len, .. } => {
                out.a.extend(std::iter::repeat_n(Change::Modified, old_len));
                out.b.extend(std::iter::repeat_n(Change::Modified, new_len));
                out.differing += old_len.max(new_len);
                note(&out, &mut rows);
            }
        }
    }
    rows.sort_unstable();
    rows.dedup();
    out.diff_rows = rows;
    out
}

/// The comparison for buffers too large to align: byte at offset *i* against byte at offset
/// *i*, which cannot follow an insertion but costs one pass.
fn diff_bytes_by_offset(a: &[u8], b: &[u8]) -> ByteDiff {
    let n = a.len().max(b.len());
    let mut out = ByteDiff { a: Vec::with_capacity(a.len()), b: Vec::with_capacity(b.len()), differing: 0, diff_rows: Vec::new() };
    for i in 0..n {
        let (ca, cb) = match (a.get(i), b.get(i)) {
            (Some(x), Some(y)) if x == y => (Some(Change::Same), Some(Change::Same)),
            (Some(_), Some(_)) => (Some(Change::Modified), Some(Change::Modified)),
            (Some(_), None) => (Some(Change::Deleted), None),
            (None, Some(_)) => (None, Some(Change::Inserted)),
            (None, None) => (None, None),
        };
        if ca != Some(Change::Same) {
            out.differing += 1;
            let row = i / BYTES_PER_ROW;
            if out.diff_rows.last() != Some(&row) {
                out.diff_rows.push(row);
            }
        }
        if let Some(c) = ca { out.a.push(c); }
        if let Some(c) = cb { out.b.push(c); }
    }
    out
}

// ---- app state ---------------------------------------------------------------------------

type WordResult = Result<WordDiff, String>;

/// A word comparison running on a worker thread; the result lands in the slot when done.
#[derive(Clone, Debug)]
pub struct WordJob(std::sync::Arc<std::sync::OnceLock<WordResult>>);

impl PartialEq for WordJob {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl WordJob {
    /// Diff `a` and `b` word by word off the UI thread using Patience Diff.
    fn start(a: Vec<u8>, b: Vec<u8>) -> Self {
        let slot = std::sync::Arc::new(std::sync::OnceLock::new());
        let out = slot.clone();
        std::thread::spawn(move || {
            let res = if a.len() > MAX_WORD_DIFF_SIZE || b.len() > MAX_WORD_DIFF_SIZE {
                Err(WORD_DIFF_LIMIT_NOTE.to_string())
            } else {
                let (a, b) = (String::from_utf8_lossy(&a), String::from_utf8_lossy(&b));
                compute_patience_word_diff(&a, &b)
            };
            let _ = out.set(res);
        });
        WordJob(slot)
    }
}

/// An open comparison: the two items, the mode shown, and each mode's result (computed the
/// first time that mode is shown; words in the background, see `poll`).
#[derive(Clone, Debug, PartialEq)]
pub struct DiffView {
    pub mode: DiffMode,
    pub a: ComparerItem,
    pub b: ComparerItem,
    /// Err: too large for a word comparison.
    pub words: Option<WordResult>,
    /// The word comparison still running, if any.
    pub words_job: Option<WordJob>,
    pub bytes: Option<ByteDiff>,
    /// The difference the view is on: the one "next/previous" last moved to, drawn
    /// differently from the rest. Indexes `jump_targets`.
    pub active_diff_index: Option<usize>,
    /// Note shown when word diff falls back to byte diff because an item exceeds 256 KB.
    pub fallback_note: Option<String>,
}

impl DiffView {
    pub fn new(a: ComparerItem, b: ComparerItem, mode: DiffMode) -> Self {
        let mut v = DiffView {
            mode,
            a,
            b,
            words: None,
            words_job: None,
            bytes: None,
            active_diff_index: None,
            fallback_note: None,
        };
        v.set_mode(mode);
        v
    }

    pub fn set_mode(&mut self, mode: DiffMode) {
        self.mode = mode;
        self.active_diff_index = None;
        match mode {
            DiffMode::Words => {
                if self.a.data.len() > MAX_WORD_DIFF_SIZE || self.b.data.len() > MAX_WORD_DIFF_SIZE {
                    let note = WORD_DIFF_LIMIT_NOTE.to_string();
                    self.words = Some(Err(note.clone()));
                    self.fallback_note = Some(note);
                    self.mode = DiffMode::Bytes;
                    if self.bytes.is_none() {
                        self.bytes = Some(diff_bytes(&self.a.data, &self.b.data));
                    }
                } else if let Some(Err(note)) = &self.words {
                    self.fallback_note = Some(note.clone());
                    self.mode = DiffMode::Bytes;
                    if self.bytes.is_none() {
                        self.bytes = Some(diff_bytes(&self.a.data, &self.b.data));
                    }
                } else if self.words.is_none() && self.words_job.is_none() {
                    self.words_job = Some(WordJob::start(self.a.data.clone(), self.b.data.clone()));
                    self.poll();
                }
            }
            DiffMode::Bytes if self.bytes.is_none() => {
                self.bytes = Some(diff_bytes(&self.a.data, &self.b.data));
            }
            _ => {}
        }
    }

    /// Take the background word comparison's result if it's done. True while it's running.
    pub fn poll(&mut self) -> bool {
        let Some(job) = &self.words_job else { return false };
        match job.0.get() {
            Some(res) => {
                let res_cloned = res.clone();
                self.words_job = None;
                if let Err(note) = &res_cloned {
                    self.fallback_note = Some(note.clone());
                    self.mode = DiffMode::Bytes;
                    if self.bytes.is_none() {
                        self.bytes = Some(diff_bytes(&self.a.data, &self.b.data));
                    }
                }
                self.words = Some(res_cloned);
                false
            }
            None => true,
        }
    }

    /// Differences in the current mode (changed regions for words, offsets for bytes).
    pub fn difference_count(&self) -> usize {
        match self.mode {
            DiffMode::Words => self.word_diff().map_or(0, |w| w.hunks.len()),
            DiffMode::Bytes => self.bytes.as_ref().map_or(0, |b| b.differing),
        }
    }

    /// The word comparison, once it has landed and if it ran at all.
    pub fn word_diff(&self) -> Option<&WordDiff> {
        self.words.as_ref().and_then(|w| w.as_ref().ok())
    }

    /// Rows "next/previous difference" can jump to. Both panes show the same row of a word
    /// comparison, because the two sides are padded to the same length; for bytes they are
    /// 16-byte rows, which line up for the same reason.
    pub fn jump_targets(&self) -> Vec<usize> {
        match self.mode {
            DiffMode::Words => self.word_diff().map_or(Vec::new(), |w| w.hunks.iter().map(|h| h.row).collect()),
            DiffMode::Bytes => self.bytes.as_ref().map_or(Vec::new(), |b| b.diff_rows.clone()),
        }
    }
}

/// Add a byte buffer as an item (see `push`).
pub fn add(app: &mut crate::state::App, label: impl Into<String>, data: &[u8]) {
    push(app, |id| ComparerItem::from_bytes(id, label, data));
}

/// Add text as an item (see `push`).
pub fn add_text(app: &mut crate::state::App, label: impl Into<String>, text: &str) {
    push(app, |id| ComparerItem::from_text(id, label, text));
}

/// Add an item and select the two newest ones, ready to compare.
fn push(app: &mut crate::state::App, make: impl FnOnce(usize) -> ComparerItem) {
    app.comparer_next_id += 1;
    app.comparer_items.push(make(app.comparer_next_id));
    let n = app.comparer_items.len();
    app.comparer_sel_b = Some(n - 1);
    app.comparer_sel_a = Some(n.saturating_sub(2));
}

/// Remove item `i`, keeping the selections pointing at the same items.
pub fn remove(app: &mut crate::state::App, i: usize) {
    if i >= app.comparer_items.len() {
        return;
    }
    app.comparer_items.remove(i);
    let fix = |sel: Option<usize>| match sel {
        Some(s) if s == i => None,
        Some(s) if s > i => Some(s - 1),
        other => other,
    };
    app.comparer_sel_a = fix(app.comparer_sel_a);
    app.comparer_sel_b = fix(app.comparer_sel_b);
}

/// Remove the item selected in the active Comparer pane (0 = Item 1, 1 = Item 2), falling back to the other pane.
pub fn remove_selected(app: &mut crate::state::App) {
    let target = if app.comparer_active_pane == 1 {
        app.comparer_sel_b.or(app.comparer_sel_a)
    } else {
        app.comparer_sel_a.or(app.comparer_sel_b)
    };
    if let Some(idx) = target {
        if idx < app.comparer_items.len() {
            remove(app, idx);
        } else {
            let len = app.comparer_items.len();
            let clamp = |sel: Option<usize>| match sel {
                Some(_) if len == 0 => None,
                Some(s) if s >= len => Some(len - 1),
                other => other,
            };
            app.comparer_sel_a = clamp(app.comparer_sel_a);
            app.comparer_sel_b = clamp(app.comparer_sel_b);
        }
    }
}

/// Open a comparison of the selected items (they must be two different items).
pub fn compare_selected(app: &mut crate::state::App, mode: DiffMode) -> bool {
    match (app.comparer_sel_a, app.comparer_sel_b) {
        (Some(a), Some(b)) if a != b && a < app.comparer_items.len() && b < app.comparer_items.len() => {
            app.comparer_active_diff = Some(DiffView::new(app.comparer_items[a].clone(), app.comparer_items[b].clone(), mode));
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    struct DiffCase<'a> {
        name: &'a str,
        left: &'a [u8],
        right: &'a [u8],
        mode: DiffMode,
        expected_changes: usize,
        expected_left_ops: Vec<(Change, &'a str)>,
        expected_right_ops: Vec<(Change, &'a str)>,
        expected_jump_rows: Vec<(usize, usize)>,
    }

    /// The text of every span of one kind, in order, for the item built from `rows`.
    fn of_kind(rows: &[Row], want: Change) -> Vec<String> {
        spans(rows).into_iter().filter(|s| s.change == want).map(|s| s.text).collect()
    }

    /// A value is compared against the next value, not against the punctuation stuck to it.
    /// Without delimiter tokens, `true}` against `true, "debug": 1}` reads as a change to the
    /// whole tail, and a path against the same path with more on the end reads as a change to
    /// all of it.
    #[test]
    fn delimiters_are_tokens_of_their_own_matrix() {
        struct Case<'a> {
            name: &'a str,
            a: &'a str,
            b: &'a str,
            /// Text that must come back as unchanged on both sides.
            same: Vec<&'a str>,
            modified_a: Vec<&'a str>,
            modified_b: Vec<&'a str>,
            added: Vec<&'a str>,
        }
        let cases = [
            Case {
                name: "a field added to the end of an object is an addition, not a rewrite",
                a: r#"{"id": 101, "role": "user", "active": true}"#,
                b: r#"{"id": 102, "role": "admin", "active": true, "debug": 1}"#,
                same: vec!["true", "}"],
                modified_a: vec!["101", "user"],
                modified_b: vec!["102", "admin"],
                added: vec![", \"debug\": 1"],
            },
            Case {
                name: "a path with more on the end keeps the part both share",
                a: "/api/v1/users",
                b: "/api/v1/users/42?role=user",
                same: vec!["/api/v1/users"],
                modified_a: vec![],
                modified_b: vec![],
                added: vec!["/42?role=user"],
            },
            Case {
                name: "a query string gaining a parameter",
                a: "/search?q=shoes",
                b: "/search?q=shoes&page=2",
                same: vec!["/search?q=shoes"],
                modified_a: vec![],
                modified_b: vec![],
                added: vec!["&page=2"],
            },
            Case {
                name: "a value inside brackets, with the brackets left alone",
                a: "items[0] = 12",
                b: "items[0] = 34",
                same: vec!["items[0] = "],
                modified_a: vec!["12"],
                modified_b: vec!["34"],
                added: vec![],
            },
        ];

        assert_table!(cases, |idx, Case { name, a, b, same, modified_a, modified_b, added }| {
            let d = diff_words(a, b).expect("both items are small enough to compare");
            let unchanged_a = of_kind(&d.a, Change::Same).join("");
            let unchanged_b = of_kind(&d.b, Change::Same).join("");
            for text in &same {
                assert!(unchanged_a.contains(text), "case #{idx} ({name}): {text:?} unchanged in A, got {unchanged_a:?}");
                assert!(unchanged_b.contains(text), "case #{idx} ({name}): {text:?} unchanged in B, got {unchanged_b:?}");
            }
            assert_eq!(of_kind(&d.a, Change::Modified), modified_a, "case #{idx} ({name}): amber in A");
            assert_eq!(of_kind(&d.b, Change::Modified), modified_b, "case #{idx} ({name}): amber in B");
            assert_eq!(of_kind(&d.b, Change::Inserted), added, "case #{idx} ({name}): green in B");
            assert!(of_kind(&d.a, Change::Deleted).is_empty(), "case #{idx} ({name}): nothing is taken away");
            // and the tokens still spell the items they came from
            assert_eq!(rebuilt(&d.a), a, "case #{idx} ({name}): item A reads back");
            assert_eq!(rebuilt(&d.b), b, "case #{idx} ({name}): item B reads back");
        });
    }

    /// Every token the comparison works on, concatenated, is the line it came from.
    #[test]
    fn word_tokens_split_without_losing_anything_matrix() {
        let cases: [(&str, &str, Vec<&str>); 7] = [
            ("delimiters stand alone", "{\"a\": 1}", vec!["{", "\"", "a", "\"", ":", " ", "1", "}"]),
            ("a path splits on its slashes", "/api/v1", vec!["/", "api", "/", "v1"]),
            ("a query string splits on its punctuation", "?a=1&b=2", vec!["?", "a", "=", "1", "&", "b", "=", "2"]),
            ("runs of whitespace are one token", "a   b", vec!["a", "   ", "b"]),
            ("a word run is one token", "Content-Length", vec!["Content-Length"]),
            ("leading whitespace is kept", "  x", vec!["  ", "x"]),
            ("nothing at all", "", vec![]),
        ];
        assert_table!(cases, |idx, (what, line, expected)| {
            assert_eq!(word_tokens(line), expected, "case #{idx} ({what})");
            assert_eq!(word_tokens(line).concat(), line, "case #{idx} ({what}): the line reads back");
        });
    }

    /// Bytes put into the middle of a payload shift what follows instead of making every byte
    /// after them look changed: the bytes on either side stay as they are, and only the new
    /// ones are marked.
    #[test]
    fn inserted_bytes_leave_the_rest_of_the_payload_alone_matrix() {
        struct Case<'a> {
            name: &'a str,
            a: &'a [u8],
            b: &'a [u8],
            /// How many bytes of each item are marked as unchanged.
            same_a: usize,
            same_b: usize,
            differing: usize,
        }
        let cases = [
            Case {
                name: "two bytes put in the middle",
                a: b"HEADER----PAYLOAD----FOOTER",
                b: b"HEADER----PAY!!LOAD----FOOTER",
                same_a: 27,
                same_b: 27,
                differing: 2,
            },
            Case {
                name: "two bytes taken out of the middle",
                a: b"HEADER----PAY!!LOAD----FOOTER",
                b: b"HEADER----PAYLOAD----FOOTER",
                same_a: 27,
                same_b: 27,
                differing: 2,
            },
            Case {
                name: "one byte put at the front",
                a: b"0123456789abcdef0123456789abcdef",
                b: b"X0123456789abcdef0123456789abcdef",
                same_a: 32,
                same_b: 32,
                differing: 1,
            },
            Case {
                name: "a byte changed in place is still a change in place",
                a: b"0123456789abcdef",
                b: b"0123X56789abcdef",
                same_a: 15,
                same_b: 15,
                differing: 1,
            },
            Case {
                name: "two payloads with nothing in common",
                a: b"AAAAAAAA",
                b: b"BBBBBBBB",
                same_a: 0,
                same_b: 0,
                differing: 8,
            },
        ];

        assert_table!(cases, |idx, Case { name, a, b, same_a, same_b, differing }| {
            let d = diff_bytes(a, b);
            assert_eq!(d.a.len(), a.len(), "case #{idx} ({name}): one mark per byte of A");
            assert_eq!(d.b.len(), b.len(), "case #{idx} ({name}): one mark per byte of B");
            assert_eq!(d.a.iter().filter(|c| **c == Change::Same).count(), same_a, "case #{idx} ({name}): A untouched");
            assert_eq!(d.b.iter().filter(|c| **c == Change::Same).count(), same_b, "case #{idx} ({name}): B untouched");
            assert_eq!(d.differing, differing, "case #{idx} ({name}): bytes counted as differing");
            // the bytes marked unchanged in each item really are the same bytes, in order
            let kept = |data: &[u8], marks: &[Change]| -> Vec<u8> {
                data.iter().zip(marks).filter(|(_, c)| **c == Change::Same).map(|(byte, _)| *byte).collect()
            };
            assert_eq!(kept(a, &d.a), kept(b, &d.b), "case #{idx} ({name}): both items kept the same bytes");
        });

        // a buffer past the ceiling falls back to the offset-by-offset comparison, which is
        // coarser but will not keep the window waiting
        let big_a = vec![b'x'; MAX_BYTE_ALIGN_SIZE + 1];
        let mut big_b = big_a.clone();
        big_b[0] = b'y';
        let d = diff_bytes(&big_a, &big_b);
        assert_eq!(d.differing, 1, "the one byte that differs is still found");
        assert_eq!(d.a.len(), big_a.len());
    }

    #[test]
    fn text_and_byte_diff_matrix() {
        let word_and_line_cases = [
            DiffCase {
                name: "word-level substitution groups adjacent delete+insert into Modified",
                left: b"Hello brave world, see you soon",
                right: b"Hello new world, see you later today",
                mode: DiffMode::Words,
                expected_changes: 2,
                expected_left_ops: vec![
                    (Change::Same, "Hello "),
                    (Change::Modified, "brave"),
                    (Change::Same, " world, see you "),
                    (Change::Modified, "soon"),
                ],
                expected_right_ops: vec![
                    (Change::Same, "Hello "),
                    (Change::Modified, "new"),
                    (Change::Same, " world, see you "),
                    (Change::Modified, "later today"),
                ],
                expected_jump_rows: vec![(0, 0), (0, 0)],
            },
            DiffCase {
                name: "word-level pure insertion",
                left: b"a b c",
                right: b"a b X c",
                mode: DiffMode::Words,
                expected_changes: 1,
                expected_left_ops: vec![(Change::Same, "a b c")],
                expected_right_ops: vec![
                    (Change::Same, "a b "),
                    (Change::Inserted, "X "),
                    (Change::Same, "c"),
                ],
                expected_jump_rows: vec![(0, 0)],
            },
            DiffCase {
                name: "word-level pure deletion",
                left: b"one two three",
                right: b"one three",
                mode: DiffMode::Words,
                expected_changes: 1,
                expected_left_ops: vec![
                    (Change::Same, "one "),
                    (Change::Deleted, "two "),
                    (Change::Same, "three"),
                ],
                expected_right_ops: vec![(Change::Same, "one three")],
                expected_jump_rows: vec![(0, 0)],
            },
            DiffCase {
                name: "word-level identical multiline text",
                left: b"same\ntext",
                right: b"same\ntext",
                mode: DiffMode::Words,
                expected_changes: 0,
                expected_left_ops: vec![(Change::Same, "same\ntext")],
                expected_right_ops: vec![(Change::Same, "same\ntext")],
                expected_jump_rows: vec![],
            },
            DiffCase {
                name: "line-level HTTP header modification and trailing line insertion",
                left: b"HTTP/1.1 200 OK\nX-Id: 1\nBody\n",
                right: b"HTTP/1.1 200 OK\nX-Id: 2\nBody\nExtra\n",
                mode: DiffMode::Words,
                expected_changes: 2,
                expected_left_ops: vec![
                    (Change::Same, "HTTP/1.1 200 OK\nX-Id: "),
                    (Change::Modified, "1"),
                    (Change::Same, "\nBody\n"),
                ],
                expected_right_ops: vec![
                    (Change::Same, "HTTP/1.1 200 OK\nX-Id: "),
                    (Change::Modified, "2"),
                    (Change::Same, "\nBody\n"),
                    (Change::Inserted, "Extra\n"),
                ],
                expected_jump_rows: vec![(1, 1), (3, 3)],
            },
        ];

        assert_table!(word_and_line_cases, |idx, case| {
            assert_eq!(case.mode, DiffMode::Words);
            let a = std::str::from_utf8(case.left).unwrap();
            let b = std::str::from_utf8(case.right).unwrap();
            let d = diff_words(a, b).unwrap();
            assert_eq!(d.hunks.len(), case.expected_changes, "case #{idx} ({}) changes", case.name);
            let (flat_a, flat_b) = (spans(&d.a), spans(&d.b));
            let got_left: Vec<(Change, &str)> = flat_a.iter().map(|s| (s.change, s.text.as_str())).collect();
            let got_right: Vec<(Change, &str)> = flat_b.iter().map(|s| (s.change, s.text.as_str())).collect();
            assert_eq!(got_left, case.expected_left_ops, "case #{idx} ({}) left ops", case.name);
            assert_eq!(got_right, case.expected_right_ops, "case #{idx} ({}) right ops", case.name);
            assert_eq!(d.hunks.len(), case.expected_jump_rows.len(), "case #{idx} ({}) jump len", case.name);
            if !case.expected_jump_rows.is_empty() {
                assert_eq!((d.hunks[0].line_a, d.hunks[0].line_b), case.expected_jump_rows[0], "case #{idx} ({}) first jump row", case.name);
            }
        });

        // Byte-level diff matrix
        let byte_cases: [(&str, &[u8], &[u8], usize, Vec<usize>, Option<(usize, Change)>, Option<(usize, Change)>); 4] = [
            (
                "byte modification in row 0 and deletion in row 1",
                b"0123456789abcdefXYZ",
                b"0123456789abcdeFXY",
                2,
                vec![0, 1],
                Some((15, Change::Modified)),
                Some((18, Change::Deleted)),
            ),
            (
                "byte pure insertion at tail",
                b"ab",
                b"abcd",
                2,
                vec![0],
                None,
                Some((2, Change::Inserted)),
            ),
            (
                "byte pure deletion at tail",
                b"abcd",
                b"ab",
                2,
                vec![0],
                Some((2, Change::Deleted)),
                None,
            ),
            (
                "byte identical buffers",
                b"same",
                b"same",
                0,
                vec![],
                Some((0, Change::Same)),
                Some((0, Change::Same)),
            ),
        ];

        assert_table!(byte_cases, |idx, (name, left, right, expected_diff, expected_rows, check_a, check_b)| {
            let d = diff_bytes(left, right);
            assert_eq!(d.differing, expected_diff, "byte case #{idx} ({name}) differing");
            assert_eq!(d.diff_rows, expected_rows, "byte case #{idx} ({name}) diff_rows");
            assert_eq!(d.a.len(), left.len(), "byte case #{idx} ({name}) a len");
            assert_eq!(d.b.len(), right.len(), "byte case #{idx} ({name}) b len");
            if let Some((off, ch)) = check_a {
                assert_eq!(d.a[off], ch, "byte case #{idx} ({name}) a[{off}]");
            }
            if let Some((off, ch)) = check_b {
                let side = if off < d.b.len() { &d.b } else { &d.a };
                assert_eq!(side[off], ch, "byte case #{idx} ({name}) side[{off}]");
            }
        });
    }

    #[test]
    fn edge_cases_and_resilience_matrix() {
        let edge_cases: [(&str, &str, &str, usize); 8] = [
            ("empty vs empty", "", "", 0),
            ("populated vs empty", "abc", "", 1),
            ("empty vs populated", "", "abc", 1),
            ("identical single word", "abc", "abc", 0),
            ("whitespace-only change (spaces vs tabs)", "a  b", "a\tb", 1),
            ("mismatched CRLF vs LF line endings", "line1\r\nline2\r\n", "line1\nline2\n", 2),
            ("multibyte UTF-8 accents", "naïve café", "naïve thé", 1),
            ("multibyte UTF-8 ZWJ emoji grapheme clusters", "status: 👨‍👩‍👧‍👦 ok", "status: 🚀 ok", 1),
        ];

        assert_table!(edge_cases, |idx, (name, left, right, expected_changes)| {
            let d = compute_patience_word_diff(left, right).unwrap();
            let (text_a, text_b) = (rebuilt(&d.a), rebuilt(&d.b));
            assert_eq!(text_a, left, "case #{idx} ({name}) left reconstruction");
            assert_eq!(text_b, right, "case #{idx} ({name}) right reconstruction");
            assert_eq!(d.hunks.len(), expected_changes, "case #{idx} ({name}) change count");
        });

        // Tokenize & ComparerItem classification table
        let s = "GET /a?b=1 HTTP/1.1\r\nHost: shop.test\n\n{\"id\": 42}";
        let t = tokenize(s);
        assert_eq!(t.concat(), s);
        assert_eq!(&t[..6], ["GET", " ", "/", "a", "?", "b"]);
        assert!(t.contains(&"\r\n"));
        assert!(t.contains(&"\n\n"));
        assert_eq!(tokenize(""), Vec::<&str>::new());
        assert_eq!(tokenize("naïve café"), ["naïve", " ", "café"]);

        let item_cases: [(&str, &[u8], usize, bool); 4] = [
            ("ASCII with CRLF is text", b"hello\r\n", 7, true),
            ("UTF-8 with tabs/newlines is text", "café\t✓\n".as_bytes(), 10, true),
            ("gzip magic bytes with NUL/0xff is binary", &[0x1f, 0x8b, 0x00, 0xff], 4, false),
            ("embedded NUL byte in ASCII is binary", b"a\x00b", 3, false),
        ];
        assert_table!(item_cases, |idx, (name, bytes, expected_len, expected_is_text)| {
            let item = ComparerItem::from_bytes(idx + 1, name, bytes);
            assert_eq!((item.length, item.is_text), (expected_len, expected_is_text), "case #{idx} ({name})");
        });
    }

    #[test]
    fn diff_invariant_reconstructs_right_from_left_matrix() {
        let samples: [(&str, &str, &str); 7] = [
            ("empty buffers", "", ""),
            ("insertion into empty", "", "GET /index.html HTTP/1.1\r\n\r\n"),
            ("deletion to empty", "GET /index.html HTTP/1.1\r\n\r\n", ""),
            ("fox sentence edit", "the quick brown fox", "the quick red fox jumps"),
            (
                "JSON payload mutation",
                "{\"user\":\"alice\",\"role\":\"viewer\",\"active\":true}",
                "{\"user\":\"alice\",\"role\":\"admin\",\"active\":false,\"mfa\":1}",
            ),
            (
                "HTTP response headers and body",
                "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Length: 5\r\n\r\nhello",
                "HTTP/1.1 403 Forbidden\r\nServer: envoy\r\nContent-Length: 6\r\n\r\ndenied",
            ),
            (
                "UTF-8 and punctuation mix",
                "α + β = γ; café #1\nline two",
                "α - β = δ; café #2\nline two\nline three",
            ),
        ];

        assert_table!(samples, |idx, (name, left, right)| {
            let d = compute_patience_word_diff(left, right).unwrap();
            // 1. Span stream on each side reproduces its respective buffer verbatim
            let (rebuilt_left, rebuilt_right) = (rebuilt(&d.a), rebuilt(&d.b));
            assert_eq!(rebuilt_left, left, "case #{idx} ({name}) rebuilt left");
            assert_eq!(rebuilt_right, right, "case #{idx} ({name}) rebuilt right");

            // 2. Applying Patience TextDiff edit script to `left` slices reconstructs `right`
            let text_diff = similar::TextDiff::configure()
                .algorithm(similar::Algorithm::Patience)
                .diff_words(left, right);
            let mut applied = String::new();
            for op in text_diff.ops() {
                match *op {
                    similar::DiffOp::Equal { old_index, len, .. } => {
                        for s in &text_diff.old_slices()[old_index..old_index + len] {
                            applied.push_str(s);
                        }
                    }
                    similar::DiffOp::Delete { .. } => {}
                    similar::DiffOp::Insert { new_index, new_len, .. }
                    | similar::DiffOp::Replace { new_index, new_len, .. } => {
                        for s in &text_diff.new_slices()[new_index..new_index + new_len] {
                            applied.push_str(s);
                        }
                    }
                }
            }
            assert_eq!(applied, right, "case #{idx} ({name}) edit script application");

            // 3. Byte-level diff invariant: the two change streams describe one edit script.
            // They are walked together -- a byte marked the same or modified is consumed from
            // both items, a deleted one from the left only and an inserted one from the right
            // only -- and the left item plus that script has to give the right item back. The
            // walk is what proves the alignment: the two streams no longer share an index.
            let bd = diff_bytes(left.as_bytes(), right.as_bytes());
            let mut rebuilt_bytes = Vec::with_capacity(right.len());
            let (mut ia, mut ib) = (0usize, 0usize);
            while ia < bd.a.len() || ib < bd.b.len() {
                match (bd.a.get(ia).copied(), bd.b.get(ib).copied()) {
                    (Some(Change::Same), Some(Change::Same)) => {
                        assert_eq!(
                            left.as_bytes()[ia], right.as_bytes()[ib],
                            "case #{idx} ({name}): a byte marked unchanged is the byte it was lined up with"
                        );
                        rebuilt_bytes.push(right.as_bytes()[ib]);
                        ia += 1;
                        ib += 1;
                    }
                    (Some(Change::Deleted), _) | (Some(_), None) => ia += 1,
                    (_, Some(Change::Inserted)) | (None, Some(_)) => {
                        rebuilt_bytes.push(right.as_bytes()[ib]);
                        ib += 1;
                    }
                    // a replacement: the two runs stand for each other whatever their lengths,
                    // so each is taken whole rather than a byte at a time
                    (Some(Change::Modified), _) | (_, Some(Change::Modified)) => {
                        while bd.a.get(ia) == Some(&Change::Modified) {
                            ia += 1;
                        }
                        while bd.b.get(ib) == Some(&Change::Modified) {
                            rebuilt_bytes.push(right.as_bytes()[ib]);
                            ib += 1;
                        }
                    }
                    (None, None) => break,
                    // a deletion is only ever marked on the left item and an insertion only
                    // on the right, so no other pairing exists
                    (left_change, right_change) => {
                        unreachable!("case #{idx} ({name}): {left_change:?} against {right_change:?}")
                    }
                }
            }
            assert_eq!(rebuilt_bytes, right.as_bytes(), "case #{idx} ({name}) byte diff reconstruction");
        });
    }

    #[test]
    fn threshold_and_async_worker_matrix() {
        let over_limit = "a".repeat(MAX_WORD_DIFF_SIZE + 1);
        let under_limit_a = "token ".repeat(20_000);
        let under_limit_b = under_limit_a.replacen("token", "other", 1);

        let threshold_cases: [(&str, &str, &str, Option<usize>, DiffMode, Option<&str>); 4] = [
            (
                "left exceeds 256 KB falls back to Bytes",
                &over_limit,
                "w",
                None,
                DiffMode::Bytes,
                Some(WORD_DIFF_LIMIT_NOTE),
            ),
            (
                "right exceeds 256 KB falls back to Bytes",
                "w",
                &over_limit,
                None,
                DiffMode::Bytes,
                Some(WORD_DIFF_LIMIT_NOTE),
            ),
            (
                "both exceed 256 KB falls back to Bytes",
                &over_limit,
                &over_limit,
                None,
                DiffMode::Bytes,
                Some(WORD_DIFF_LIMIT_NOTE),
            ),
            (
                "120 KB payload within 256 KB ceiling stays in Words mode",
                &under_limit_a,
                &under_limit_b,
                Some(1),
                DiffMode::Words,
                None,
            ),
        ];

        assert_table!(threshold_cases, |idx, (name, a, b, expected_word_changes, expected_mode, expected_note)| {
            assert_eq!(
                diff_words(a, b).map(|d| d.hunks.len()),
                expected_word_changes,
                "case #{idx} ({name}) diff_words"
            );
            let item_a = ComparerItem::from_text(1, "A", a);
            let item_b = ComparerItem::from_text(2, "B", b);
            let mut v = DiffView::new(item_a, item_b, DiffMode::Words);
            if expected_mode == DiffMode::Words {
                wait(&mut v);
            }
            assert_eq!(v.mode, expected_mode, "case #{idx} ({name}) DiffView mode");
            assert_eq!(v.fallback_note.as_deref(), expected_note, "case #{idx} ({name}) fallback_note");
            if expected_mode == DiffMode::Bytes {
                assert!(v.bytes.is_some(), "case #{idx} ({name}) byte diff populated on fallback");
            }
        });

        // DiffView mode switching and lazy byte computation
        let a = ComparerItem::from_text(1, "A", "alpha beta");
        let b = ComparerItem::from_text(2, "B", "alpha gamma!");
        let mut v = DiffView::new(a, b, DiffMode::Words);
        wait(&mut v);
        assert_eq!(v.difference_count(), 1);
        assert!(v.bytes.is_none(), "bytes computed only when shown");
        v.set_mode(DiffMode::Bytes);
        // "alpha beta" against "alpha gamma!": the shared prefix is left alone and only the
        // bytes the alignment cannot pair up are counted
        assert_eq!(v.difference_count(), 5);
        assert_eq!(v.jump_targets(), [0]);
        v.set_mode(DiffMode::Words);
        assert!(!v.poll(), "already computed: not started again");
        assert_eq!(v.difference_count(), 1);

        // Background worker non-blocking check
        let a = ComparerItem::from_text(1, "A", &"alpha ".repeat(5_000));
        let b = ComparerItem::from_text(2, "B", &"omega ".repeat(5_000));
        let started = std::time::Instant::now();
        let mut v = DiffView::new(a, b, DiffMode::Words);
        assert!(started.elapsed() < std::time::Duration::from_millis(200), "the diff didn't block");
        for _ in 0..3000 {
            if !v.poll() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(v.words_job.is_none());
        assert!(v.words.as_ref().unwrap().is_ok());
        assert!(v.difference_count() >= 1);
    }

    struct ClassCase<'a> {
        name: &'a str,
        a: &'a str,
        b: &'a str,
        /// Every difference, in document order.
        kinds: Vec<Change>,
        /// The text highlighted red in A, green in B, and amber on each side.
        deleted: Vec<&'a str>,
        added: Vec<&'a str>,
        modified_a: Vec<&'a str>,
        modified_b: Vec<&'a str>,
    }

    /// The text of every span on one side belonging to a difference of this kind.
    fn marked(rows: &[Row], kind: Change) -> Vec<&str> {
        spans_of(rows).filter(|s| s.change == kind).map(|s| s.text.as_str()).collect()
    }

    /// Every span of a side, filler rows and all (they have none), in order.
    fn spans_of(rows: &[Row]) -> impl Iterator<Item = &Span> {
        rows.iter().flat_map(|r| r.spans.iter())
    }

    /// The text of one side end to end: filler rows add nothing, so this is the item itself.
    fn rebuilt(rows: &[Row]) -> String {
        spans_of(rows).map(|s| s.text.as_str()).collect()
    }

    /// A line only A has stays red and a line only B has stays green, however close together
    /// they fall. Amber is for one field whose value changed and nothing else: before the diff
    /// worked line by line, `User-Agent: Mozilla/5.0` and `Content-Length: 48` on the same line
    /// of their items were paired into one amber block, as if the one had become the other.
    #[test]
    fn line_classification_matrix() {
        let cases = [
            ClassCase {
                name: "pure deletion: a header only A has",
                a: "Host: shop.test\nUser-Agent: Mozilla/5.0\nAccept: */*\n",
                b: "Host: shop.test\nAccept: */*\n",
                kinds: vec![Change::Deleted],
                deleted: vec!["User-Agent: Mozilla/5.0\n"],
                added: vec![],
                modified_a: vec![],
                modified_b: vec![],
            },
            ClassCase {
                name: "pure addition: the header and body only B has",
                a: "HTTP/1.1 200 OK\nContent-Type: application/json\n",
                b: "HTTP/1.1 200 OK\nContent-Type: application/json\nContent-Length: 2\n\n{}",
                kinds: vec![Change::Inserted],
                deleted: vec![],
                // one difference, but three rows of it: the view draws a row at a time
                added: vec!["Content-Length: 2\n", "\n", "{}"],
                modified_a: vec![],
                modified_b: vec![],
            },
            ClassCase {
                name: "semantic modification: the same header with a changed value",
                a: "X-Request-Id: 1\nContent-Length: 48\n",
                b: "X-Request-Id: 1\nContent-Length: 96\n",
                kinds: vec![Change::Modified],
                deleted: vec![],
                added: vec![],
                modified_a: vec!["48"],
                modified_b: vec!["96"],
            },
            ClassCase {
                name: "semantic modification: the method and target of a start line",
                a: "GET /users/42 HTTP/1.1\n",
                b: "POST /orders HTTP/1.1\n",
                kinds: vec![Change::Modified, Change::Modified],
                deleted: vec![],
                added: vec![],
                // the leading "/" is a token of its own and is common to both targets, so
                // only what follows it is marked
                modified_a: vec!["GET", "users/42"],
                modified_b: vec!["POST", "orders"],
            },
            ClassCase {
                name: "no ghost pairing: unrelated headers on the same line of each item",
                a: "Host: shop.test\nUser-Agent: Mozilla/5.0\n\n",
                b: "Host: shop.test\nContent-Length: 48\n\n",
                kinds: vec![Change::Deleted, Change::Inserted],
                deleted: vec!["User-Agent: Mozilla/5.0\n"],
                added: vec!["Content-Length: 48\n"],
                modified_a: vec![],
                modified_b: vec![],
            },
            ClassCase {
                name: "a whole request: start line amber, User-Agent red, length and body green",
                a: "GET /users/42 HTTP/1.1\r\nHost: shop.test\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                b: "POST /orders HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 48\r\n\r\n{\"sku\":\"A-1\",\"qty\":2}",
                kinds: vec![Change::Modified, Change::Modified, Change::Deleted, Change::Inserted, Change::Inserted],
                deleted: vec!["User-Agent: Mozilla/5.0\r\n"],
                added: vec!["Content-Length: 48\r\n", "{\"sku\":\"A-1\",\"qty\":2}"],
                // the leading "/" is common to both targets, so only what follows it is marked
                modified_a: vec!["GET", "users/42"],
                modified_b: vec!["POST", "orders"],
            },
            ClassCase {
                name: "a body line mostly the same is modified, not swapped out",
                a: "{\n  \"role\": \"viewer\",\n  \"active\": true\n}\n",
                b: "{\n  \"role\": \"admin\",\n  \"active\": true\n}\n",
                kinds: vec![Change::Modified],
                deleted: vec![],
                added: vec![],
                // the quotes and the comma around the value are tokens of their own and are
                // common to both, so only the value itself is marked
                modified_a: vec!["viewer"],
                modified_b: vec!["admin"],
            },
            ClassCase {
                name: "a body line sharing no words is a deletion and an addition",
                a: "{\n  \"role\": \"viewer\"\n}\n",
                b: "{\n  \"totals\": [1, 2]\n}\n",
                kinds: vec![Change::Deleted, Change::Inserted],
                deleted: vec!["  \"role\": \"viewer\"\n"],
                added: vec!["  \"totals\": [1, 2]\n"],
                modified_a: vec![],
                modified_b: vec![],
            },
        ];

        assert_table!(cases, |idx, case| {
            let d = compute_patience_word_diff(case.a, case.b).unwrap();
            let kinds: Vec<Change> = d.hunks.iter().map(|h| h.kind).collect();
            assert_eq!(kinds, case.kinds, "case #{idx} ({}) kinds", case.name);
            assert_eq!(marked(&d.a, Change::Deleted), case.deleted, "case #{idx} ({}) red in A", case.name);
            assert_eq!(marked(&d.b, Change::Inserted), case.added, "case #{idx} ({}) green in B", case.name);
            assert_eq!(marked(&d.a, Change::Modified), case.modified_a, "case #{idx} ({}) amber in A", case.name);
            assert_eq!(marked(&d.b, Change::Modified), case.modified_b, "case #{idx} ({}) amber in B", case.name);
            // a deletion only ever shows in A and an addition only in B
            assert!(marked(&d.b, Change::Deleted).is_empty(), "case #{idx} ({}) nothing deleted in B", case.name);
            assert!(marked(&d.a, Change::Inserted).is_empty(), "case #{idx} ({}) nothing added in A", case.name);
            // whatever the classification, each side still reproduces its item exactly
            assert_eq!(rebuilt(&d.a), case.a, "case #{idx} ({}) A rebuilt", case.name);
            assert_eq!(rebuilt(&d.b), case.b, "case #{idx} ({}) B rebuilt", case.name);
            // every difference is marked on the side(s) it belongs to, so the window can pick
            // the active one out of the spans of its own colour
            for (h, hunk) in d.hunks.iter().enumerate() {
                if hunk.kind != Change::Inserted {
                    assert!(spans_of(&d.a).any(|s| s.hunk == Some(h)), "case #{idx} ({}) difference {h} marked in A", case.name);
                }
                if hunk.kind != Change::Deleted {
                    assert!(spans_of(&d.b).any(|s| s.hunk == Some(h)), "case #{idx} ({}) difference {h} marked in B", case.name);
                }
            }
        });
    }

    /// The two sides are drawn row against row, so they have to come out the same length, a
    /// line must never face one it was not compared with, and the padding must leave what each
    /// item says untouched.
    #[test]
    fn aligned_rows_pair_up_and_rebuild_both_items() {
        let cases: [(&str, &str, &str); 8] = [
            ("identical items", "a\nb\n", "a\nb\n"),
            ("a multi-line insertion in the middle", "a\nd\n", "a\nb1\nb2\nb3\nd\n"),
            ("a multi-line deletion in the middle", "a\nb1\nb2\nb3\nd\n", "a\nd\n"),
            ("an insertion at the end", "a\n", "a\nb\nc\n"),
            ("a deletion at the start", "x\ny\na\n", "a\n"),
            ("both items empty", "", ""),
            ("one item empty", "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", ""),
            (
                "a request gaining a body",
                "GET /users/42 HTTP/1.1\r\nHost: shop.test\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                "POST /orders HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 48\r\n\r\n{\"sku\":\"A-1\"}",
            ),
        ];

        assert_table!(cases, |idx, (name, a, b)| {
            let d = compute_patience_word_diff(a, b).unwrap();
            assert_eq!(d.a.len(), d.b.len(), "case #{idx} ({name}) the two sides are the same length");
            // each item's lines are all there, once each and in order, padding aside
            let own = |rows: &[Row]| rows.iter().filter_map(|r| r.line).collect::<Vec<_>>();
            assert_eq!(own(&d.a), (0..split_lines(a).len()).collect::<Vec<_>>(), "case #{idx} ({name}) A's lines");
            assert_eq!(own(&d.b), (0..split_lines(b).len()).collect::<Vec<_>>(), "case #{idx} ({name}) B's lines");
            // and the padding has not changed a byte of either item
            assert_eq!(rebuilt(&d.a), a, "case #{idx} ({name}) A rebuilt");
            assert_eq!(rebuilt(&d.b), b, "case #{idx} ({name}) B rebuilt");
            assert_table!(d.a.iter().zip(&d.b).enumerate().collect::<Vec<_>>(), |(row, (ra, rb))| {
                assert!(!(ra.is_filler() && rb.is_filler()), "case #{idx} ({name}) row {row} is padding on both sides");
                // nothing drawn carries a line terminator: one row of the model is one row on
                // screen, which is what holds the two panes level
                for s in ra.spans.iter().chain(&rb.spans) {
                    assert!(!shown(s).contains(['\r', '\n']), "case #{idx} ({name}) row {row} draws a terminator");
                }
            });
            assert_table!(&d.hunks, |h, hunk| {
                assert!(hunk.row < d.a.len().max(1), "case #{idx} ({name}) difference {h} is on row {} of {}", hunk.row, d.a.len());
            });
        });
    }

    /// "Next" and "Previous" step through `jump_targets`, so there is one per difference, in
    /// order, on a line that exists in the side it belongs to.
    #[test]
    fn navigation_targets_follow_the_differences() {
        let a = "GET /users/42 HTTP/1.1\r\nHost: shop.test\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        let b = "POST /orders HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 48\r\n\r\n{\"sku\":\"A-1\",\"qty\":2}";
        let mut v = DiffView::new(ComparerItem::from_text(1, "A", a), ComparerItem::from_text(2, "B", b), DiffMode::Words);
        wait(&mut v);
        assert!(v.active_diff_index.is_none(), "the view starts on no difference in particular");
        let targets = v.jump_targets();
        assert_eq!(targets.len(), v.difference_count(), "one place to jump to per difference");
        // both panes show the same rows, so one row number scrolls both: the start line is
        // row 0, the deleted User-Agent row 2, the added Content-Length row 3 (against A's
        // filler), and the added body row 5
        assert_eq!(targets, [0, 0, 2, 3, 5]);
        let rows = v.word_diff().unwrap().a.len();
        assert_table!(targets, |idx, row| {
            assert!(row < rows, "target #{idx} (row {row}) is one of the {rows} rows on show");
        });
        // changing mode drops the difference the view was on: the places to jump to are rows
        // of the hex dump now, not lines
        v.active_diff_index = Some(3);
        v.set_mode(DiffMode::Bytes);
        assert!(v.active_diff_index.is_none(), "the active difference does not survive the mode switch");
        assert_eq!(v.jump_targets().len(), v.bytes.as_ref().unwrap().diff_rows.len());
    }

    fn wait(v: &mut DiffView) {
        for _ in 0..500 {
            if !v.poll() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("word comparison never finished");
    }
}

