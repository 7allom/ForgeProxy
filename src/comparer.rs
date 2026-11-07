//! Comparer: captured items and the two comparisons.
//!
//! Words: both items are tokenized at the word level (`diff_words`) and diffed with
//! `similar::TextDiff` configured with `Algorithm::Patience`. Runs of changes are grouped:
//! a deletion next to an insertion is a modification, shown on both sides.
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
    pub text: String,
}

/// Word comparison: each side's text as spans, the number of changed regions, and the line
/// (0-based) each change starts on in each side, for "next/previous difference".
#[derive(Clone, Debug, PartialEq)]
pub struct WordDiff {
    pub a: Vec<Span>,
    pub b: Vec<Span>,
    pub changes: usize,
    pub change_lines: Vec<(usize, usize)>,
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
#[cfg_attr(not(test), allow(dead_code))]
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

// ---- word comparison (Patience Diff) -----------------------------------------------------

/// Compute a word-level diff using `similar::TextDiff` configured with `Algorithm::Patience`.
/// Returns `Err(WORD_DIFF_LIMIT_NOTE)` when either input exceeds [`MAX_WORD_DIFF_SIZE`] (256 KB).
pub fn compute_patience_word_diff(a: &str, b: &str) -> Result<WordDiff, String> {
    if a.len() > MAX_WORD_DIFF_SIZE || b.len() > MAX_WORD_DIFF_SIZE {
        return Err(WORD_DIFF_LIMIT_NOTE.into());
    }
    let diff = similar::TextDiff::configure()
        .algorithm(similar::Algorithm::Patience)
        .diff_words(a, b);
    let old_slices = diff.old_slices();
    let new_slices = diff.new_slices();
    let mut out = WordDiff {
        a: Vec::new(),
        b: Vec::new(),
        changes: 0,
        change_lines: Vec::new(),
    };
    let push = |spans: &mut Vec<Span>, change: Change, text: &str| match spans.last_mut() {
        Some(last) if last.change == change => last.text.push_str(text),
        _ => spans.push(Span { change, text: text.to_string() }),
    };
    let (mut line_a, mut line_b) = (0usize, 0usize);
    for op in diff.ops() {
        match *op {
            similar::DiffOp::Equal { old_index, new_index, len } => {
                for k in 0..len {
                    let ta = old_slices[old_index + k];
                    let tb = new_slices[new_index + k];
                    push(&mut out.a, Change::Same, ta);
                    push(&mut out.b, Change::Same, tb);
                    line_a += ta.matches('\n').count();
                    line_b += tb.matches('\n').count();
                }
            }
            similar::DiffOp::Delete { old_index, old_len, .. } => {
                out.changes += 1;
                out.change_lines.push((line_a, line_b));
                for &t in &old_slices[old_index..old_index + old_len] {
                    push(&mut out.a, Change::Deleted, t);
                    line_a += t.matches('\n').count();
                }
            }
            similar::DiffOp::Insert { new_index, new_len, .. } => {
                out.changes += 1;
                out.change_lines.push((line_a, line_b));
                for &t in &new_slices[new_index..new_index + new_len] {
                    push(&mut out.b, Change::Inserted, t);
                    line_b += t.matches('\n').count();
                }
            }
            similar::DiffOp::Replace { old_index, old_len, new_index, new_len } => {
                out.changes += 1;
                out.change_lines.push((line_a, line_b));
                for &t in &old_slices[old_index..old_index + old_len] {
                    push(&mut out.a, Change::Modified, t);
                    line_a += t.matches('\n').count();
                }
                for &t in &new_slices[new_index..new_index + new_len] {
                    push(&mut out.b, Change::Modified, t);
                    line_b += t.matches('\n').count();
                }
            }
        }
    }
    Ok(out)
}

/// None when either item exceeds `MAX_WORD_DIFF_SIZE` (256 KB).
#[cfg_attr(not(test), allow(dead_code))]
pub fn diff_words(a: &str, b: &str) -> Option<WordDiff> {
    compute_patience_word_diff(a, b).ok()
}

// ---- byte comparison ---------------------------------------------------------------------

pub const BYTES_PER_ROW: usize = 16;

pub fn diff_bytes(a: &[u8], b: &[u8]) -> ByteDiff {
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
    /// Difference the view last jumped to.
    pub current: Option<usize>,
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
            current: None,
            fallback_note: None,
        };
        v.set_mode(mode);
        v
    }

    pub fn set_mode(&mut self, mode: DiffMode) {
        self.mode = mode;
        self.current = None;
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
            DiffMode::Words => self.words.as_ref().and_then(|w| w.as_ref().ok()).map_or(0, |w| w.changes),
            DiffMode::Bytes => self.bytes.as_ref().map_or(0, |b| b.differing),
        }
    }

    /// Places "next/previous difference" can jump to: (row in A, row in B). Lines for
    /// words, 16-byte rows for bytes.
    pub fn jump_targets(&self) -> Vec<(usize, usize)> {
        match self.mode {
            DiffMode::Words => self.words.as_ref().and_then(|w| w.as_ref().ok()).map_or(Vec::new(), |w| w.change_lines.clone()),
            DiffMode::Bytes => self.bytes.as_ref().map_or(Vec::new(), |b| b.diff_rows.iter().map(|&r| (r, r)).collect()),
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
            assert_eq!(d.changes, case.expected_changes, "case #{idx} ({}) changes", case.name);
            let got_left: Vec<(Change, &str)> = d.a.iter().map(|s| (s.change, s.text.as_str())).collect();
            let got_right: Vec<(Change, &str)> = d.b.iter().map(|s| (s.change, s.text.as_str())).collect();
            assert_eq!(got_left, case.expected_left_ops, "case #{idx} ({}) left ops", case.name);
            assert_eq!(got_right, case.expected_right_ops, "case #{idx} ({}) right ops", case.name);
            assert_eq!(d.change_lines.len(), case.expected_jump_rows.len(), "case #{idx} ({}) jump len", case.name);
            if !case.expected_jump_rows.is_empty() {
                assert_eq!(d.change_lines[0], case.expected_jump_rows[0], "case #{idx} ({}) first jump row", case.name);
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
            let text_a: String = d.a.iter().map(|s| s.text.as_str()).collect();
            let text_b: String = d.b.iter().map(|s| s.text.as_str()).collect();
            assert_eq!(text_a, left, "case #{idx} ({name}) left reconstruction");
            assert_eq!(text_b, right, "case #{idx} ({name}) right reconstruction");
            assert_eq!(d.changes, expected_changes, "case #{idx} ({name}) change count");
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
            let rebuilt_left: String = d.a.iter().map(|s| s.text.as_str()).collect();
            let rebuilt_right: String = d.b.iter().map(|s| s.text.as_str()).collect();
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

            // 3. Byte-level diff invariant: applying byte changes to `left` reconstructs `right`
            let bd = diff_bytes(left.as_bytes(), right.as_bytes());
            let mut rebuilt_bytes = Vec::with_capacity(right.len());
            for (i, &ch) in bd.b.iter().enumerate() {
                match ch {
                    Change::Same => rebuilt_bytes.push(left.as_bytes()[i]),
                    Change::Modified | Change::Inserted => rebuilt_bytes.push(right.as_bytes()[i]),
                    Change::Deleted => unreachable!("Deleted only appears in bd.a"),
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
                diff_words(a, b).map(|d| d.changes),
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
        assert_eq!(v.difference_count(), 6);
        assert_eq!(v.jump_targets(), [(0, 0)]);
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
