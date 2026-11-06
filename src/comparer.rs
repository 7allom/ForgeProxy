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

    #[test]
    fn tokens_rebuild_the_text() {
        let s = "GET /a?b=1 HTTP/1.1\r\nHost: shop.test\n\n{\"id\": 42}";
        let t = tokenize(s);
        assert_eq!(t.concat(), s);
        assert_eq!(&t[..6], ["GET", " ", "/", "a", "?", "b"]);
        assert!(t.contains(&"\r\n"));
        assert!(t.contains(&"\n\n"));
        assert_eq!(tokenize(""), Vec::<&str>::new());
        assert_eq!(tokenize("naïve café"), ["naïve", " ", "café"]);
    }

    #[test]
    fn patience_word_diff_is_accurate() {
        for (a, b) in [
            ("", ""),
            ("abc", ""),
            ("", "abc"),
            ("abc", "abc"),
            ("the quick brown fox", "the quick red fox jumps"),
        ] {
            let d = compute_patience_word_diff(a, b).unwrap();
            let text_a: String = d.a.iter().map(|s| s.text.as_str()).collect();
            let text_b: String = d.b.iter().map(|s| s.text.as_str()).collect();
            assert_eq!(text_a, a);
            assert_eq!(text_b, b);
        }
    }

    #[test]
    fn word_diff_groups_changes() {
        let a = "Hello brave world, see you soon";
        let b = "Hello new world, see you later today";
        let d = diff_words(a, b).unwrap();
        let text = |s: &[Span]| s.iter().map(|x| x.text.as_str()).collect::<String>();
        assert_eq!(text(&d.a), a);
        assert_eq!(text(&d.b), b);
        // "brave" -> "new" and "soon" -> "later today"
        assert_eq!(d.changes, 2);
        let changed = |s: &[Span], c: Change| s.iter().filter(|x| x.change == c).map(|x| x.text.clone()).collect::<Vec<_>>();
        assert_eq!(changed(&d.a, Change::Modified), ["brave", "soon"]);
        assert_eq!(changed(&d.b, Change::Modified), ["new", "later today"]);
        // pure insertion and deletion
        let d = diff_words("a b c", "a b X c").unwrap();
        assert_eq!(d.changes, 1);
        assert!(d.b.iter().any(|s| s.change == Change::Inserted && s.text.contains('X')));
        assert!(d.a.iter().all(|s| s.change == Change::Same));
        let d = diff_words("one two three", "one three").unwrap();
        assert!(d.a.iter().any(|s| s.change == Change::Deleted && s.text.contains("two")));
        // identical
        assert_eq!(diff_words("same\ntext", "same\ntext").unwrap().changes, 0);
    }

    #[test]
    fn word_diff_change_lines() {
        let a = "HTTP/1.1 200 OK\nX-Id: 1\nBody\n";
        let b = "HTTP/1.1 200 OK\nX-Id: 2\nBody\nExtra\n";
        let d = diff_words(a, b).unwrap();
        assert_eq!(d.changes, 2);
        assert_eq!(d.change_lines[0], (1, 1));
        // the added line can be aligned either side of "Body"'s newline; both are minimal
        assert!(matches!(d.change_lines[1], (2, 2) | (3, 3)), "{:?}", d.change_lines);
    }

    #[test]
    fn byte_diff_offsets() {
        let a = b"0123456789abcdefXYZ";
        let b = b"0123456789abcdeFXY";
        let d = diff_bytes(a, b);
        assert_eq!(d.differing, 2); // offset 15 differs, offset 18 only in A
        assert_eq!(d.a[15], Change::Modified);
        assert_eq!(d.b[15], Change::Modified);
        assert_eq!(d.a[18], Change::Deleted);
        assert_eq!(d.b.len(), 18);
        assert_eq!(d.diff_rows, [0, 1]);
        let d = diff_bytes(b"ab", b"abcd");
        assert_eq!((d.differing, &d.b[2..]), (2, &[Change::Inserted, Change::Inserted][..]));
        assert_eq!(diff_bytes(b"same", b"same").differing, 0);
    }

    #[test]
    fn items_from_text_and_bytes() {
        let t = ComparerItem::from_text(1, "Manual", "hello\r\n");
        assert_eq!((t.length, t.is_text), (7, true));
        assert_eq!(t.text(), "hello\r\n");
        let bin = ComparerItem::from_bytes(2, "Selection (4 bytes)", &[0x1f, 0x8b, 0x00, 0xff]);
        assert_eq!((bin.length, bin.is_text), (4, false));
        assert!(!ComparerItem::from_bytes(3, "x", b"a\x00b").is_text);
    }

    #[test]
    fn large_inputs_fall_back_to_bytes() {
        let big = "a".repeat(MAX_WORD_DIFF_SIZE + 1);
        assert_eq!(compute_patience_word_diff(&big, "w"), Err(WORD_DIFF_LIMIT_NOTE.to_string()));
        assert!(diff_words(&big, "w").is_none());

        let item_a = ComparerItem::from_text(1, "Big", &big);
        let item_b = ComparerItem::from_text(2, "Small", "w");
        let v = DiffView::new(item_a, item_b, DiffMode::Words);
        assert_eq!(v.mode, DiffMode::Bytes);
        assert_eq!(v.fallback_note.as_deref(), Some(WORD_DIFF_LIMIT_NOTE));
        assert!(v.bytes.is_some());

        // a long, mostly-equal input within 256 KB succeeds
        let a = "token ".repeat(20_000);
        let b = a.replacen("token", "other", 1);
        assert_eq!(diff_words(&a, &b).unwrap().changes, 1);
    }

    #[test]
    fn diff_view_modes() {
        let a = ComparerItem::from_text(1, "A", "alpha beta");
        let b = ComparerItem::from_text(2, "B", "alpha gamma!");
        let mut v = DiffView::new(a, b, DiffMode::Words);
        wait(&mut v);
        assert_eq!(v.difference_count(), 1);
        assert!(v.bytes.is_none(), "bytes computed only when shown");
        v.set_mode(DiffMode::Bytes);
        assert_eq!(v.difference_count(), 6); // "beta" vs "gamm" + "a!" past the end
        assert_eq!(v.jump_targets(), [(0, 0)]);
        v.set_mode(DiffMode::Words);
        assert!(!v.poll(), "already computed: not started again");
        assert_eq!(v.difference_count(), 1);
    }

    fn wait(v: &mut DiffView) {
        for _ in 0..500 {
            if !v.poll() { return; }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("word comparison never finished");
    }

    #[test]
    fn word_comparison_runs_off_the_calling_thread() {
        // big and fully different: slow for Myers, yet `new` returns at once
        let a = ComparerItem::from_text(1, "A", &"alpha ".repeat(5_000));
        let b = ComparerItem::from_text(2, "B", &"omega ".repeat(5_000));
        let started = std::time::Instant::now();
        let mut v = DiffView::new(a, b, DiffMode::Words);
        assert!(started.elapsed() < std::time::Duration::from_millis(200), "the diff didn't block");
        assert_eq!(v.difference_count(), 0, "nothing to show until it's done");
        for _ in 0..3000 {
            if !v.poll() { break; }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(v.words_job.is_none());
        assert!(v.words.as_ref().unwrap().is_ok());
        assert!(v.difference_count() >= 1);
    }
}
