//! Comparer: captured items and the two comparisons.
//!
//! Words: both items are split into tokens (runs of letters/digits, runs of whitespace,
//! single punctuation characters, so joining the tokens gives the text back exactly) and
//! diffed with Myers' algorithm (linear-space, O((N+M)·D)). Runs of changes are grouped:
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

/// Largest word comparison (tokens in both items together); beyond it, use bytes.
pub const MAX_WORD_TOKENS: usize = 200_000;

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

// ---- Myers diff ------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Op {
    /// a[i] == b[j]
    Equal(usize, usize),
    /// a[i] only
    Delete(usize),
    /// b[j] only
    Insert(usize),
}

/// Edit script turning `a` into `b`, with the fewest insertions and deletions.
pub fn diff_ops<T: PartialEq>(a: &[T], b: &[T]) -> Vec<Op> {
    let max = a.len() + b.len() + 1;
    let mut vf = vec![0usize; 2 * max + 2];
    let mut vb = vec![0usize; 2 * max + 2];
    let mut out = Vec::with_capacity(max);
    conquer(a, 0, a.len(), b, 0, b.len(), &mut vf, &mut vb, &mut out);
    out
}

fn conquer<T: PartialEq>(a: &[T], mut a0: usize, mut a1: usize, b: &[T], mut b0: usize, mut b1: usize,
                         vf: &mut [usize], vb: &mut [usize], out: &mut Vec<Op>) {
    // common prefix and suffix
    while a0 < a1 && b0 < b1 && a[a0] == b[b0] {
        out.push(Op::Equal(a0, b0));
        a0 += 1;
        b0 += 1;
    }
    let mut suffix = 0;
    while a0 < a1 && b0 < b1 && a[a1 - 1] == b[b1 - 1] {
        a1 -= 1;
        b1 -= 1;
        suffix += 1;
    }
    if a0 == a1 {
        out.extend((b0..b1).map(Op::Insert));
    } else if b0 == b1 {
        out.extend((a0..a1).map(Op::Delete));
    } else {
        let (x, y) = middle_snake(a, a0, a1, b, b0, b1, vf, vb);
        conquer(a, a0, x, b, b0, y, vf, vb, out);
        conquer(a, x, a1, b, y, b1, vf, vb, out);
    }
    out.extend((0..suffix).map(|k| Op::Equal(a1 + k, b1 + k)));
}

/// A split point (x, y) on an optimal path through a[a0..a1] × b[b0..b1] (both non-empty),
/// found by running the forward and backward searches until they overlap.
fn middle_snake<T: PartialEq>(a: &[T], a0: usize, a1: usize, b: &[T], b0: usize, b1: usize,
                              vf: &mut [usize], vb: &mut [usize]) -> (usize, usize) {
    let n = (a1 - a0) as isize;
    let m = (b1 - b0) as isize;
    let delta = n - m;
    let odd = delta & 1 != 0;
    let off = (n + m + 1) as isize; // index offset for diagonal k
    let at = |k: isize| (k + off) as usize;
    vf[at(1)] = 0;
    vb[at(1)] = 0;
    let d_max = (n + m + 1) / 2;
    for d in 0..=d_max {
        // forward: furthest x on each diagonal k = x - y
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && vf[at(k - 1)] < vf[at(k + 1)]) { vf[at(k + 1)] as isize } else { vf[at(k - 1)] as isize + 1 };
            let mut y = x - k;
            let (sx, sy) = (x, y);
            while x < n && y < m && a[a0 + x as usize] == b[b0 + y as usize] {
                x += 1;
                y += 1;
            }
            vf[at(k)] = x as usize;
            let kb = delta - k; // the same diagonal in backward coordinates
            if odd && kb >= -(d - 1) && kb <= d - 1 && x + vb[at(kb)] as isize >= n {
                // split where this forward snake starts: a point on an optimal path
                return (a0 + sx as usize, b0 + sy as usize);
            }
            k += 2;
        }
        // backward: furthest distance from the end on each diagonal
        let mut k = -d;
        while k <= d {
            let mut x = if k == -d || (k != d && vb[at(k - 1)] < vb[at(k + 1)]) { vb[at(k + 1)] as isize } else { vb[at(k - 1)] as isize + 1 };
            let mut y = x - k;
            while x < n && y < m && a[a1 - 1 - x as usize] == b[b1 - 1 - y as usize] {
                x += 1;
                y += 1;
            }
            vb[at(k)] = x as usize;
            let kf = delta - k;
            if !odd && kf >= -d && kf <= d && x + vf[at(kf)] as isize >= n {
                return (a0 + (n - x) as usize, b0 + (m - y) as usize);
            }
            k += 2;
        }
    }
    // unreachable for non-empty inputs; split anywhere valid
    (a0 + 1, b0)
}

// ---- word comparison ---------------------------------------------------------------------

/// None when the items are too large for a word comparison (see `MAX_WORD_TOKENS`).
pub fn diff_words(a: &str, b: &str) -> Option<WordDiff> {
    let ta = tokenize(a);
    let tb = tokenize(b);
    if ta.len() + tb.len() > MAX_WORD_TOKENS {
        return None;
    }
    let ops = diff_ops(&ta, &tb);
    let mut out = WordDiff { a: Vec::new(), b: Vec::new(), changes: 0, change_lines: Vec::new() };
    let push = |spans: &mut Vec<Span>, change: Change, text: &str| match spans.last_mut() {
        Some(last) if last.change == change => last.text.push_str(text),
        _ => spans.push(Span { change, text: text.to_string() }),
    };
    let (mut line_a, mut line_b) = (0usize, 0usize);
    let mut i = 0;
    while i < ops.len() {
        if let Op::Equal(x, y) = ops[i] {
            push(&mut out.a, Change::Same, ta[x]);
            push(&mut out.b, Change::Same, tb[y]);
            line_a += ta[x].matches('\n').count();
            line_b += tb[y].matches('\n').count();
            i += 1;
            continue;
        }
        // a run of changes, up to the next equal token
        let start = i;
        while i < ops.len() && !matches!(ops[i], Op::Equal(..)) {
            i += 1;
        }
        let run = &ops[start..i];
        let dels: Vec<&str> = run.iter().filter_map(|o| if let Op::Delete(x) = o { Some(ta[*x]) } else { None }).collect();
        let ins: Vec<&str> = run.iter().filter_map(|o| if let Op::Insert(y) = o { Some(tb[*y]) } else { None }).collect();
        // whitespace-only changes still count, but a pure layout change reads better as such
        let (ca, cb) = match (dels.is_empty(), ins.is_empty()) {
            (false, false) => (Change::Modified, Change::Modified),
            (false, true) => (Change::Deleted, Change::Same),
            _ => (Change::Same, Change::Inserted),
        };
        out.changes += 1;
        out.change_lines.push((line_a, line_b));
        for t in &dels {
            push(&mut out.a, ca, t);
            line_a += t.matches('\n').count();
        }
        for t in &ins {
            push(&mut out.b, cb, t);
            line_b += t.matches('\n').count();
        }
    }
    Some(out)
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
    /// Diff `a` and `b` word by word off the UI thread (Myers is O((N+M)·D): large, very
    /// different items take long enough to freeze the window).
    fn start(a: Vec<u8>, b: Vec<u8>) -> Self {
        let slot = std::sync::Arc::new(std::sync::OnceLock::new());
        let out = slot.clone();
        std::thread::spawn(move || {
            let (a, b) = (String::from_utf8_lossy(&a), String::from_utf8_lossy(&b));
            let res = diff_words(&a, &b).ok_or_else(|| {
                format!("These items are too large for a word comparison (over {MAX_WORD_TOKENS} words and symbols). Compare bytes instead.")
            });
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
}

impl DiffView {
    pub fn new(a: ComparerItem, b: ComparerItem, mode: DiffMode) -> Self {
        let mut v = DiffView { mode, a, b, words: None, words_job: None, bytes: None, current: None };
        v.set_mode(mode);
        v
    }

    pub fn set_mode(&mut self, mode: DiffMode) {
        self.mode = mode;
        self.current = None;
        match mode {
            DiffMode::Words if self.words.is_none() && self.words_job.is_none() => {
                self.words_job = Some(WordJob::start(self.a.data.clone(), self.b.data.clone()));
                self.poll();
            }
            DiffMode::Bytes if self.bytes.is_none() => self.bytes = Some(diff_bytes(&self.a.data, &self.b.data)),
            _ => {}
        }
    }

    /// Take the background word comparison's result if it's done. True while it's running.
    pub fn poll(&mut self) -> bool {
        let Some(job) = &self.words_job else { return false };
        match job.0.get() {
            Some(res) => {
                self.words = Some(res.clone());
                self.words_job = None;
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

    /// LCS length by dynamic programming, to check Myers finds an optimal script.
    fn lcs_len<T: PartialEq>(a: &[T], b: &[T]) -> usize {
        let mut t = vec![vec![0usize; b.len() + 1]; a.len() + 1];
        for i in (0..a.len()).rev() {
            for j in (0..b.len()).rev() {
                t[i][j] = if a[i] == b[j] { t[i + 1][j + 1] + 1 } else { t[i + 1][j].max(t[i][j + 1]) };
            }
        }
        t[0][0]
    }

    fn check_script(a: &[u8], b: &[u8]) {
        let ops = diff_ops(a, b);
        // the script consumes each side in order, and equal pairs are equal
        let (mut i, mut j) = (0, 0);
        for op in &ops {
            match *op {
                Op::Equal(x, y) => { assert_eq!((x, y), (i, j)); assert_eq!(a[x], b[y]); i += 1; j += 1; }
                Op::Delete(x) => { assert_eq!(x, i); i += 1; }
                Op::Insert(y) => { assert_eq!(y, j); j += 1; }
            }
        }
        assert_eq!((i, j), (a.len(), b.len()), "{a:?} {b:?}");
        let equal = ops.iter().filter(|o| matches!(o, Op::Equal(..))).count();
        assert_eq!(equal, lcs_len(a, b), "not optimal for {a:?} / {b:?}");
    }

    #[test]
    fn myers_is_correct_and_optimal() {
        for (a, b) in [("", ""), ("abc", ""), ("", "abc"), ("abc", "abc"), ("abcabba", "cbabac"), ("kitten", "sitting"),
                       ("aaaa", "aa"), ("ab", "ba"), ("xaxbxc", "abc"), ("the quick brown fox", "the quick red fox jumps")] {
            check_script(a.as_bytes(), b.as_bytes());
        }
        // many small random cases over a tiny alphabet (lots of repeats: the hard case)
        let mut seed = 0x2545_f491_u64;
        let mut next = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
        for _ in 0..400 {
            let la = (next() % 12) as usize;
            let lb = (next() % 12) as usize;
            let a: Vec<u8> = (0..la).map(|_| b'a' + (next() % 3) as u8).collect();
            let b: Vec<u8> = (0..lb).map(|_| b'a' + (next() % 3) as u8).collect();
            check_script(&a, &b);
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
        let big = "w ".repeat(MAX_WORD_TOKENS);
        assert!(diff_words(&big, "w").is_none());
        // a long, mostly-equal input is fast (only the difference is searched)
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
