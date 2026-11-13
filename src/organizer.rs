//! The Organizer's data model: collections, the filter and sort state of its table, and the
//! facts it reads off a stored message.
//!
//! The UI is in `ui_organizer`. Everything here is a plain value or a pure function over
//! one, so what the table shows and what a row stands for can be tested without drawing it.

use crate::state::{OrgItem, OrgStatus};
use crate::theme::HIGHLIGHTS;

/// The collection every item arrives in, which cannot be renamed or deleted. Its id is fixed:
/// an item saved before collections existed has no collection of its own and reads back as
/// this one.
pub const INBOX: usize = 0;

/// What the default collection is called.
pub const INBOX_NAME: &str = "Inbox";

/// A named collection of items. Only its id identifies it: renaming one keeps every item in
/// it, and ids are never reused, so a deleted collection cannot take items with it.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OrgCollection {
    pub id: usize,
    pub name: String,
}

/// The collections a project starts with: the inbox alone.
pub fn default_collections() -> Vec<OrgCollection> {
    vec![OrgCollection { id: INBOX, name: INBOX_NAME.into() }]
}

/// Which column the table is sorted by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrgSortColumn {
    Index,
    Status,
    Highlight,
    Method,
    Host,
    Path,
    StatusCode,
    Length,
}

/// What the Organizer's table shows: the search box, the filter toggles above it, and the
/// column it is sorted by.
#[derive(Clone, Debug, PartialEq)]
pub struct OrgView {
    /// Matched against an item's host, path and notes, ignoring case.
    pub search: String,
    pub only_highlighted: bool,
    pub only_notes: bool,
    /// The one status being shown, or `None` for all of them.
    pub status: Option<OrgStatus>,
    pub sort_column: Option<OrgSortColumn>,
    pub sort_ascending: bool,
}

impl Default for OrgView {
    fn default() -> Self {
        Self {
            search: String::new(),
            only_highlighted: false,
            only_notes: false,
            status: None,
            // the order items arrived in, which is what an untouched table shows
            sort_column: Some(OrgSortColumn::Index),
            sort_ascending: true,
        }
    }
}

impl OrgView {
    /// Click on a column header: the same column flips the order, another one sorts by it
    /// ascending. The same rule the traffic tables follow.
    pub fn click_column(&mut self, col: OrgSortColumn) {
        if self.sort_column == Some(col) {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = Some(col);
            self.sort_ascending = true;
        }
    }

    /// Is any filter narrowing what is shown?
    pub fn is_filtering(&self) -> bool {
        !self.search.trim().is_empty() || self.only_highlighted || self.only_notes || self.status.is_some()
    }

    /// Does this item pass the filters? The collection is not one of them: that is the
    /// sidebar's business, and [`rows`] applies it.
    pub fn matches(&self, it: &OrgItem) -> bool {
        if self.only_highlighted && it.highlight.is_none() {
            return false;
        }
        if self.only_notes && it.note.trim().is_empty() {
            return false;
        }
        if self.status.is_some_and(|want| want != it.status) {
            return false;
        }
        let q = self.search.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        format!("{}{} {}", it.host, it.path, it.note).to_lowercase().contains(&q)
    }
}

/// Is this item one of the kinds the Organizer leaves out of its table -- a script, a
/// stylesheet, an image? Judged by the file extension of its path, as
/// `rules::ORGANIZER_HIDE_EXTENSIONS` lists them.
pub fn hidden_by_extension(it: &OrgItem) -> bool {
    it.path.contains('.')
        && it.path.rsplit('.').next().is_some_and(|e| {
            let e = e.split(['?', '#']).next().unwrap_or(e).to_lowercase();
            crate::rules::ORGANIZER_HIDE_EXTENSIONS.contains(&e.as_str())
        })
}

/// The rows the table shows, as indices into `items`: the ones in this collection that pass
/// the filters, in the order the sort asks for.
///
/// Every row the table draws comes from here, and a row stands for `items[index]` however the
/// table is sorted or filtered -- which is what keeps a click on a row, the detail pane under
/// it and an edit made from either one all pointing at the same item.
pub fn rows(items: &[OrgItem], collection: usize, view: &OrgView) -> Vec<usize> {
    let mut rows: Vec<usize> = items
        .iter()
        .enumerate()
        .filter(|(_, it)| it.collection == collection && !hidden_by_extension(it) && view.matches(it))
        .map(|(i, _)| i)
        .collect();
    if let Some(col) = view.sort_column {
        sort_rows(items, &mut rows, col, view.sort_ascending);
    }
    rows
}

/// Sort row indices by `col`, falling back to the order the items arrived in so that equal
/// values keep a fixed order whichever way the column is sorted.
fn sort_rows(items: &[OrgItem], rows: &mut [usize], col: OrgSortColumn, ascending: bool) {
    let rank = |st: OrgStatus| OrgStatus::ALL.iter().position(|s| *s == st).unwrap_or(0);
    let text = |a: &str, b: &str| a.to_lowercase().cmp(&b.to_lowercase());
    rows.sort_by(|&x, &y| {
        let (a, b) = (&items[x], &items[y]);
        let primary = match col {
            OrgSortColumn::Index => x.cmp(&y),
            OrgSortColumn::Status => rank(a.status).cmp(&rank(b.status)),
            // unhighlighted items first, then the colours in the order the palette lists them
            OrgSortColumn::Highlight => a.highlight.map_or(0, |h| h + 1).cmp(&b.highlight.map_or(0, |h| h + 1)),
            OrgSortColumn::Method => text(&a.method, &b.method),
            OrgSortColumn::Host => text(&a.host, &b.host),
            OrgSortColumn::Path => text(&a.path, &b.path),
            OrgSortColumn::StatusCode => match (status_code(&a.response), status_code(&b.response)) {
                (Some(i), Some(j)) => i.cmp(&j),
                // an item with no response at all sorts last, either way round
                (Some(_), None) => return std::cmp::Ordering::Less,
                (None, Some(_)) => return std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            },
            OrgSortColumn::Length => body_length(&a.response).cmp(&body_length(&b.response)),
        };
        let primary = if ascending { primary } else { primary.reverse() };
        primary.then(x.cmp(&y))
    });
}

/// The status a stored response reports, without its version: "404 Not Found". Empty when the
/// item has no response, and the same either way round for a response recorded with a version
/// on its status line and one recorded before the tools wrote it.
pub fn status_text(response: &str) -> String {
    let first = response.lines().next().unwrap_or("").trim();
    if first.is_empty() {
        return String::new();
    }
    match first.split_once(' ') {
        Some((version, rest)) if version.starts_with("HTTP/") => rest.trim().to_string(),
        _ => first.to_string(),
    }
}

/// The status code of a stored response, or `None` when it has none to read.
pub fn status_code(response: &str) -> Option<u16> {
    crate::http::status_code(&status_text(response))
}

/// How long a stored response's body is, in bytes: what follows the blank line that ends the
/// head. A response with no blank line in it has no body to measure.
pub fn body_length(response: &str) -> usize {
    response.split_once("\n\n").map_or(0, |(_, body)| body.len())
}

/// The name of an item's highlight, as the dropdown shows it.
pub fn highlight_name(highlight: Option<usize>) -> &'static str {
    highlight.and_then(|h| HIGHLIGHTS.get(h)).map_or("None", |(name, _)| name)
}

/// The id to give the next item, which is one past the highest in use. Ids are never reused,
/// so a selection cannot come to mean a different item after a removal.
pub fn next_item_id(items: &[OrgItem]) -> usize {
    items.iter().map(|it| it.id).max().unwrap_or(0) + 1
}

/// Give every item an id of its own, for items read from a project saved before they had one
/// (they all read back as 0). Items that already have distinct ids are left as they are.
pub fn renumber(items: &mut [OrgItem]) {
    let mut seen = std::collections::HashSet::new();
    if items.iter().all(|it| it.id != 0 && seen.insert(it.id)) {
        return;
    }
    for (i, it) in items.iter_mut().enumerate() {
        it.id = i + 1;
    }
}

/// Put every collection an item names back in the list, for items read from a project whose
/// collections did not survive -- an item cannot be left pointing at a collection that is not
/// there, or it would be in the table of none of them.
pub fn adopt_orphans(items: &mut [OrgItem], collections: &mut Vec<OrgCollection>) {
    if collections.is_empty() {
        *collections = default_collections();
    }
    for it in items.iter_mut() {
        if !collections.iter().any(|c| c.id == it.collection) {
            it.collection = INBOX;
        }
    }
}

/// Add a collection under this name, trimmed, and return its id. A name nobody typed gets a
/// plain one rather than no name at all; ids count up from the highest ever used, so an id is
/// never handed out twice even after a deletion.
pub fn add_collection(collections: &mut Vec<OrgCollection>, name: &str) -> usize {
    let id = collections.iter().map(|c| c.id).max().unwrap_or(INBOX) + 1;
    let name = name.trim();
    let name = if name.is_empty() { format!("Collection {id}") } else { name.to_string() };
    collections.push(OrgCollection { id, name });
    id
}

/// Rename a collection. The inbox keeps its name, being where everything arrives, and a name
/// of nothing but spaces is not a name.
pub fn rename_collection(collections: &mut [OrgCollection], id: usize, name: &str) -> bool {
    if id == INBOX || name.trim().is_empty() {
        return false;
    }
    match collections.iter_mut().find(|c| c.id == id) {
        Some(c) => {
            c.name = name.trim().to_string();
            true
        }
        None => false,
    }
}

/// Delete a collection, moving everything that was in it back to the inbox. The inbox itself
/// cannot be deleted. Returns how many items were moved, so the UI can say what became of
/// them -- deleting a collection never throws an item away.
pub fn delete_collection(items: &mut [OrgItem], collections: &mut Vec<OrgCollection>, id: usize) -> Option<usize> {
    if id == INBOX || !collections.iter().any(|c| c.id == id) {
        return None;
    }
    collections.retain(|c| c.id != id);
    let mut moved = 0;
    for it in items.iter_mut().filter(|it| it.collection == id) {
        it.collection = INBOX;
        moved += 1;
    }
    Some(moved)
}

/// How many items are in each collection, whatever the filters are hiding: the sidebar counts
/// what a collection holds, not what is on screen.
pub fn count_in(items: &[OrgItem], collection: usize) -> usize {
    items.iter().filter(|it| it.collection == collection).count()
}

/// Move the item with this id into a collection. `false` when there is no such item, or no
/// such collection to move it to.
pub fn move_to(items: &mut [OrgItem], id: usize, collection: usize, collections: &[OrgCollection]) -> bool {
    if !collections.iter().any(|c| c.id == collection) {
        return false;
    }
    match items.iter_mut().find(|it| it.id == id) {
        Some(it) => {
            it.collection = collection;
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::assert_table;

    /// An item with the bits the table reads, and nothing else.
    fn item(id: usize, host: &str, path: &str, response: &str) -> OrgItem {
        OrgItem {
            id,
            collection: INBOX,
            method: "GET".into(),
            host: host.into(),
            path: path.into(),
            note: String::new(),
            highlight: None,
            status: OrgStatus::New,
            request: format!("GET {path} HTTP/1.1\nHost: {host}\n\n"),
            response: response.into(),
            url: format!("http://{host}{path}"),
        }
    }

    fn ok(body: &str) -> String {
        format!("HTTP/1.1 200 OK\ncontent-length: {}\n\n{body}", body.len())
    }

    /// A row stands for one item whatever the table is sorted by or filtered to, which is what
    /// the detail pane, the inline editors and the row actions all depend on.
    #[test]
    fn rows_are_filtered_and_sorted_and_still_point_at_their_own_item_matrix() {
        let mut items = vec![
            item(1, "shop.test", "/cart", &ok("one")),
            item(2, "api.test", "/v1/users", "HTTP/1.1 404 Not Found\n\n"),
            item(3, "shop.test", "/pay", &ok("a longer body")),
            item(4, "cdn.test", "/logo.png", &ok("binary")),
        ];
        items[1].status = OrgStatus::Done;
        items[1].note = "needs a second look".into();
        items[2].highlight = Some(0);

        struct Case {
            name: &'static str,
            view: OrgView,
            /// The ids of the items the table shows, in the order it shows them.
            want: Vec<usize>,
        }
        let view = |f: fn(&mut OrgView)| {
            let mut v = OrgView::default();
            f(&mut v);
            v
        };
        let cases = [
            Case {
                name: "nothing filtered, in the order they arrived -- and no image among them",
                view: OrgView::default(),
                want: vec![1, 2, 3],
            },
            Case {
                name: "the order they arrived in, reversed",
                view: view(|v| v.sort_ascending = false),
                want: vec![3, 2, 1],
            },
            Case {
                name: "by host",
                view: view(|v| v.sort_column = Some(OrgSortColumn::Host)),
                want: vec![2, 1, 3],
            },
            Case {
                name: "by status code, and the one with no body length last",
                view: view(|v| v.sort_column = Some(OrgSortColumn::StatusCode)),
                want: vec![1, 3, 2],
            },
            Case {
                name: "by length",
                view: view(|v| v.sort_column = Some(OrgSortColumn::Length)),
                want: vec![2, 1, 3],
            },
            Case {
                name: "by status, which is the order the dropdown lists them in",
                view: view(|v| v.sort_column = Some(OrgSortColumn::Status)),
                want: vec![1, 3, 2],
            },
            Case {
                name: "by highlight, unhighlighted first",
                view: view(|v| v.sort_column = Some(OrgSortColumn::Highlight)),
                want: vec![1, 2, 3],
            },
            Case {
                name: "searching the address",
                view: view(|v| v.search = "shop".into()),
                want: vec![1, 3],
            },
            Case {
                name: "searching the notes, which the address does not hold",
                view: view(|v| v.search = "second look".into()),
                want: vec![2],
            },
            Case {
                name: "only the highlighted",
                view: view(|v| v.only_highlighted = true),
                want: vec![3],
            },
            Case {
                name: "only those with notes",
                view: view(|v| v.only_notes = true),
                want: vec![2],
            },
            Case {
                name: "one status",
                view: view(|v| v.status = Some(OrgStatus::Done)),
                want: vec![2],
            },
            Case {
                name: "a status nothing is in",
                view: view(|v| v.status = Some(OrgStatus::Ignored)),
                want: vec![],
            },
            Case {
                name: "filters together, narrowing to nothing",
                view: view(|v| {
                    v.search = "shop".into();
                    v.only_notes = true;
                }),
                want: vec![],
            },
        ];
        assert_table!(cases, |idx, case| {
            let rows = rows(&items, INBOX, &case.view);
            let got: Vec<usize> = rows.iter().map(|&i| items[i].id).collect();
            assert_eq!(got, case.want, "case #{idx} ({})", case.name);
            // and every row points at an item that really is in the table
            for &i in &rows {
                assert!(i < items.len(), "case #{idx} ({}): row {i} is out of range", case.name);
                assert!(case.view.matches(&items[i]), "case #{idx} ({}): row {i} does not pass the filters", case.name);
            }
        });
    }

    /// What the table reads off a stored response, including the forms a project saved before
    /// the tools wrote a version on the status line holds.
    #[test]
    fn the_table_reads_a_status_and_a_length_off_a_stored_response_matrix() {
        let cases: [(&str, &str, &str, Option<u16>, usize); 6] = [
            ("a response as the tools record one now", "HTTP/1.1 404 Not Found\nserver: x\n\nnot there", "404 Not Found", Some(404), 9),
            ("one recorded before the version was written", "200 OK\nserver: x\n\nok", "200 OK", Some(200), 2),
            ("a tunnel, which has a code but no body", "HTTP/1.1 200 Connection established\n\n", "200 Connection established", Some(200), 0),
            ("a failed connection, which has neither", "— (transport error)\n\nRequest failed: nope", "— (transport error)", None, 20),
            ("no response at all", "", "", None, 0),
            ("a head with no blank line under it", "HTTP/1.1 204 No Content\ncontent-length: 0", "204 No Content", Some(204), 0),
        ];
        assert_table!(cases, |idx, (what, response, text, code, length)| {
            assert_eq!(status_text(response), text, "case #{idx} ({what}): the status");
            assert_eq!(status_code(response), code, "case #{idx} ({what}): the code");
            assert_eq!(body_length(response), length, "case #{idx} ({what}): the body length");
        });
    }

    /// Collections are made, renamed and deleted by id, and deleting one puts what was in it
    /// back in the inbox: the one thing that must never happen is an item going missing with
    /// the collection that held it.
    #[test]
    fn collections_are_kept_by_id_and_deleting_one_re_homes_its_items() {
        let mut collections = default_collections();
        let mut items = vec![item(1, "a.test", "/one", ""), item(2, "b.test", "/two", ""), item(3, "c.test", "/three", "")];

        let auth = add_collection(&mut collections, "  Auth flows  ");
        let payments = add_collection(&mut collections, "Payments");
        assert_eq!(collections.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), [INBOX_NAME, "Auth flows", "Payments"], "trimmed, in the order they were made");

        assert!(move_to(&mut items, 1, auth, &collections));
        assert!(move_to(&mut items, 2, auth, &collections));
        assert!(!move_to(&mut items, 9, auth, &collections), "no such item");
        assert!(!move_to(&mut items, 3, 404, &collections), "no such collection");
        assert_eq!(items[2].collection, INBOX, "and the item it could not move stayed where it was");
        assert_eq!((count_in(&items, auth), count_in(&items, INBOX), count_in(&items, payments)), (2, 1, 0));

        // renaming keeps the items: a collection is its id, not its name
        assert!(rename_collection(&mut collections, auth, " Login "));
        assert_eq!(collections[1].name, "Login");
        assert_eq!(count_in(&items, auth), 2, "the items are still in it");
        assert!(!rename_collection(&mut collections, INBOX, "Everything"), "the inbox keeps its name");
        assert!(!rename_collection(&mut collections, auth, "   "), "and a name of nothing is not a name");
        assert_eq!(collections[1].name, "Login");

        // deleting it moves its items back to the inbox rather than taking them along
        assert_eq!(delete_collection(&mut items, &mut collections, auth), Some(2), "both items were moved");
        assert_eq!(collections.iter().map(|c| c.id).collect::<Vec<_>>(), vec![INBOX, payments]);
        assert_eq!(count_in(&items, INBOX), 3, "everything is back in the inbox");
        assert_eq!(items.len(), 3, "and nothing was thrown away");
        assert_eq!(delete_collection(&mut items, &mut collections, INBOX), None, "the inbox cannot be deleted");
        assert_eq!(delete_collection(&mut items, &mut collections, 404), None, "nor can a collection that is not there");

        // an id is never handed out twice, so the selection cannot land on the wrong one
        let next = add_collection(&mut collections, "Later");
        assert!(next > payments && next != auth, "a new collection takes an id of its own ({next})");
    }

    /// A project saved before items had ids of their own reads them all back as 0, and one
    /// saved before collections existed leaves every item pointing at a collection that is not
    /// in the file. Neither may leave an item unreachable.
    #[test]
    fn items_from_an_older_project_are_given_ids_and_a_collection_matrix() {
        struct Case {
            name: &'static str,
            ids: Vec<usize>,
            want: Vec<usize>,
        }
        let cases = [
            Case { name: "no ids at all", ids: vec![0, 0, 0], want: vec![1, 2, 3] },
            Case { name: "ids that repeat", ids: vec![1, 1, 2], want: vec![1, 2, 3] },
            Case { name: "ids of their own are left alone", ids: vec![7, 3, 9], want: vec![7, 3, 9] },
        ];
        assert_table!(cases, |idx, case| {
            let mut items: Vec<OrgItem> = case.ids.iter().map(|&id| item(id, "a.test", "/x", "")).collect();
            renumber(&mut items);
            assert_eq!(items.iter().map(|it| it.id).collect::<Vec<_>>(), case.want, "case #{idx} ({})", case.name);
            let mut ids = std::collections::HashSet::new();
            assert!(items.iter().all(|it| it.id != 0 && ids.insert(it.id)), "case #{idx} ({}): every item has an id of its own", case.name);
            assert_eq!(next_item_id(&items), case.want.iter().max().unwrap() + 1, "case #{idx} ({})", case.name);
        });

        // a collection nothing knows about: the item goes back to the inbox
        let mut items = vec![item(1, "a.test", "/x", ""), item(2, "b.test", "/y", "")];
        items[0].collection = 12;
        let mut collections = Vec::new();
        adopt_orphans(&mut items, &mut collections);
        assert_eq!(collections, default_collections(), "the inbox is put back first");
        assert_eq!(items[0].collection, INBOX, "and the orphan is in it");
        assert_eq!(count_in(&items, INBOX), 2);
    }
}
