//! Target > Site map: the hierarchical tree of everything seen (left), the requests under the
//! selected branch (right, top) and the request/response viewer for the selected row (right,
//! bottom). The tree engine is [`crate::target`]; scope configuration stays in ui_tools'
//! `target_scope` view, and both share [`crate::scope::TargetScope`].

use crate::actions;
use crate::editor;
use crate::state::App;
use crate::target::SiteMapNode;
use crate::theme::{self, bold, Palette};
use crate::ui_core::method_color;
use eframe::egui;
use egui::{RichText, Ui};

/// A right-click choice on a tree node or table row, applied after drawing (drawing can't touch the app).
enum NodeAction {
    /// Add the node's origin to the target scope (via a representative request).
    AddHostToScope(usize),
    /// Send a request under the node to another tool.
    Send(usize, actions::SendTo),
    /// Copy the node's URL to the clipboard.
    CopyUrl(String),
}

/// A representative history id for a node: its own first, else the first found in a descendant.
fn first_id(node: &SiteMapNode) -> Option<usize> {
    node.history_ids.first().copied().or_else(|| node.children.values().find_map(first_id))
}

/// The node's right-click menu. Returns the choice; `apply_node_action` carries it out.
fn node_menu(ui: &mut Ui, node: &SiteMapNode) -> Option<NodeAction> {
    let mut pick = None;
    ui.label(RichText::new(&node.full_url).monospace().size(11.5));
    ui.separator();
    if let Some(id) = first_id(node) {
        if ui.button("Add host to scope").clicked() {
            pick = Some(NodeAction::AddHostToScope(id));
        }
        ui.separator();
        for (label, to) in crate::ui_tools::traffic_context_menu_targets(crate::state::Tab::Target) {
            if ui.button(label).clicked() {
                pick = Some(NodeAction::Send(id, to));
            }
            if to == actions::SendTo::Comparer {
                if ui.button("Send request to Comparer").clicked() {
                    pick = Some(NodeAction::Send(id, actions::SendTo::ComparerRequest));
                }
                if ui.button("Send response to Comparer").clicked() {
                    pick = Some(NodeAction::Send(id, actions::SendTo::Comparer));
                }
            }
        }
        ui.separator();
    }
    if ui.button("Copy URL").clicked() {
        pick = Some(NodeAction::CopyUrl(node.full_url.clone()));
    }
    if pick.is_some() {
        ui.close_menu();
    }
    pick
}

fn apply_node_action(app: &mut App, all: &[std::sync::Arc<crate::http::HttpEntry>], action: NodeAction, ctx: &egui::Context) {
    match action {
        NodeAction::AddHostToScope(id) => {
            if let Some(e) = all.iter().find(|e| e.id == id) {
                app.target_scope.add(&actions::scope_prefix(e));
            }
        }
        NodeAction::Send(id, to) => {
            if let Some(e) = all.iter().find(|e| e.id == id).cloned() {
                actions::send_to(app, &e, to);
            }
        }
        NodeAction::CopyUrl(url) => ctx.copy_text(url),
    }
}

/// One tree node and its subtree. Branches are `CollapsingHeader`s; leaves are selectable rows.
/// Out-of-scope nodes are dimmed, or left out altogether when the filter bar says so. Clicking
/// a node selects its branch for the right pane.
#[allow(clippy::too_many_arguments)]
fn draw_node(
    ui: &mut Ui,
    p: &Palette,
    node: &SiteMapNode,
    filter: crate::target::SiteMapFilter<'_>,
    selected: &Option<String>,
    default_open: bool,
    pick: &mut Option<String>,
    menu: &mut Option<NodeAction>,
) {
    if !filter.keeps(node) {
        return;
    }
    // everything under a node that matched the search text is shown, so searching for a host
    // does not then hide that host's own paths
    let below = if filter.hits(node) { filter.below_a_match() } else { filter };
    let col = if filter.scope.is_in_scope(&node.full_url) { p.strong } else { p.disabled };
    let is_sel = selected.as_deref() == Some(node.full_url.as_str());
    let label = RichText::new(&node.name).size(12.5).color(col).monospace();
    if node.children.is_empty() {
        let resp = ui.selectable_label(is_sel, label);
        if resp.clicked() {
            *pick = Some(node.full_url.clone());
        }
        resp.context_menu(|ui| {
            if let Some(a) = node_menu(ui, node) {
                *menu = Some(a);
            }
        });
    } else {
        let header = egui::CollapsingHeader::new(label)
            .id_salt(&node.full_url)
            .default_open(default_open)
            .show(ui, |ui| {
                for child in node.children.values() {
                    draw_node(ui, p, child, below, selected, false, pick, menu);
                }
            });
        if header.header_response.clicked() {
            *pick = Some(node.full_url.clone());
        }
        header.header_response.context_menu(|ui| {
            if let Some(a) = node_menu(ui, node) {
                *menu = Some(a);
            }
        });
    }
}

/// The site map's filter bar: a search box with a clear button, and a "Scope only" toggle.
/// Both narrow the tree and the requests listed beside it; neither touches what has been
/// recorded, and folders keep whatever expansion state they had.
fn filter_bar(app: &mut App, ui: &mut Ui, p: &Palette) {
    egui::Frame::new().fill(p.header).corner_radius(4.0).inner_margin(egui::Margin::symmetric(8, 4)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            ui.add(
                egui::TextEdit::singleline(&mut app.site_map_search)
                    .id_salt("site_map_search")
                    .hint_text("Filter site map...")
                    .desired_width(230.0),
            )
            .on_hover_text("Matches a host or path segment, and the full address, ignoring case");
            if ui
                .add_enabled(!app.site_map_search.is_empty(), egui::Button::new("×").frame(false))
                .on_hover_text("Clear the filter")
                .clicked()
            {
                app.site_map_search.clear();
            }
            ui.separator();
            if theme::pill(ui, p, "Scope only", app.site_map_scope_only)
                .on_hover_text("Hide hosts and folders with nothing inside Target > Scope under them")
                .clicked()
            {
                app.site_map_scope_only = !app.site_map_scope_only;
            }
        });
    });
    ui.add_space(4.0);
}

/// Site map request columns, as (minimum width, share of the spare width): #, Time, Method,
/// Host, Path, Status code, Length. Path takes the slack; below these minimums the table
/// scrolls sideways instead of cutting the last columns off. Status code is as wide as it is
/// in HTTP history, so "405 Method Not Allowed" reads in full.
pub(crate) const SITE_MAP_COLS: [(f32, f32); 7] = [(50.0, 0.0), (72.0, 0.0), (70.0, 0.0),
    (180.0, 0.0), (280.0, 1.0), (170.0, 0.0), (80.0, 0.0)];

pub fn site_map(app: &mut App, ui: &mut Ui, p: &Palette) {
    let all = app.history.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut pick_node: Option<String> = None;
    let mut menu: Option<NodeAction> = None;

    filter_bar(app, ui, p);
    // the panels below take `app` mutably, so the filter reads from copies taken here; the
    // rules are a handful of short strings, beside the history snapshot already cloned above
    let (scope, query) = (app.target_scope.clone(), app.site_map_search.clone());
    let filter = crate::target::SiteMapFilter { scope: &scope, scope_only: app.site_map_scope_only, query: &query };

    // the tree gives way as the window narrows: it keeps at most 60% of whatever width there
    // is, so the requests beside it always have room, and the splitter cannot be dragged past
    // either edge. On a window too narrow for the usual minimum, that minimum gives way too.
    let avail_w = ui.available_width().max(0.0);
    let tree_widest = (avail_w * 0.6).max(0.0);
    let tree_narrowest = 180.0_f32.min(tree_widest);
    egui::SidePanel::left("site_map_tree")
        .resizable(true)
        .default_width(300.0)
        .width_range(tree_narrowest..=tree_widest.max(tree_narrowest))
        .frame(egui::Frame::new().fill(p.deep).inner_margin(egui::Margin::same(6)))
        .show_inside(ui, |ui| {
            ui.label(bold("Site map", 13.0).color(p.strong));
            ui.add_space(4.0);
            egui::ScrollArea::vertical().id_salt("site_map_scroll").auto_shrink([false, false]).show(ui, |ui| {
                if app.site_map.roots.is_empty() {
                    ui.label(RichText::new("No requests recorded yet.").size(12.0).color(p.disabled));
                }
                let shown = app.site_map.roots.values().filter(|r| filter.keeps(r)).count();
                for root in app.site_map.roots.values() {
                    draw_node(ui, p, root, filter, &app.target_selected_node, true, &mut pick_node, &mut menu);
                }
                if shown == 0 && !app.site_map.roots.is_empty() {
                    ui.label(RichText::new("Nothing here matches the filter.").size(12.0).color(p.disabled));
                }
            });
        });

    egui::CentralPanel::default().frame(egui::Frame::NONE).show_inside(ui, |ui| {
        // the requests filed under the selected branch
        let ids = app
            .target_selected_node
            .as_ref()
            .map(|n| app.site_map.collect_history_ids(n))
            .unwrap_or_default();
        let rows: Vec<std::sync::Arc<crate::http::HttpEntry>> = ids
            .iter()
            .filter_map(|id| all.iter().find(|e| e.id == *id))
            .filter(|e| filter.keeps_url(&actions::entry_url(e)))
            .cloned()
            .collect();

        // the detail viewer for the selected row, pinned to the bottom
        let detail = app
            .target_selected_history_id
            .and_then(|id| all.iter().find(|e| e.id == id))
            .cloned();
        if let Some(e) = detail {
            // same again downwards: the viewer takes at most 70% of the height on offer, so
            // the table above it never ends up with less than no room
            let avail_h = ui.available_height().max(0.0);
            let detail_tallest = (avail_h * 0.7).max(0.0);
            let detail_shortest = 100.0_f32.min(detail_tallest);
            egui::TopBottomPanel::bottom("site_map_detail")
                .resizable(true)
                .default_height(260.0)
                .height_range(detail_shortest..=detail_tallest.max(detail_shortest))
                .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::same(6)))
                .show_inside(ui, |ui| {
                    // the address on its own line, truncated rather than pushing the buttons
                    // off the edge of a narrow window
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("#{} ", e.id)).color(p.text));
                        ui.add(egui::Label::new(RichText::new(actions::entry_url(&e)).monospace().size(11.5).color(p.disabled)).truncate());
                    });
                    // and the buttons wrapped, so a narrow window gets more rows of them
                    ui.horizontal_wrapped(|ui| {
                        if theme::plain_button(ui, p, "Send to Repeater", true).clicked() {
                            actions::send_to(app, &e, actions::SendTo::Repeater);
                        }
                        if theme::plain_button(ui, p, "Send to Intruder", true).clicked() {
                            actions::send_to(app, &e, actions::SendTo::Intruder);
                        }
                        if theme::plain_button(ui, p, "Send to Sequencer", true).clicked() {
                            actions::send_to(app, &e, actions::SendTo::Sequencer);
                        }
                        if theme::plain_button(ui, p, "Send to Comparer", true).clicked() {
                            actions::send_to(app, &e, actions::SendTo::Comparer);
                        }
                        if theme::plain_button(ui, p, "Send to Decoder", true).clicked() {
                            actions::send_to(app, &e, actions::SendTo::Decoder);
                        }
                        if theme::plain_button(ui, p, "Send to Organizer", true).clicked() {
                            actions::send_to(app, &e, actions::SendTo::Organizer);
                        }
                    });
                    ui.add_space(2.0);
                    let name = format!("{} #{}", actions::history_name(&e), e.id);
                    // the viewers fill the panel as the user drags it, instead of standing at
                    // a fixed height that a short panel would have to cut off
                    let view_h = (ui.available_height() - 2.0).max(40.0);
                    let (out_req, out_resp) = theme::columns(ui, 2, |cols| {
                        cols[0].label(bold("Request", 13.0).color(p.strong));
                        let req_v = editor::message_view(&mut cols[0], p, "sm_req", &e.request, view_h);
                        cols[1].label(bold("Response", 13.0).color(p.strong));
                        let resp_v = editor::message_view(&mut cols[1], p, "sm_resp", &e.response, view_h);
                        (req_v, resp_v)
                    });
                    let e_url = actions::entry_url(&e);
                    let e_req = actions::raw_request(&e);
                    crate::ui_tools::attach_view_context_menu(&out_req, &e.request, app, crate::state::Tab::Target, &e_url, &e_req, Some(&e.response), &format!("{name} request"));
                    crate::ui_tools::attach_view_context_menu(&out_resp, &e.response, app, crate::state::Tab::Target, &e_url, &e_req, Some(&e.response), &format!("{name} response"));
                });
        }

        egui::CentralPanel::default().frame(egui::Frame::NONE).show_inside(ui, |ui| {
            if app.target_selected_node.is_none() {
                ui.add_space(8.0);
                ui.label(RichText::new("Select a node in the tree to see its requests.").size(12.5).color(p.disabled));
                return;
            }
            // as tall as the space the viewer below has left, never taller
            let table_h = ui.available_height().max(0.0);
            theme::fitted_table(ui, p, "site_map_table", table_h, &SITE_MAP_COLS, |ui, w| {
                use crate::history::time_of_day;
                theme::table_header(ui, p, &[("#", w[0]), ("Time", w[1]), ("Method", w[2]), ("Host", w[3]), ("Path", w[4]), ("Status code", w[5]), ("Length", w[6])]);
                let sel = app.target_selected_history_id;
                let mut clicked = None;
                egui::ScrollArea::vertical().id_salt("site_map_rows").show_rows(ui, 19.0, rows.len(), |ui, range| {
                    for (i, e) in rows.iter().enumerate().skip(range.start).take(range.len()) {
                        let cells = [
                            (e.id.to_string(), w[0], None),
                            (time_of_day(e.time), w[1], Some(p.disabled)),
                            (e.method.clone(), w[2], Some(method_color(p, &e.method))),
                            (e.host.clone(), w[3], None),
                            (e.path.clone(), w[4], None),
                            (e.status.clone(), w[5], None),
                            (e.length.to_string(), w[6], None),
                        ];
                        let row = theme::table_row(ui, p, &cells, sel == Some(e.id), i % 2 == 1);
                        if row.clicked() {
                            clicked = Some(e.id);
                        }
                        row.context_menu(|ui| {
                            for (label, to) in crate::ui_tools::traffic_context_menu_targets(crate::state::Tab::Target) {
                                if ui.button(label).clicked() {
                                    menu = Some(NodeAction::Send(e.id, to));
                                    ui.close_menu();
                                }
                                if to == actions::SendTo::Comparer {
                                    if ui.button("Send request to Comparer").clicked() {
                                        menu = Some(NodeAction::Send(e.id, actions::SendTo::ComparerRequest));
                                        ui.close_menu();
                                    }
                                    if ui.button("Send response to Comparer").clicked() {
                                        menu = Some(NodeAction::Send(e.id, actions::SendTo::Comparer));
                                        ui.close_menu();
                                    }
                                }
                            }
                            ui.separator();
                            if ui.button("Copy as cURL").clicked() {
                                ui.ctx().copy_text(actions::entry_as_curl(e));
                                ui.close_menu();
                            }
                            if ui.button("Copy URL").clicked() {
                                ui.ctx().copy_text(actions::entry_url(e));
                                ui.close_menu();
                            }
                        });
                    }
                });
                if let Some(id) = clicked {
                    app.target_selected_history_id = if sel == Some(id) { None } else { Some(id) };
                }
            });
        });
    });

    if let Some(n) = pick_node {
        let changed = app.target_selected_node.as_deref() != Some(n.as_str());
        app.target_selected_node = Some(n);
        if changed {
            app.target_selected_history_id = None;
        }
    }
    if let Some(a) = menu {
        apply_node_action(app, &all, a, ui.ctx());
    }
}

#[cfg(test)]
mod layout_tests {
    use crate::state::Tab;
    use crate::test_utils::{assert_table, HttpFixture, MockAppBuilder};
    use eframe::egui;

    /// The Target tab with a site map, a selected branch and a selected row, so the tree, the
    /// table and the request/response viewer are all on screen at once.
    fn target_app() -> (egui::Context, crate::state::App) {
        let entry = HttpFixture::get("shop.test", "/api/v1/orders?page=2")
            .with_response("200 OK", r#"{"orders":[]}"#)
            .into_history_entry(1, "Proxy");
        let (ctx, mut app) = MockAppBuilder::new().with_tab(Tab::Target).with_history_entry(entry).build_with_ctx();
        crate::actions::sync_site_map(&mut app);
        app.target_selected_node = app.site_map.roots.keys().next().cloned();
        app.target_selected_history_id = Some(1);
        (ctx, app)
    }

    /// Dragging the window down to nothing must not take the app with it. egui asserts on a
    /// negative width or height, so every size worked out from the space left has to stay at
    /// or above zero however little of it there is.
    #[test]
    fn the_target_tab_survives_a_window_squeezed_to_nothing() {
        let sizes: [(f32, f32); 6] = [(1400.0, 800.0), (400.0, 300.0), (200.0, 200.0), (100.0, 100.0), (50.0, 50.0), (1.0, 1.0)];
        assert_table!(sizes, |idx, (w, h)| {
            let (ctx, mut app) = target_app();
            for _ in 0..2 {
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(w, h))),
                    ..Default::default()
                };
                let _ = ctx.run(input.clone(), |ctx| crate::ui_core::frame(&mut app, ctx));
            }
            assert_eq!(app.tab, Tab::Target, "case #{idx} ({w}x{h}): still on the Target tab");
        });
    }

    /// The crash was in a helper every table in the app draws through, so every tab is worth
    /// the same squeeze, at the smallest size and with something selected to draw.
    #[test]
    fn every_tab_survives_a_window_squeezed_to_nothing() {
        assert_table!(Tab::ALL, |idx, tab| {
            let (ctx, mut app) = target_app();
            app.tab = tab;
            for size in [egui::vec2(1400.0, 800.0), egui::vec2(50.0, 50.0), egui::vec2(1.0, 1.0)] {
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    ..Default::default()
                };
                let _ = ctx.run(input, |ctx| crate::ui_core::frame(&mut app, ctx));
            }
            assert_eq!(app.tab, tab, "case #{idx} ({}): drawn at every size", tab.label());
        });
    }

    /// The sub-tabs and the floating windows draw through the same helpers, and are only
    /// reached by setting the state that opens them.
    #[test]
    fn the_sub_tabs_and_windows_survive_it_too() {
        struct Scene(&'static str, fn(&mut crate::state::App));
        let scenes = [
            Scene("Proxy > Intercept", |a| { a.tab = Tab::Proxy; a.proxy_sub = 0; }),
            Scene("Proxy > HTTP history", |a| { a.tab = Tab::Proxy; a.proxy_sub = 1; }),
            Scene("Proxy > Match and replace", |a| { a.tab = Tab::Proxy; a.proxy_sub = 2; }),
            Scene("Proxy > Proxy settings", |a| { a.tab = Tab::Proxy; a.proxy_sub = 3; }),
            Scene("Target > Scope", |a| { a.tab = Tab::Target; a.target_sub = 1; }),
            Scene("Target > Scope, advanced", |a| {
                a.tab = Tab::Target;
                a.target_sub = 1;
                a.target_scope.advanced = true;
                a.target_scope.include.push(crate::scope::ScopeRule {
                    protocol: crate::scope::ScopeProtocol::Https,
                    host: "^corp\\.test$".into(),
                    port: "^8443$".into(),
                    file: "^/api/".into(),
                    ..crate::scope::ScopeRule::new("")
                });
                // and one the engine cannot compile, which the table marks up
                a.target_scope.exclude.push(crate::scope::ScopeRule {
                    host: "^(unclosed".into(),
                    ..crate::scope::ScopeRule::new("")
                });
            }),
            Scene("Sequencer > Manual load", |a| {
                a.tab = Tab::Sequencer;
                a.seq_sub = 1;
                a.seq_paste = "a1b2\n\nc3d4\n".into();
            }),
            Scene("Sequencer > Analysis", |a| { a.tab = Tab::Sequencer; a.seq_sub = 2; }),
            Scene("the Intruder attack window", |a| { a.tab = Tab::Intruder; a.show_attack = true; }),
            Scene("the comparison window", |a| {
                a.tab = Tab::Comparer;
                let item = |id: usize, text: &str| crate::comparer::ComparerItem::from_text(id, format!("Item {id}"), text);
                a.comparer_active_diff = Some(crate::comparer::DiffView::new(
                    item(1, "{\"id\": 101}"),
                    item(2, "{\"id\": 102, \"debug\": 1}"),
                    crate::comparer::DiffMode::Bytes,
                ));
            }),
            Scene("the settings window", |a| a.show_settings = true),
            Scene("the command palette", |a| a.show_palette = true),
        ];
        assert_table!(scenes, |idx, Scene(what, open)| {
            let (ctx, mut app) = target_app();
            open(&mut app);
            for size in [egui::vec2(1400.0, 800.0), egui::vec2(50.0, 50.0), egui::vec2(1.0, 1.0)] {
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    ..Default::default()
                };
                let _ = ctx.run(input, |ctx| crate::ui_core::frame(&mut app, ctx));
            }
            assert!(!what.is_empty(), "case #{idx} ({what}): drawn at every size");
        });
    }
}

