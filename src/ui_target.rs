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

/// A right-click choice on a tree node, applied after drawing (drawing can't touch the app).
enum NodeAction {
    /// Add the node's origin to the target scope (via a representative request).
    AddHostToScope(usize),
    /// Send a representative request under the node to Repeater.
    SendToRepeater(usize),
    /// Send a representative request under the node to the Sequencer.
    SendToSequencer(usize),
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
        if ui.button("Send to Repeater").clicked() {
            pick = Some(NodeAction::SendToRepeater(id));
        }
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
        NodeAction::SendToRepeater(id) => {
            if let Some(e) = all.iter().find(|e| e.id == id).cloned() {
                actions::send_to(app, &e, actions::SendTo::Repeater);
            }
        }
        NodeAction::SendToSequencer(id) => {
            if let Some(e) = all.iter().find(|e| e.id == id).cloned() {
                actions::send_to(app, &e, actions::SendTo::Sequencer);
            }
        }
        NodeAction::CopyUrl(url) => ctx.copy_text(url),
    }
}

/// One tree node and its subtree. Branches are `CollapsingHeader`s; leaves are selectable rows.
/// Out-of-scope nodes are dimmed. Clicking a node selects its branch for the right pane.
#[allow(clippy::too_many_arguments)]
fn draw_node(
    ui: &mut Ui,
    p: &Palette,
    node: &SiteMapNode,
    scope: &crate::scope::TargetScope,
    selected: &Option<String>,
    default_open: bool,
    pick: &mut Option<String>,
    menu: &mut Option<NodeAction>,
) {
    let col = if scope.is_in_scope(&node.full_url) { p.strong } else { p.disabled };
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
                    draw_node(ui, p, child, scope, selected, false, pick, menu);
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

pub fn site_map(app: &mut App, ui: &mut Ui, p: &Palette) {
    let all = app.history.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let mut pick_node: Option<String> = None;
    let mut menu: Option<NodeAction> = None;

    egui::SidePanel::left("site_map_tree")
        .resizable(true)
        .default_width(300.0)
        .min_width(180.0)
        .frame(egui::Frame::new().fill(p.deep).inner_margin(egui::Margin::same(6)))
        .show_inside(ui, |ui| {
            ui.label(bold("Site map", 13.0).color(p.strong));
            ui.add_space(4.0);
            egui::ScrollArea::vertical().id_salt("site_map_scroll").auto_shrink([false, false]).show(ui, |ui| {
                if app.site_map.roots.is_empty() {
                    ui.label(RichText::new("No requests recorded yet.").size(12.0).color(p.disabled));
                }
                for root in app.site_map.roots.values() {
                    draw_node(ui, p, root, &app.target_scope, &app.target_selected_node, true, &mut pick_node, &mut menu);
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
        let rows: Vec<std::sync::Arc<crate::http::HttpEntry>> =
            ids.iter().filter_map(|id| all.iter().find(|e| e.id == *id)).cloned().collect();

        // the detail viewer for the selected row, pinned to the bottom
        let detail = app
            .target_selected_history_id
            .and_then(|id| all.iter().find(|e| e.id == id))
            .cloned();
        if let Some(e) = detail {
            egui::TopBottomPanel::bottom("site_map_detail")
                .resizable(true)
                .default_height(260.0)
                .min_height(100.0)
                .frame(egui::Frame::new().fill(p.panel).inner_margin(egui::Margin::same(6)))
                .show_inside(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("#{} ", e.id)).color(p.text));
                        ui.label(RichText::new(actions::entry_url(&e)).monospace().size(11.5).color(p.disabled));
                        if theme::plain_button(ui, p, "Send to Repeater", true).clicked() {
                            actions::send_to(app, &e, actions::SendTo::Repeater);
                        }
                    });
                    ui.add_space(2.0);
                    let name = format!("{} #{}", actions::history_name(&e), e.id);
                    let mut menu_pick = None;
                    ui.columns(2, |cols| {
                        cols[0].label(bold("Request", 13.0).color(p.strong));
                        let out = editor::message_view(&mut cols[0], p, "sm_req", &e.request, 140.0);
                        menu_pick = out.menu(&e.request).map(|m| (m, format!("{name} request")));
                        cols[1].label(bold("Response", 13.0).color(p.strong));
                        let out = editor::message_view(&mut cols[1], p, "sm_resp", &e.response, 140.0);
                        menu_pick = menu_pick.take().or_else(|| out.menu(&e.response).map(|m| (m, format!("{name} response"))));
                    });
                    if let Some((m, what)) = menu_pick {
                        crate::ui_tools::apply_menu_pick(app, m, &what);
                    }
                });
        }

        egui::CentralPanel::default().frame(egui::Frame::NONE).show_inside(ui, |ui| {
            if app.target_selected_node.is_none() {
                ui.add_space(8.0);
                ui.label(RichText::new("Select a node in the tree to see its requests.").size(12.5).color(p.disabled));
                return;
            }
            theme::table_well(ui, p, ui.available_height().max(120.0), |ui| {
                use crate::history::time_of_day;
                theme::table_header(ui, p, &[("#", 50.0), ("Time", 72.0), ("Method", 70.0), ("Host", 180.0), ("Path", 280.0), ("Status code", 120.0), ("Length", 80.0)]);
                let sel = app.target_selected_history_id;
                let mut clicked = None;
                egui::ScrollArea::vertical().id_salt("site_map_rows").show_rows(ui, 19.0, rows.len(), |ui, range| {
                    for (i, e) in rows.iter().enumerate().skip(range.start).take(range.len()) {
                        let cells = [
                            (e.id.to_string(), 50.0, None),
                            (time_of_day(e.time), 72.0, Some(p.disabled)),
                            (e.method.clone(), 70.0, Some(method_color(p, &e.method))),
                            (e.host.clone(), 180.0, None),
                            (e.path.clone(), 280.0, None),
                            (e.status.clone(), 120.0, None),
                            (e.length.to_string(), 80.0, None),
                        ];
                        let row = theme::table_row(ui, p, &cells, sel == Some(e.id), i % 2 == 1);
                        if row.clicked() {
                            clicked = Some(e.id);
                        }
                        row.context_menu(|ui| {
                            if ui.button("Send to Repeater").clicked() {
                                menu = Some(NodeAction::SendToRepeater(e.id));
                                ui.close_menu();
                            }
                            if ui.button("Send to Sequencer").clicked() {
                                menu = Some(NodeAction::SendToSequencer(e.id));
                                ui.close_menu();
                            }
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
