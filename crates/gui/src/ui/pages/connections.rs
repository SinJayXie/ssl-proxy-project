use crate::core::types::ConnectionInfo;
use crate::core::Core;
use crate::ui::assets::mdi;
use crate::ui::components::icon_button::{danger_icon_button, muted_icon_button};
use crate::ui::components::rule_dialog::{self, RulePrefill};
use crate::ui::components::{badge, confirm};
use crate::ui::pages::RulesPage;
use crate::ui::{i18n, theme, util};
use gpui_kit::base::{h_flex, v_flex};
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::{ActiveTheme as _, Icon};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

pub struct ConnectionsPage {
    core: Arc<Core>,
    rules: WeakEntity<RulesPage>,
    connections: Vec<ConnectionInfo>,
    collapsed: HashSet<String>,
    _poll: Task<()>,
}

impl ConnectionsPage {
    pub fn new(
        core: Arc<Core>,
        rules: WeakEntity<RulesPage>,
        cx: &mut Context<Self>,
    ) -> Self {
        let mut connections = core.snapshot_connections().unwrap_or_default();
        connections.sort_by_key(|connection| connection.id);

        let poll_core = core.clone();
        let poll = cx.spawn(async move |this, cx| loop {
            smol::Timer::after(Duration::from_secs(1)).await;

            let Some(mut connections) = poll_core.snapshot_connections() else {
                continue;
            };
            connections.sort_by_key(|connection| connection.id);

            let updated = this.update(cx, |page, cx| {
                if page.connections != connections {
                    page.connections = connections;
                    cx.notify();
                }
            });
            if updated.is_err() {
                break;
            }
        });

        Self {
            core,
            rules,
            connections,
            collapsed: HashSet::new(),
            _poll: poll,
        }
    }

    fn toggle_group(&mut self, host: &str, cx: &mut Context<Self>) {
        if !self.collapsed.remove(host) {
            self.collapsed.insert(host.to_string());
        }
        cx.notify();
    }

    fn kill_one(&mut self, id: u32, cx: &mut Context<Self>) {
        self.connections.retain(|connection| connection.id != id);
        cx.notify();

        let handle = self.core.kill_connection(id);
        cx.spawn(async move |_, _| {
            let _ = handle.await;
        })
        .detach();
    }

    fn kill_group(
        &mut self,
        host: String,
        ids: Vec<u32>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let count = ids.len();
        let message = i18n::t_with(
            "DISCONNECT_GROUP_PROMPT",
            &[("host", &host), ("count", &count.to_string())],
        );

        let weak = cx.weak_entity();
        let core = self.core.clone();

        confirm::open_confirm(
            window,
            cx,
            i18n::t("DISCONNECT"),
            message,
            true,
            move |_, cx| {
                let ids_for_ui = ids.clone();
                let _ = weak.update(cx, move |page, cx| {
                    page.connections
                        .retain(|connection| !ids_for_ui.contains(&connection.id));
                    cx.notify();
                });

                let ids = ids.clone();
                let core = core.clone();
                cx.spawn(async move |_| {
                    for id in ids {
                        let _ = core.kill_connection(id).await;
                    }
                })
                .detach();
            },
        );
    }

    fn add_rule(&mut self, host: String, window: &mut Window, cx: &mut Context<Self>) {
        let rules = self.rules.clone();
        let on_done = Arc::new(move |cx: &mut App| {
            let _ = rules.update(cx, |page, cx| page.reload(cx));
        });

        rule_dialog::open_rule_dialog(
            self.core.clone(),
            RulePrefill::new("HOST", format!("*.{host}"), "DIRECT"),
            None,
            on_done,
            window,
            cx,
        );
    }
}

impl Render for ConnectionsPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.connections.is_empty() {
            return v_flex()
                .size_full()
                .items_center()
                .justify_center()
                .gap_3()
                .child(
                    Icon::default()
                        .path(mdi("shield-link-variant-outline"))
                        .w(px(48.))
                        .h(px(48.))
                        .text_color(theme::text_muted(cx))
                        .opacity(0.4),
                )
                .child(
                    div()
                        .text_size(px(14.))
                        .text_color(theme::text_muted(cx))
                        .child(i18n::t("NO_CONNECTIONS")),
                )
                .into_any_element();
        }

        let mut groups: BTreeMap<String, Vec<ConnectionInfo>> = BTreeMap::new();
        for connection in &self.connections {
            groups
                .entry(connection.host.clone())
                .or_default()
                .push(connection.clone());
        }

        let mut list = v_flex().gap_2();
        for (host, connections) in groups {
            list = list.child(self.group_card(host, connections, cx));
        }

        v_flex()
            .size_full()
            .child(
                h_flex()
                    .items_center()
                    .gap_2()
                    .mb_4()
                    .pr_6()
                    .child(
                        div()
                            .text_size(px(20.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(i18n::t("CONNECTIONS")),
                    )
                    .child(badge::title_count(self.connections.len(), cx)),
            )
            .child(
                div()
                    .id("connections-scroll")
                    .flex_1()
                    .min_h_0()
                    .pr_6()
                    .overflow_y_scrollbar()
                    .child(list),
            )
            .into_any_element()
    }
}

impl ConnectionsPage {
    fn group_card(
        &self,
        host: String,
        connections: Vec<ConnectionInfo>,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let open = !self.collapsed.contains(&host);
        let ids: Vec<u32> = connections.iter().map(|connection| connection.id).collect();
        let country = connections
            .first()
            .map(|connection| connection.geo.country.clone())
            .unwrap_or_default();
        let conn_type = connections
            .first()
            .map(|connection| connection.conn_type.clone())
            .unwrap_or_else(|| "DIRECT".to_string());
        let average = avg_latency(&connections);
        let up = connections.iter().map(|connection| connection.data.up).sum();
        let down = connections
            .iter()
            .map(|connection| connection.data.down)
            .sum();

        let weak_toggle = cx.weak_entity();
        let host_toggle = host.clone();
        let header_hover = theme::card_hover(cx);

        let weak_add = cx.weak_entity();
        let host_add = host.clone();

        let weak_kill = cx.weak_entity();
        let host_kill = host.clone();
        let ids_kill = ids.clone();

        let header = h_flex()
            .id(ElementId::Name(format!("conn-group-{host}").into()))
            .items_center()
            .gap_2()
            .px_3()
            .py(px(10.))
            .cursor_pointer()
            .hover(move |style| style.bg(header_hover))
            .on_click(move |_, _, cx| {
                let _ = weak_toggle.update(cx, |page, cx| {
                    page.toggle_group(&host_toggle, cx);
                });
            })
            .child(
                Icon::default()
                    .path(mdi("web"))
                    .w(px(20.))
                    .h(px(20.))
                    .text_color(theme::text_muted(cx)),
            )
            .child(
                v_flex()
                    .flex_1()
                    .min_w_0()
                    .gap(px(4.))
                    .child(
                        h_flex()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .font_weight(FontWeight::MEDIUM)
                                    .overflow_hidden()
                                    .child(host.clone()),
                            )
                            .child(
                                h_flex()
                                    .items_center()
                                    .gap(px(3.))
                                    .flex_shrink_0()
                                    .child(
                                        Icon::default()
                                            .path(mdi("earth"))
                                            .w(px(12.))
                                            .h(px(12.))
                                            .text_color(theme::text_muted(cx)),
                                    )
                                    .child(
                                        div()
                                            .text_size(px(11.))
                                            .text_color(theme::text_muted(cx))
                                            .child(country),
                                    ),
                            ),
                    )
                    .child(
                        h_flex()
                            .items_center()
                            .gap_2()
                            .flex_wrap()
                            .child(badge::protocol_badge(&conn_type, cx))
                            .child(badge::mode_badge(&conn_type, cx))
                            .when(average > 0, |this| {
                                this.child(
                                    h_flex()
                                        .items_center()
                                        .gap(px(2.))
                                        .min_w(px(52.))
                                        .text_size(px(11.))
                                        .text_color(latency_color(average, cx))
                                        .child(
                                            Icon::default()
                                                .path(mdi("clock-outline"))
                                                .w(px(12.))
                                                .h(px(12.)),
                                        )
                                        .child(format!("{average}ms")),
                                )
                            })
                            .child(
                                h_flex()
                                    .items_center()
                                    .gap(px(2.))
                                    .text_size(px(11.))
                                    .child(
                                        Icon::default()
                                            .path(mdi("arrow-up-thin"))
                                            .w(px(12.))
                                            .h(px(12.))
                                            .text_color(cx.theme().success),
                                    )
                                    .child(
                                        div()
                                            .text_color(cx.theme().success)
                                            .child(util::format_bytes(up)),
                                    )
                                    .child(
                                        Icon::default()
                                            .path(mdi("arrow-down-thin"))
                                            .w(px(12.))
                                            .h(px(12.))
                                            .text_color(cx.theme().primary),
                                    )
                                    .child(
                                        div()
                                            .text_color(cx.theme().primary)
                                            .child(util::format_bytes(down)),
                                    ),
                            )
                            .child(badge::conn_count(connections.len(), cx)),
                    ),
            )
            .child(
                h_flex()
                    .items_center()
                    .gap(px(2.))
                    .flex_shrink_0()
                    .child(muted_icon_button(
                        ElementId::Name(format!("conn-add-{host}").into()),
                        "pencil-ruler-outline",
                        28.,
                        16.,
                        cx,
                        {
                            let weak = weak_add;
                            let host = host_add.clone();
                            move |_, window, cx| {
                                cx.stop_propagation();
                                let host = host.clone();
                                let _ = weak.update(cx, move |page, cx| {
                                    page.add_rule(host, window, cx);
                                });
                            }
                        },
                    ))
                    .child(danger_icon_button(
                        ElementId::Name(format!("conn-kill-{host}").into()),
                        "lan-disconnect",
                        28.,
                        16.,
                        cx,
                        {
                            let weak = weak_kill;
                            let host = host_kill.clone();
                            let ids = ids_kill.clone();
                            move |_, window, cx| {
                                cx.stop_propagation();
                                let host = host.clone();
                                let ids = ids.clone();
                                let _ = weak.update(cx, move |page, cx| {
                                    page.kill_group(host, ids, window, cx);
                                });
                            }
                        },
                    ))
                    .child(
                        Icon::default()
                            .path(mdi("chevron-down"))
                            .w(px(18.))
                            .h(px(18.))
                            .text_color(theme::text_muted(cx))
                            .rotate(radians(if open {
                                std::f32::consts::PI
                            } else {
                                0.0
                            })),
                    ),
            );

        let mut rows = v_flex();
        if open {
            let count = connections.len();
            for (index, connection) in connections.into_iter().enumerate() {
                rows = rows.child(connection_row(connection, index + 1 == count, cx));
            }
        }

        let card_border = cx.theme().border;
        v_flex()
            .rounded(px(10.))
            .bg(theme::card(cx))
            .border_1()
            .border_color(theme::border_light(cx))
            .shadow_xs()
            .overflow_hidden()
            .hover(move |style| style.border_color(card_border))
            .child(header)
            .when(open, |this| {
                this.child(
                    v_flex()
                        .border_t_1()
                        .border_color(theme::border_light(cx))
                        .child(rows),
                )
            })
            .into_any_element()
    }
}

fn connection_row(
    connection: ConnectionInfo,
    is_last: bool,
    cx: &mut Context<ConnectionsPage>,
) -> AnyElement {
    let weak = cx.weak_entity();
    let id = connection.id;
    let ping = connection.latency_ms;
    let conn_type = connection.conn_type.clone();
    let row_hover = theme::card_hover(cx);

    h_flex()
        .items_center()
        .gap_2()
        .py(px(5.))
        .pr_3()
        .pl(px(40.))
        .text_size(px(11.))
        .when(!is_last, |this| {
            this.border_b_1().border_color(theme::border_light(cx))
        })
        .hover(move |style| style.bg(row_hover))
        .child(badge::protocol_badge(&conn_type, cx))
        .child(
            h_flex()
                .flex_1()
                .min_w_0()
                .items_center()
                .gap(px(3.))
                .text_color(theme::text_secondary(cx))
                .child(
                    Icon::default()
                        .path(mdi("ip-outline"))
                        .w(px(14.))
                        .h(px(14.)),
                )
                .child(div().min_w_0().overflow_hidden().child(connection.ip.clone()))
                .child(
                    div()
                        .text_color(theme::text_muted(cx))
                        .flex_shrink_0()
                        .child(format!(":{}", connection.port)),
                ),
        )
        .child(
            h_flex()
                .items_center()
                .gap(px(3.))
                .text_color(cx.theme().success)
                .child(
                    Icon::default()
                        .path(mdi("arrow-up-thin"))
                        .w(px(14.))
                        .h(px(14.)),
                )
                .child(util::format_bytes(connection.data.up)),
        )
        .child(
            h_flex()
                .items_center()
                .gap(px(3.))
                .text_color(cx.theme().primary)
                .child(
                    Icon::default()
                        .path(mdi("arrow-down-thin"))
                        .w(px(14.))
                        .h(px(14.)),
                )
                .child(util::format_bytes(connection.data.down)),
        )
        .when(ping > 0, |this| {
            this.child(
                div()
                    .min_w(px(44.))
                    .text_align(TextAlign::Right)
                    .text_color(latency_color(ping, cx))
                    .child(format!("{ping}ms")),
            )
        })
        .child(danger_icon_button(
            ElementId::Name(format!("conn-kill-{id}").into()),
            "close",
            24.,
            14.,
            cx,
            move |_, _, cx| {
                let _ = weak.update(cx, |page, cx| page.kill_one(id, cx));
            },
        ))
        .into_any_element()
}

fn avg_latency(group: &[ConnectionInfo]) -> u64 {
    let valid: Vec<u64> = group
        .iter()
        .map(|connection| connection.latency_ms)
        .filter(|latency| *latency > 0)
        .collect();
    if valid.is_empty() {
        0
    } else {
        (valid.iter().sum::<u64>() as f64 / valid.len() as f64).round() as u64
    }
}

fn latency_color(ms: u64, cx: &App) -> Hsla {
    if ms < 100 {
        cx.theme().success
    } else if ms < 300 {
        cx.theme().warning
    } else {
        cx.theme().danger
    }
}
