use crate::core::types::ConnectionInfo;
use crate::core::Core;
use crate::ui::assets::mdi;
use crate::ui::components::icon_button::{danger_icon_button, muted_icon_button};
use crate::ui::components::rule_dialog::{self, RulePrefill};
use crate::ui::components::{badge, confirm};
use crate::ui::pages::RulesPage;
use crate::ui::{i18n, theme, util};
use gpui_kit::base::{h_flex, v_flex};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::searchable_list::SearchableVec;
use gpui_kit::component::select::{Select, SelectEvent, SelectState};
use gpui_kit::component::{
    v_virtual_list, ActiveTheme as _, Icon, IndexPath, VirtualListScrollHandle,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

/// 分组头高度（含上下内边距与边框）。
const HEADER_H: f32 = 64.;
/// 单条连接行高度。
const ROW_H: f32 = 28.;
/// 分组之间的间距（合并到最后一项的高度里）。
const GROUP_GAP: f32 = 8.;

type ConnSelect = Entity<SelectState<SearchableVec<SharedString>>>;

/// 规则过滤：0 = 全部，1 = 代理（PROXY），2 = 直连（DIRECT）。
fn mode_labels() -> Vec<SharedString> {
    vec![
        i18n::t("CONN_FILTER_ALL").into(),
        i18n::t("CONN_FILTER_PROXY").into(),
        i18n::t("CONN_FILTER_DIRECT").into(),
    ]
}

/// 排序：0 = 时间，1 = 流量，2 = 延迟，3 = 主机。
fn sort_labels() -> Vec<SharedString> {
    vec![
        i18n::t("CONN_SORT_TIME").into(),
        i18n::t("CONN_SORT_TRAFFIC").into(),
        i18n::t("CONN_SORT_LATENCY").into(),
        i18n::t("CONN_SORT_HOST").into(),
    ]
}

/// 进程下拉选项：首项固定为“全部进程”，其余为当前连接中的进程名。
fn process_labels(names: &[String]) -> Vec<SharedString> {
    std::iter::once(i18n::t("CONN_PROCESS_ALL"))
        .chain(names.iter().cloned())
        .map(SharedString::from)
        .collect()
}

/// 当前连接里出现过的非空进程名，去重并排序。
fn collect_process_names(connections: &[ConnectionInfo]) -> Vec<String> {
    let mut names: Vec<String> = connections
        .iter()
        .map(|connection| connection.process.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

/// 搜索 + 规则 + 进程三重过滤；`process` 为 `None` 表示不过滤进程。
fn filter_connections<'a>(
    connections: &'a [ConnectionInfo],
    query: &str,
    mode: usize,
    process: Option<&str>,
) -> Vec<&'a ConnectionInfo> {
    let query = query.trim().to_lowercase();
    connections
        .iter()
        .filter(|connection| {
            let matches_query = query.is_empty()
                || connection.host.to_lowercase().contains(&query)
                || connection.ip.to_lowercase().contains(&query)
                || connection.process.to_lowercase().contains(&query);
            let matches_mode = match mode {
                1 => connection.conn_type.eq_ignore_ascii_case("PROXY"),
                2 => connection.conn_type.eq_ignore_ascii_case("DIRECT"),
                _ => true,
            };
            let matches_process = process.is_none_or(|name| connection.process == name);
            matches_query && matches_mode && matches_process
        })
        .collect()
}

fn traffic(connection: &ConnectionInfo) -> u64 {
    connection.data.up.saturating_add(connection.data.down)
}

/// 延迟排序：0 视为未知，统一排在最后。
fn latency_cmp(a: u64, b: u64) -> Ordering {
    match (a, b) {
        (0, 0) => Ordering::Equal,
        (0, _) => Ordering::Greater,
        (_, 0) => Ordering::Less,
        _ => a.cmp(&b),
    }
}

/// 分组并按当前排序模式排列：先排分组（host），再排组内连接。
/// `sort` 与 [`sort_labels`] 的下标一致。
fn group_and_sort(
    filtered: &[&ConnectionInfo],
    sort: usize,
) -> Vec<(String, Vec<ConnectionInfo>)> {
    let mut groups: BTreeMap<String, Vec<ConnectionInfo>> = BTreeMap::new();
    for connection in filtered {
        groups
            .entry(connection.host.clone())
            .or_default()
            .push((*connection).clone());
    }

    let mut items: Vec<(String, Vec<ConnectionInfo>)> = groups.into_iter().collect();
    match sort {
        1 => {
            for (_, rows) in items.iter_mut() {
                rows.sort_by(|a, b| traffic(b).cmp(&traffic(a)).then(a.id.cmp(&b.id)));
            }
            items.sort_by(|(host_a, rows_a), (host_b, rows_b)| {
                let total_a: u64 = rows_a.iter().map(traffic).sum();
                let total_b: u64 = rows_b.iter().map(traffic).sum();
                total_b.cmp(&total_a).then(host_a.cmp(host_b))
            });
        }
        2 => {
            for (_, rows) in items.iter_mut() {
                rows.sort_by(|a, b| {
                    latency_cmp(a.latency_ms, b.latency_ms).then(a.id.cmp(&b.id))
                });
            }
            items.sort_by(|(host_a, rows_a), (host_b, rows_b)| {
                latency_cmp(avg_latency(rows_a), avg_latency(rows_b)).then(host_a.cmp(host_b))
            });
        }
        3 => {
            for (_, rows) in items.iter_mut() {
                rows.sort_by_key(|connection| connection.id);
            }
            // BTreeMap 已按主机名字典序。
        }
        _ => {
            // 时间：沿用默认的 id 升序；分组保持主机名字典序。
            for (_, rows) in items.iter_mut() {
                rows.sort_by_key(|connection| connection.id);
            }
        }
    }
    items
}

pub struct ConnectionsPage {
    core: Arc<Core>,
    rules: WeakEntity<RulesPage>,
    connections: Vec<ConnectionInfo>,
    /// 已展开的分组；默认全部收起。
    expanded: HashSet<String>,
    scroll: VirtualListScrollHandle,
    search: Entity<InputState>,
    mode_filter: ConnSelect,
    process_filter: ConnSelect,
    sort: ConnSelect,
    /// 进程下拉当前的连接进程名（不含首项“全部进程”），用于检测选项集合变化。
    process_options: Vec<String>,
    _poll: Task<()>,
    _search_subscription: Subscription,
    _mode_subscription: Subscription,
    _process_subscription: Subscription,
    _sort_subscription: Subscription,
}

impl ConnectionsPage {
    pub fn new(
        core: Arc<Core>,
        rules: WeakEntity<RulesPage>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let mut connections = core.snapshot_connections().unwrap_or_default();
        connections.sort_by_key(|connection| connection.id);
        let process_options = collect_process_names(&connections);

        let search = cx.new(|cx| {
            InputState::new(window, cx).placeholder(i18n::t("CONN_SEARCH_PLACEHOLDER"))
        });
        let search_subscription = cx.subscribe(&search, |_, _, _: &InputEvent, cx| {
            cx.notify();
        });

        let mode_filter = cx.new(|cx| {
            SelectState::new(
                SearchableVec::new(mode_labels()),
                Some(IndexPath::new(0)),
                window,
                cx,
            )
        });
        let mode_subscription = cx.subscribe(
            &mode_filter,
            |_, _, _: &SelectEvent<SearchableVec<SharedString>>, cx| cx.notify(),
        );

        let process_filter = cx.new(|cx| {
            SelectState::new(
                SearchableVec::new(process_labels(&process_options)),
                Some(IndexPath::new(0)),
                window,
                cx,
            )
        });
        let process_subscription = cx.subscribe(
            &process_filter,
            |_, _, _: &SelectEvent<SearchableVec<SharedString>>, cx| cx.notify(),
        );

        let sort = cx.new(|cx| {
            SelectState::new(
                SearchableVec::new(sort_labels()),
                Some(IndexPath::new(0)),
                window,
                cx,
            )
        });
        let sort_subscription = cx.subscribe(
            &sort,
            |_, _, _: &SelectEvent<SearchableVec<SharedString>>, cx| cx.notify(),
        );

        let window_handle = window.window_handle();

        let poll_core = core.clone();
        let poll = cx.spawn(async move |this, cx| loop {
            smol::Timer::after(Duration::from_secs(1)).await;

            let Some(mut connections) = poll_core.snapshot_connections() else {
                continue;
            };
            connections.sort_by_key(|connection| connection.id);

            // 选项集合变化时重建进程下拉；窗口在轮询回调里不可用，借存下的句柄。
            let mut rebuild: Option<(ConnSelect, Vec<SharedString>, usize)> = None;
            let updated = this.update(cx, |page, cx| {
                if page.connections == connections {
                    return;
                }
                page.connections = connections;

                let options = collect_process_names(&page.connections);
                if options != page.process_options {
                    let selected = page
                        .process_filter
                        .read(cx)
                        .selected_value()
                        .map(|value| value.to_string());
                    let index = selected
                        .and_then(|value| options.iter().position(|name| name == &value))
                        .map(|position| position + 1)
                        .unwrap_or(0);
                    let labels = process_labels(&options);
                    page.process_options = options;
                    rebuild = Some((page.process_filter.clone(), labels, index));
                }
                cx.notify();
            });
            if updated.is_err() {
                break;
            }

            if let Some((select, labels, index)) = rebuild {
                let _ = window_handle.update(cx, move |_, window, cx| {
                    select.update(cx, |state, cx| {
                        state.set_items(SearchableVec::new(labels), window, cx);
                        state.set_selected_index(Some(IndexPath::new(index)), window, cx);
                    });
                });
            }
        });

        Self {
            core,
            rules,
            connections,
            expanded: HashSet::new(),
            scroll: VirtualListScrollHandle::new(),
            search,
            mode_filter,
            process_filter,
            sort,
            process_options,
            _poll: poll,
            _search_subscription: search_subscription,
            _mode_subscription: mode_subscription,
            _process_subscription: process_subscription,
            _sort_subscription: sort_subscription,
        }
    }

    fn toggle_group(&mut self, host: &str, cx: &mut Context<Self>) {
        if !self.expanded.remove(host) {
            self.expanded.insert(host.to_string());
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

        let query = self.search.read(cx).value().to_string();
        let mode = self
            .mode_filter
            .read(cx)
            .selected_index(cx)
            .map(|index| index.row)
            .unwrap_or(0);
        let process_index = self
            .process_filter
            .read(cx)
            .selected_index(cx)
            .map(|index| index.row)
            .unwrap_or(0);
        let process = process_index
            .checked_sub(1)
            .and_then(|index| self.process_options.get(index))
            .map(String::as_str);
        let sort = self
            .sort
            .read(cx)
            .selected_index(cx)
            .map(|index| index.row)
            .unwrap_or(0);

        let filtered = filter_connections(&self.connections, &query, mode, process);
        let filtered_count = filtered.len();
        let items = Rc::new(group_and_sort(&filtered, sort));

        let search = self.search.clone();
        let mode_filter = self.mode_filter.clone();
        let process_filter = self.process_filter.clone();
        let sort_select = self.sort.clone();

        let toolbar = h_flex()
            .items_center()
            .flex_wrap()
            .gap_2()
            .mb_4()
            .pr_6()
            .child(
                div()
                    .text_size(px(20.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .mr_2()
                    .child(i18n::t("CONNECTIONS")),
            )
            .child(badge::title_count(filtered_count, cx))
            .child(div().w(px(180.)).child(Input::new(&search)))
            .child(div().w(px(104.)).child(Select::new(&mode_filter)))
            .child(div().w(px(140.)).child(Select::new(&process_filter)))
            .child(div().w(px(104.)).child(Select::new(&sort_select)));

        // 虚拟滚动：只为可见分组渲染卡片。
        // 每项高度 = 分组头 + 展开后的连接行（行高固定，可预估）。
        let list: AnyElement = if items.is_empty() {
            v_flex()
                .flex_1()
                .min_h_0()
                .items_center()
                .justify_center()
                .gap_2()
                .pr_6()
                .child(
                    Icon::default()
                        .path(mdi("text-box-search-outline"))
                        .w(px(32.))
                        .h(px(32.))
                        .text_color(theme::text_muted(cx)),
                )
                .child(
                    div()
                        .text_size(px(13.))
                        .text_color(theme::text_muted(cx))
                        .child(i18n::t("NO_MATCH")),
                )
                .into_any_element()
        } else {
            let sizes: Vec<Size<Pixels>> = items
                .iter()
                .map(|(host, connections)| {
                    let rows = if self.expanded.contains(host) {
                        connections.len() as f32 * ROW_H
                    } else {
                        0.
                    };
                    size(px(0.), px(HEADER_H + GROUP_GAP + rows))
                })
                .collect();

            let list = v_virtual_list(
                cx.entity(),
                "connections-list",
                Rc::new(sizes),
                move |page, range, _window, cx| {
                    range
                        .filter_map(|ix| {
                            items.get(ix).map(|(host, connections)| {
                                // 虚拟列表按项测量宽度，item 必须显式铺满，否则整列会缩成内容宽度。
                                div()
                                    .w_full()
                                    .child(page.group_card(host.clone(), connections.clone(), cx))
                            })
                        })
                        .collect::<Vec<_>>()
                },
            )
            .w_full()
            // 右侧留白放在列表内部，滚动条才能贴到页面最右边。
            .pr_6()
            .track_scroll(&self.scroll);

            div()
                .id("connections-scroll")
                .relative()
                .w_full()
                .flex_1()
                .min_h_0()
                .overflow_hidden()
                .child(list)
                // 用库自带的滚动条装饰器：内部会包一层 absolute inset_0，
                // 手写 Scrollbar 子元素没有 top/left，会落到可视区之外。
                .vertical_scrollbar(&self.scroll)
                .into_any_element()
        };

        v_flex()
            .size_full()
            .child(toolbar)
            .child(list)
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
        let open = self.expanded.contains(&host);
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
            .h(px(HEADER_H))
            .gap_2()
            // hover 背景需要跟随卡片圆角，否则会被矩形裁切出直角。
            .when(open, |this| this.rounded_t(px(10.)))
            .when(!open, |this| this.rounded(px(10.)))
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
            .w_full()
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
    let process = connection.process.clone();
    let row_hover = theme::card_hover(cx);

    h_flex()
        .items_center()
        .gap_2()
        .h(px(ROW_H))
        .py(px(5.))
        .pr_3()
        .pl(px(40.))
        .text_size(px(11.))
        // 最后一行贴卡片底边，hover 背景也要跟着底部圆角。
        .when(is_last, |this| this.rounded_b(px(10.)))
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
                )
                // 进程名：保持单行，过长时省略，避免撑高固定行高。
                .child(
                    div()
                        .flex_shrink_1()
                        .min_w_0()
                        .whitespace_nowrap()
                        .text_ellipsis()
                        .overflow_hidden()
                        .text_color(theme::text_muted(cx))
                        .child(if process.is_empty() {
                            "-".to_string()
                        } else {
                            process
                        }),
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
