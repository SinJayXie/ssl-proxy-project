use crate::core::Core;
use crate::ui::assets::mdi;
use crate::ui::{i18n, theme};
use gpui_kit::base::{h_flex, v_flex};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::searchable_list::SearchableVec;
use gpui_kit::component::select::{Select, SelectEvent, SelectState};
use gpui_kit::component::{ActiveTheme as _, Icon, IndexPath, Sizable as _};
use gpui_kit::*;
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;

static LOG_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^\[(\S+)\s+(INFO|WARN|ERROR|DEBUG)\]\s*(.*)$").expect("valid log regex")
});

struct LogEntry {
    time: String,
    level: String,
    message: String,
}

/// 级别下拉的可选项：0 = 全部，其余与日志级别一一对应。
fn level_labels() -> Vec<SharedString> {
    vec![
        i18n::t("LOG_FILTER_ALL").into(),
        "INFO".into(),
        "WARN".into(),
        "ERROR".into(),
        "DEBUG".into(),
    ]
}

/// 按级别与关键字过滤日志；`level` 为 0 时不过滤级别，`query` 为空时不过滤关键字。
fn filter_entries<'a>(entries: &'a [LogEntry], level: usize, query: &str) -> Vec<&'a LogEntry> {
    let level = match level {
        1 => Some("INFO"),
        2 => Some("WARN"),
        3 => Some("ERROR"),
        4 => Some("DEBUG"),
        _ => None,
    };
    let query = query.trim().to_lowercase();

    entries
        .iter()
        .filter(|entry| {
            level.is_none_or(|wanted| entry.level == wanted)
                && (query.is_empty() || entry.message.to_lowercase().contains(&query))
        })
        .collect()
}

/// 与页面展示一致的导出行格式。
fn line_text(entry: &LogEntry) -> String {
    if entry.time.is_empty() {
        format!("[{}] {}", entry.level, entry.message)
    } else {
        format!("[{} {}] {}", entry.time, entry.level, entry.message)
    }
}

/// 把设置文件中 key 含 `password` 的行替换为 `key: "***"`，保留缩进。
fn mask_password_lines(text: &str) -> String {
    text.lines()
        .map(|line| {
            let key = line.split(':').next().unwrap_or_default();
            if key.to_lowercase().contains("password") {
                let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                format!("{indent}{}: \"***\"", key.trim())
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub struct LogsPage {
    core: Arc<Core>,
    entries: Vec<LogEntry>,
    scroll: ScrollHandle,
    /// 0 = 全部，1 = INFO，2 = WARN，3 = ERROR，4 = DEBUG。
    level_filter: usize,
    /// 下拉与搜索框依赖 `Window`，在 `new` 内创建。
    level_select: Entity<SelectState<SearchableVec<SharedString>>>,
    search: Entity<InputState>,
    /// 导出 / 诊断包的结果路径或错误。
    notice: Option<String>,
    _level_subscription: Subscription,
    _search_subscription: Subscription,
}

impl LogsPage {
    pub fn new(core: Arc<Core>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let level_filter = 0;
        let level_select = cx.new(|cx| {
            SelectState::new(
                SearchableVec::new(level_labels()),
                Some(IndexPath::new(level_filter)),
                window,
                cx,
            )
        });
        let level_subscription = cx.subscribe(
            &level_select,
            |this, _, event: &SelectEvent<SearchableVec<SharedString>>, cx| {
                if let SelectEvent::Confirm(Some(value)) = event {
                    this.level_filter = level_labels()
                        .iter()
                        .position(|label| label.as_ref() == value.as_ref())
                        .unwrap_or(0);
                    cx.notify();
                }
            },
        );

        let search = cx.new(|cx| {
            InputState::new(window, cx).placeholder(i18n::t("LOG_SEARCH_PLACEHOLDER"))
        });
        let search_subscription = cx.subscribe(&search, |_, _, _: &InputEvent, cx| {
            cx.notify();
        });

        let mut page = Self {
            core,
            entries: Vec::new(),
            scroll: ScrollHandle::new(),
            level_filter,
            level_select,
            search,
            notice: None,
            _level_subscription: level_subscription,
            _search_subscription: search_subscription,
        };
        page.refresh(cx);
        page
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        let raw = self.core.read_logs_tail(2 * 1024 * 1024);
        self.entries = raw
            .lines()
            .map(|line| {
                if let Some(captures) = LOG_RE.captures(line) {
                    LogEntry {
                        time: captures[1].to_string(),
                        level: captures[2].to_string(),
                        message: captures[3].to_string(),
                    }
                } else {
                    LogEntry {
                        time: String::new(),
                        level: "INFO".to_string(),
                        message: line.to_string(),
                    }
                }
            })
            .collect();

        self.scroll.scroll_to_bottom();
        cx.notify();
    }

    fn search_query(&self, cx: &App) -> String {
        self.search.read(cx).value().to_string()
    }

    /// 导出当前过滤结果到 `<config_dir>/exports/logs-*.txt`。
    fn export_logs(&mut self, cx: &mut Context<Self>) {
        let query = self.search_query(cx);
        let filtered = filter_entries(&self.entries, self.level_filter, &query);
        let text = filtered
            .iter()
            .map(|entry| line_text(entry))
            .collect::<Vec<_>>()
            .join("\n");

        self.notice = Some(match self.core.export_text("logs", &text) {
            Ok(path) => {
                let path = path.display().to_string();
                i18n::t_with("LOG_EXPORT_DONE", &[("path", &path)])
            }
            Err(err) => i18n::t_with("LOG_EXPORT_FAILED", &[("error", &err.to_string())]),
        });
        cx.notify();
    }

    /// 生成诊断包（TUN、配置、路由、诊断结果与日志尾部）并异步导出。
    fn export_bundle(&mut self, cx: &mut Context<Self>) {
        let core = self.core.clone();
        cx.spawn(async move |this, cx| {
            let mut content = String::new();
            content.push_str("SSL Proxy diagnostics\n");
            content.push_str(&format!("version: {}\n", env!("CARGO_PKG_VERSION")));
            content.push_str(&format!(
                "os: {}/{}\n",
                std::env::consts::OS,
                std::env::consts::ARCH
            ));

            content.push_str("\n== TUN ==\n");
            content.push_str(&format!("{:?}\n", crate::core::tun::runner::status()));

            content.push_str("\n== CONFIG ==\n");
            let config_path = core.state.config_dir.join("setting.yaml");
            match std::fs::read_to_string(&config_path) {
                Ok(text) => content.push_str(&mask_password_lines(&text)),
                Err(_) => content.push_str("unavailable"),
            }
            content.push('\n');

            content.push_str("\n== ROUTE (IPv4) ==\n");
            content.push_str(&crate::core::diagnostics::route_table_text());
            content.push('\n');

            content.push_str("\n== DIAGNOSTICS ==\n");
            let report = crate::core::diagnostics::format_report(
                &core.run_diagnostics().await.unwrap_or_default(),
            );
            content.push_str(&report);
            content.push('\n');

            content.push_str("\n== LOG (tail 2000 lines) ==\n");
            let tail = core.read_logs_tail(2 * 1024 * 1024);
            let lines: Vec<&str> = tail.lines().collect();
            let start = lines.len().saturating_sub(2000);
            content.push_str(&lines[start..].join("\n"));

            let notice = match core.export_text("diagnostics", &content) {
                Ok(path) => {
                    let path = path.display().to_string();
                    i18n::t_with("LOG_BUNDLE_DONE", &[("path", &path)])
                }
                Err(err) => i18n::t_with("LOG_EXPORT_FAILED", &[("error", &err.to_string())]),
            };
            let _ = this.update(cx, |page, cx| {
                page.notice = Some(notice);
                cx.notify();
            });
        })
        .detach();
    }

    fn level_color(level: &str) -> Hsla {
        match level {
            "WARN" => theme::log_warn(),
            "ERROR" => theme::log_error(),
            "DEBUG" => theme::log_debug(),
            _ => theme::log_info(),
        }
    }
}

impl Render for LogsPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let query = self.search_query(cx);
        let filtered = filter_entries(&self.entries, self.level_filter, &query);
        let level_select = self.level_select.clone();
        let search = self.search.clone();

        let toolbar = h_flex()
            .items_center()
            .flex_wrap()
            .gap_2()
            .pr_6()
            .child(
                div()
                    .text_size(px(20.))
                    .font_weight(FontWeight::SEMIBOLD)
                    .mr_2()
                    .child(i18n::t("LOG")),
            )
            .child(div().w(px(110.)).child(Select::new(&level_select)))
            .child(div().w(px(180.)).child(Input::new(&search)))
            .child(
                Button::new("logs-export")
                    .ghost()
                    .small()
                    .icon(Icon::default().path(mdi("content-save-outline")))
                    .label(i18n::t("LOG_EXPORT"))
                    .on_click(cx.listener(|this, _, _, cx| this.export_logs(cx))),
            )
            .child(
                Button::new("logs-bundle")
                    .ghost()
                    .small()
                    .icon(Icon::default().path(mdi("file-document-outline")))
                    .label(i18n::t("LOG_BUNDLE"))
                    .on_click(cx.listener(|this, _, _, cx| this.export_bundle(cx))),
            )
            .child(
                Button::new("logs-refresh")
                    .ghost()
                    .small()
                    .icon(Icon::default().path(mdi("refresh")))
                    .label("Refresh")
                    .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
            );

        let mut list = v_flex().gap_1();

        if filtered.is_empty() {
            list = list.child(
                v_flex()
                    .items_center()
                    .justify_center()
                    .py_8()
                    .gap_2()
                    .child(
                        Icon::default().path(mdi("text-box-outline"))
                            .size_8()
                            .text_color(theme::text_muted(cx)),
                    )
                    .child(
                        div()
                            .text_sm()
                            .text_color(theme::text_muted(cx))
                            .child(i18n::t("NO_MATCH")),
                    ),
            );
        } else {
            let mut body = v_flex().gap_1();
            let row_hover = cx.theme().secondary_hover;
            for (index, entry) in filtered.iter().enumerate() {
                let color = Self::level_color(&entry.level);
                let line = line_text(entry);

                body = body.child(
                    h_flex()
                        .id(ElementId::Name(format!("log-{index}").into()))
                        .items_start()
                        .gap_2()
                        .px_2()
                        .py_1()
                        .rounded(px(4.))
                        .cursor_pointer()
                        .hover(move |style| style.bg(row_hover))
                        .child(
                            div()
                                .w(px(3.))
                                .self_stretch()
                                .flex_shrink_0()
                                .bg(color),
                        )
                        .child(
                            div()
                                .w(px(150.))
                                .text_xs()
                                .font_family("Consolas")
                                .text_color(theme::text_muted(cx))
                                .child(entry.time.clone()),
                        )
                        .child(
                            div()
                                .w(px(50.))
                                .text_xs()
                                .font_family("Consolas")
                                .text_color(color)
                                .child(entry.level.clone()),
                        )
                        .child(
                            div()
                                .flex_1()
                                .text_xs()
                                .font_family("Consolas")
                                .child(entry.message.clone()),
                        )
                        .on_click(move |_, _, cx| {
                            cx.write_to_clipboard(ClipboardItem::new_string(line.clone()));
                        }),
                );
            }
            list = list.child(body);
        }

        let notice_row = self.notice.clone().map(|notice| {
            let copy_hint = i18n::t("LOG_COPY_PATH");
            h_flex()
                .id("logs-notice")
                .items_center()
                .gap_1()
                .pr_6()
                .cursor_pointer()
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(theme::text_muted(cx))
                        .child(notice.clone()),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(theme::text_muted(cx))
                        .child(format!("· {copy_hint}")),
                )
                .on_click(move |_, _, cx| {
                    cx.write_to_clipboard(ClipboardItem::new_string(notice.clone()));
                })
        });

        let mut root = v_flex().size_full().gap_4().child(toolbar);
        if let Some(notice_row) = notice_row {
            root = root.child(notice_row);
        }
        root.child(
            div()
                .id("logs-scroll")
                .flex_1()
                .min_h_0()
                .pr_6()
                .track_scroll(&self.scroll)
                .overflow_y_scrollbar()
                .child(list),
        )
    }
}
