use crate::core::stats::{self, StatsStore};
use crate::core::types::{ApiAppInfo, AppError, CheckUpdateResult, DataFlow, DownloadProgress};
use crate::core::Core;
use crate::ui::assets::mdi;
use crate::ui::pages::{
    AboutPage, ChangelogPage, ConnectionsPage, LogsPage, RulesPage, SettingsPage, TestRulePage,
};
use crate::ui::prefs::Prefs;
use crate::ui::{i18n, theme, util};
use gpui_kit::base::{h_flex, v_flex};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::chart::BarChart;
use gpui_kit::component::progress::Progress;
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Icon, Sizable as _, ThemeMode, TitleBar,
};
use gpui_kit::*;
use gpui_kit::prelude::FluentBuilder as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Set by the Dashboard "Check Update" button, consumed by the shell.
static UPDATE_REQUESTED: AtomicBool = AtomicBool::new(false);

/// 更新清单按平台区分（Windows 安装包 / macOS DMG），两者都支持应用内更新。
const UPDATES_SUPPORTED: bool = cfg!(any(windows, target_os = "macos"));

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Dashboard,
    Connections,
    Logs,
    Rules,
    TestRule,
    Settings,
    Changelog,
    About,
}

const NAV_ITEMS: [(Page, &str, &str); 8] = [
    (Page::Dashboard, "view-dashboard-outline", "APP"),
    (Page::Connections, "lan-connect", "CONNECTIONS"),
    (Page::Logs, "text-box-outline", "LOG"),
    (Page::Rules, "filter-variant", "RULES"),
    (Page::TestRule, "flask-outline", "TEST_RULE"),
    (Page::Settings, "cog-outline", "SETTINGS"),
    (Page::Changelog, "history", "CHANGELOG"),
    (Page::About, "information-outline", "ABOUT"),
];

pub struct AppShell {
    core: Arc<Core>,
    prefs: Prefs,
    page: Page,
    dashboard: Entity<DashboardPage>,
    connections: Entity<ConnectionsPage>,
    logs: Entity<LogsPage>,
    rules: Entity<RulesPage>,
    test_rule: Entity<TestRulePage>,
    settings: Entity<SettingsPage>,
    changelog: Entity<ChangelogPage>,
    about: Entity<AboutPage>,
    show_consent: bool,
    consent_scrolled: bool,
    consent_scroll: ScrollHandle,
    show_errors: bool,
    errors: Vec<AppError>,
    show_update: bool,
    /// 强制更新下载失败时的提示
    update_failed: bool,
    /// 手动检查更新且已是最新版本时的提示弹窗
    no_update_notice: bool,
    update_info: Option<CheckUpdateResult>,
    downloading: bool,
    download_percent: u32,
    _consent_watch: Task<()>,
    _lang_watch: Task<()>,
    _update_watch: Task<()>,
}

impl AppShell {
    pub fn new(
        core: Arc<Core>,
        prefs: Prefs,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let dashboard = cx.new(|cx| DashboardPage::new(core.clone(), cx));
        let logs = cx.new(|cx| LogsPage::new(core.clone(), cx));
        let rules = cx.new(|cx| RulesPage::new(core.clone(), cx));
        let connections = cx.new(|cx| {
            ConnectionsPage::new(core.clone(), rules.downgrade(), cx)
        });
        let test_rule = cx.new(|cx| {
            TestRulePage::new(core.clone(), rules.downgrade(), window, cx)
        });
        let settings = cx.new(|cx| SettingsPage::new(core.clone(), window, cx));
        let changelog = cx.new(|_| ChangelogPage::new());
        let about = cx.new(|_| AboutPage::new());

        let consent_scroll = ScrollHandle::new();
        let watch_scroll = consent_scroll.clone();
        let consent_watch = cx.spawn(async move |this, cx| loop {
            smol::Timer::after(Duration::from_millis(200)).await;

            if this.upgrade().is_none() {
                break;
            }

            let max = watch_scroll.max_offset().y;
            let offset = watch_scroll.offset().y;
            if max > px(0.) && (max - offset) < px(8.) {
                let updated = this.update(cx, |shell, cx| {
                    if shell.show_consent && !shell.consent_scrolled {
                        shell.consent_scrolled = true;
                        cx.notify();
                    }
                });
                if updated.is_err() {
                    break;
                }
            }
        });

        let mut seen_revision = i18n::revision();
        let lang_watch = cx.spawn(async move |this, cx| loop {
            smol::Timer::after(Duration::from_millis(300)).await;

            if this.upgrade().is_none() {
                break;
            }

            let revision = i18n::revision();
            if revision == seen_revision {
                continue;
            }
            seen_revision = revision;

            let updated = this.update(cx, |shell, cx| {
                shell.dashboard.update(cx, |_, cx| cx.notify());
                shell.connections.update(cx, |_, cx| cx.notify());
                shell.rules.update(cx, |_, cx| cx.notify());
                shell.test_rule.update(cx, |_, cx| cx.notify());
                shell.settings.update(cx, |_, cx| cx.notify());
                cx.notify();
            });
            if updated.is_err() {
                break;
            }
        });

        let update_watch = cx.spawn(async move |this, cx| {
            if !UPDATES_SUPPORTED {
                return;
            }
            let mut last_periodic = Instant::now();
            loop {
                smol::Timer::after(Duration::from_millis(250)).await;

                if this.upgrade().is_none() {
                    break;
                }

                if UPDATE_REQUESTED.swap(false, Ordering::Relaxed) {
                    let updated = this.update(cx, |shell, cx| {
                        shell.check_updates(true, cx);
                    });
                    if updated.is_err() {
                        break;
                    }
                }

                // 常驻进程也要周期性检查，保证强制更新能被发现。
                if last_periodic.elapsed() >= Duration::from_secs(60 * 60) {
                    last_periodic = Instant::now();
                    let updated = this.update(cx, |shell, cx| {
                        if !shell.show_update && !shell.downloading {
                            shell.check_updates(false, cx);
                        }
                    });
                    if updated.is_err() {
                        break;
                    }
                }
            }
        });

        let initial_page = match std::env::var("SSL_PROXY_GUI_PAGE")
            .unwrap_or_default()
            .as_str()
        {
            "connections" => Page::Connections,
            "logs" => Page::Logs,
            "rules" => Page::Rules,
            "test" => Page::TestRule,
            "settings" => Page::Settings,
            "changelog" => Page::Changelog,
            "about" => Page::About,
            _ => Page::Dashboard,
        };

        let mut shell = Self {
            core,
            prefs,
            page: initial_page,
            dashboard,
            connections,
            logs,
            rules,
            test_rule,
            settings,
            changelog,
            about,
            show_consent: false,
            consent_scrolled: false,
            consent_scroll,
            show_errors: false,
            errors: Vec::new(),
            show_update: false,
            update_failed: false,
            no_update_notice: false,
            update_info: None,
            downloading: false,
            download_percent: 0,
            _consent_watch: consent_watch,
            _lang_watch: lang_watch,
            _update_watch: update_watch,
        };
        shell.show_consent = !shell.core.consent_exists();
        shell.startup_checks(cx);
        shell
    }

    fn startup_checks(&mut self, cx: &mut Context<Self>) {
        if self.show_consent {
            return;
        }
        self.check_errors(cx);
        self.check_updates(false, cx);
    }

    fn check_errors(&self, cx: &mut Context<Self>) {
        let core = self.core.clone();
        cx.spawn(async move |this, cx| {
            let Ok(errors) = core.take_errors().await else {
                return;
            };
            if errors.is_empty() {
                return;
            }
            let _ = this.update(cx, |shell, cx| {
                shell.errors = errors;
                shell.show_errors = true;
                cx.notify();
            });
        })
        .detach();
    }

    fn check_updates(&mut self, force: bool, cx: &mut Context<Self>) {
        if !UPDATES_SUPPORTED {
            return;
        }
        const UPDATE_INTERVAL_MS: u64 = 60 * 60 * 1000;
        let now = now_ms();

        if !force
            && self.prefs.last_update_check > 0
            && now.saturating_sub(self.prefs.last_update_check) < UPDATE_INTERVAL_MS
        {
            return;
        }

        self.prefs.last_update_check = now;
        self.prefs.save(&self.core.state.config_dir);

        let handle = self.core.check_update();
        let dashboard = self.dashboard.downgrade();
        cx.spawn(async move |this, cx| {
            let result = handle.await;
            // 与 Vue 版一致：只有手动检查（force）且确认「无新版本」时才提示，
            // 网络错误保持静默。
            let up_to_date = force && matches!(&result, Ok(Ok(info)) if !info.has_update);
            let info = match result {
                Ok(Ok(info)) if info.has_update => Some(info),
                _ => None,
            };

            let _ = this.update(cx, |shell, cx| {
                if let Some(info) = info {
                    shell.update_info = Some(info);
                    shell.show_update = true;
                } else if up_to_date {
                    shell.no_update_notice = true;
                }
                let _ = dashboard.update(cx, |page, cx| {
                    page.checking_update = false;
                    cx.notify();
                });
                cx.notify();
            });
        })
        .detach();
    }

    fn agree_consent(&mut self, cx: &mut Context<Self>) {
        if let Err(err) = self.core.save_consent() {
            log::error!("Failed to save consent: {err}");
        }

        self.show_consent = false;
        self.consent_scrolled = false;
        cx.notify();

        let core = self.core.clone();
        cx.spawn(async move |this, cx| {
            smol::Timer::after(Duration::from_millis(500)).await;
            let Ok(errors) = core.take_errors().await else {
                return;
            };
            if errors.is_empty() {
                return;
            }
            let _ = this.update(cx, |shell, cx| {
                shell.errors = errors;
                shell.show_errors = true;
                cx.notify();
            });
        })
        .detach();

        self.check_updates(false, cx);
    }

    fn set_language(&mut self, language: i18n::Language, cx: &mut Context<Self>) {
        i18n::set_language(language);
        self.prefs.set_language(language);
        self.prefs.save(&self.core.state.config_dir);
        cx.notify();
    }

    fn start_download(&mut self, cx: &mut Context<Self>) {
        let Some(info) = self.update_info.clone() else {
            return;
        };

        self.downloading = true;
        self.update_failed = false;
        self.download_percent = 0;
        cx.notify();

        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<DownloadProgress>();
        let handle = self
            .core
            .download_update(info.download_url, info.sha256, info.signature, sender);

        cx.spawn(async move |this, cx| {
            while let Some(progress) = receiver.recv().await {
                let percent = progress.percent.min(100);
                let _ = this.update(cx, |shell, cx| {
                    shell.download_percent = percent;
                    cx.notify();
                });
            }

            // On success the process exits; only report an error here.
            if let Ok(Err(err)) = handle.await {
                log::error!("Update download failed: {err}");
                let _ = this.update(cx, |shell, cx| {
                    shell.downloading = false;
                    shell.update_failed = true;
                    cx.notify();
                });
            }
        })
        .detach();
    }

    fn consent_view(&self, cx: &mut Context<Self>) -> AnyElement {
        let language = i18n::language();
        let scrolled = self.consent_scrolled;

        v_flex()
            .flex_1()
            .items_center()
            .justify_center()
            .p_6()
            .child(
                v_flex()
                    .w(px(480.))
                    .gap_3()
                    .p_6()
                    .rounded(px(14.))
                    .bg(theme::dialog(cx))
                    .border_1()
                    .border_color(theme::border_light(cx))
                    .shadow_lg()
                    .child(
                        h_flex()
                            .items_center()
                            .gap_2()
                            .child(
                                Icon::default().path(mdi("shield-alert-outline"))
                                    .size_6()
                                    .text_color(cx.theme().warning),
                            )
                            .child(
                                div()
                                    .text_lg()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(i18n::t("DISCLAIMER_TITLE")),
                            ),
                    )
                    .child(
                        h_flex()
                            .gap_2()
                            .child(language_button(
                                "consent-lang-en",
                                "English",
                                language == i18n::Language::En,
                                i18n::Language::En,
                                cx,
                            ))
                            .child(language_button(
                                "consent-lang-zh",
                                "中文",
                                language == i18n::Language::ZhCn,
                                i18n::Language::ZhCn,
                                cx,
                            )),
                    )
                    .child(
                        div()
                            .id("consent-text")
                            .h(px(180.))
                            .pr_4()
                            .track_scroll(&self.consent_scroll)
                            .overflow_y_scrollbar()
                            .text_sm()
                            .text_color(theme::text_muted(cx))
                            .child(i18n::t("DISCLAIMER_TEXT")),
                    )
                    .child(
                        h_flex()
                            .justify_end()
                            .gap_2()
                            .child(
                                Button::new("consent-disagree")
                                    .danger()
                                    .label(i18n::t("CONSENT_DISAGREE"))
                                    .on_click(|_, _, cx| cx.quit()),
                            )
                            .child(
                                Button::new("consent-agree")
                                    .primary()
                                    .disabled(!scrolled)
                                    .label(i18n::t("CONSENT_AGREE"))
                                    .on_click(cx.listener(|this, _, _, cx| {
                                        this.agree_consent(cx)
                                    })),
                            ),
                    ),
            )
            .into_any_element()
    }

    fn error_view(&self, cx: &mut Context<Self>) -> AnyElement {
        let fatal = self
            .errors
            .iter()
            .any(|error| matches!(error.code, 1 | 2 | 3 | 10048));

        let mut list = v_flex().gap_2();
        for error in &self.errors {
            let color = if fatal {
                cx.theme().danger
            } else {
                cx.theme().warning
            };
            let tag = if fatal {
                i18n::t("ERR_FATAL")
            } else {
                i18n::t("ERR_WARNING")
            };

            list = list.child(
                h_flex()
                    .items_center()
                    .gap_2()
                    .child(
                        Icon::default().path(mdi(if fatal {
                            "close-circle"
                        } else {
                            "alert-circle-outline"
                        }))
                        .small()
                        .text_color(color),
                    )
                    .child(
                        div()
                            .flex_1()
                            .text_sm()
                            .child(i18n::t(&format!("ERR_{}", error.code))),
                    )
                    .child(
                        div()
                            .px_2()
                            .rounded(px(10.))
                            .bg(color.opacity(0.12))
                            .text_color(color)
                            .text_xs()
                            .child(tag),
                    ),
            );
        }

        let footer = if fatal {
            h_flex().justify_end().child(
                Button::new("error-quit")
                    .danger()
                    .label(i18n::t("QUIT_APP"))
                    .on_click(|_, _, cx| cx.quit()),
            )
        } else {
            h_flex().justify_end().child(
                Button::new("error-close")
                    .label(i18n::t("CLOSE"))
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.show_errors = false;
                        cx.notify();
                    })),
            )
        };

        v_flex()
            .flex_1()
            .items_center()
            .justify_center()
            .p_6()
            .child(
                v_flex()
                    .w(px(400.))
                    .gap_3()
                    .p_6()
                    .rounded(px(14.))
                    .bg(theme::dialog(cx))
                    .border_1()
                    .border_color(theme::border_light(cx))
                    .shadow_lg()
                    .child(
                        h_flex()
                            .items_center()
                            .gap_2()
                            .child(
                                Icon::default().path(mdi("alert"))
                                    .size_6()
                                    .text_color(cx.theme().warning),
                            )
                            .child(
                                div()
                                    .text_lg()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(i18n::t("ERR_TITLE")),
                            ),
                    )
                    .child(list)
                    .child(footer),
            )
            .into_any_element()
    }

    fn update_overlay(&self, cx: &mut Context<Self>) -> AnyElement {
        let Some(info) = &self.update_info else {
            return div().into_any_element();
        };

        let mut changes = v_flex().gap_1();
        for item in &info.changelog {
            changes = changes.child(
                div()
                    .text_sm()
                    .text_color(theme::text_muted(cx))
                    .child(format!("• {item}")),
            );
        }
        let changes = changes
            .id("update-changelog")
            .max_h(px(240.))
            .overflow_y_scrollbar();

        let footer: AnyElement = if self.downloading {
            h_flex()
                .gap_2()
                .items_center()
                .child(
                    div()
                        .flex_1()
                        .child(Progress::new("update-progress").value(
                            self.download_percent as f32,
                        )),
                )
                .child(
                    div()
                        .text_xs()
                        .text_color(theme::text_muted(cx))
                        .child(format!("{}%", self.download_percent)),
                )
                .into_any_element()
        } else {
            h_flex().justify_end().child(
                Button::new("update-download")
                    .primary()
                    .label(i18n::t("UPDATE_DOWNLOAD"))
                    .on_click(cx.listener(|this, _, _, cx| this.start_download(cx))),
            )
            .into_any_element()
        };

        let card = v_flex()
            .w(px(420.))
            .gap_3()
            .p_6()
            .rounded(px(14.))
            .bg(theme::dialog(cx))
            .border_1()
            .border_color(theme::border_light(cx))
            .shadow_lg()
            .child(
                h_flex()
                    .items_center()
                    .gap_2()
                    .child(
                        Icon::default().path(mdi("update"))
                            .size_6()
                            .text_color(cx.theme().primary),
                    )
                    .child(
                        div()
                            .text_lg()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(i18n::t("UPDATE_AVAILABLE")),
                    ),
            )
            .child(
                div()
                    .text_sm()
                    .child(format!(
                        "{} → {}",
                        info.current_version, info.latest_version
                    )),
            )
            .child(changes)
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().warning)
                    .child(i18n::t("UPDATE_REQUIRED")),
            )
            .when(self.update_failed, |this| {
                this.child(
                    div()
                        .text_sm()
                        .text_color(cx.theme().danger)
                        .child(i18n::t("UPDATE_FAILED")),
                )
            })
            .child(footer)
            .into_any_element();

        self.overlay(card)
    }

    /// 居中遮罩层：等价于 Vue 版 Modal，遮住页面并拦截鼠标事件。
    fn overlay(&self, card: AnyElement) -> AnyElement {
        div()
            .absolute()
            .inset_0()
            .occlude()
            .flex()
            .items_center()
            .justify_center()
            .bg(rgba(0x000000_66))
            .child(card)
            .into_any_element()
    }

    /// 手动检查更新、且已是最新版本时的提示弹窗。
    fn no_update_overlay(&self, cx: &mut Context<Self>) -> AnyElement {
        let card = v_flex()
            .w(px(360.))
            .gap_3()
            .p_6()
            .rounded(px(14.))
            .bg(theme::dialog(cx))
            .border_1()
            .border_color(theme::border_light(cx))
            .shadow_lg()
            .child(
                h_flex()
                    .items_center()
                    .gap_2()
                    .child(
                        Icon::default()
                            .path(mdi("information-outline"))
                            .size_6()
                            .text_color(cx.theme().primary),
                    )
                    .child(
                        div()
                            .text_lg()
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(i18n::t("CHECK_UPDATE")),
                    ),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(theme::text_secondary(cx))
                    .child(i18n::t("UPDATE_NONE")),
            )
            .child(
                h_flex().justify_end().child(
                    Button::new("no-update-close")
                        .primary()
                        .label(i18n::t("CLOSE"))
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.no_update_notice = false;
                            cx.notify();
                        })),
                ),
            )
            .into_any_element();

        self.overlay(card)
    }

    fn toggle_theme(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        let dark = !cx.theme().mode.is_dark();
        let mode = if dark {
            ThemeMode::Dark
        } else {
            ThemeMode::Light
        };

        theme::apply(cx, mode);
        self.prefs.set_theme(dark);
        self.prefs.save(&self.core.state.config_dir);

        self.dashboard.update(cx, |_, cx| cx.notify());
        cx.notify();
    }

    fn nav_item(
        &self,
        id: &'static str,
        page: Page,
        icon: &'static str,
        key: &'static str,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let active = self.page == page;
        let accent = cx.theme().primary;
        let hover_bg = cx.theme().sidebar_accent;
        let transparent = cx.theme().transparent;
        let idle_fg = cx.theme().sidebar_foreground;
        let weak = cx.weak_entity();

        h_flex()
            .id(id)
            .h(px(30.))
            .mx_2()
            .px_2()
            .gap_2()
            .flex_shrink_0()
            .cursor_pointer()
            .rounded(px(7.))
            .bg(if active {
                cx.theme().sidebar_accent
            } else {
                transparent
            })
            .text_color(if active {
                cx.theme().sidebar_accent_foreground
            } else {
                idle_fg
            })
            .hover(move |style| style.bg(hover_bg))
            .child(
                Icon::default()
                    .path(mdi(icon))
                    .small()
                    .text_color(if active { accent } else { idle_fg }),
            )
            .child(div().text_size(px(13.)).child(i18n::t(key)))
            .on_click(move |_, _, cx| {
                let _ = weak.update(cx, |this, cx| {
                    this.page = page;
                    cx.notify();
                });
            })
    }

    fn sidebar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let mut sidebar = v_flex()
            .w(px(176.))
            .h_full()
            .flex_shrink_0()
            .gap(px(2.))
            .py_3()
            .bg(cx.theme().sidebar)
            .border_r_1()
            .border_color(cx.theme().sidebar_border);

        for (page, icon, key) in NAV_ITEMS {
            sidebar = sidebar.child(self.nav_item(key, page, icon, key, cx));
        }

        sidebar
    }
}

impl Render for AppShell {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let dark = cx.theme().mode.is_dark();

        let body: AnyElement = if self.show_consent {
            self.consent_view(cx)
        } else if self.show_errors {
            self.error_view(cx)
        } else {
            let content = match self.page {
                Page::Dashboard => self.dashboard.clone().into_any_element(),
                Page::Connections => self.connections.clone().into_any_element(),
                Page::Logs => self.logs.clone().into_any_element(),
                Page::Rules => self.rules.clone().into_any_element(),
                Page::TestRule => self.test_rule.clone().into_any_element(),
                Page::Settings => self.settings.clone().into_any_element(),
                Page::Changelog => self.changelog.clone().into_any_element(),
                Page::About => self.about.clone().into_any_element(),
            };

            h_flex()
                .items_stretch()
                .flex_1()
                .min_h_0()
                .child(self.sidebar(cx))
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .pl_6()
                        .py_5()
                        .overflow_hidden()
                        .child(content),
                )
                .into_any_element()
        };

        // 版本号小字仅在 Windows 显示，颜色在外层取好，避免闭包里重复借用。
        let muted = theme::text_muted(cx);

        let mut root = v_flex()
            .size_full()
            .relative()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(
                TitleBar::new()
                    .bg(cx.theme().sidebar)
                    .border_b_0()
                    .child(
                        h_flex()
                            .items_center()
                            .gap_2()
                            // 与侧边栏导航项图标（mx_2 + px_2 = 16px）对齐
                            .pl_1()
                            .child(
                                Icon::default()
                                    .path(mdi("proxy-outline"))
                                    .w(px(15.))
                                    .h(px(15.))
                                    .text_color(cx.theme().primary),
                            )
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child("SSL Proxy Client"),
                            )
                            // Windows 显示版本号，macOS 跟随系统习惯只显示产品名，
                            // 左侧红绿灯安全区由组件内置。
                            .when(!cfg!(target_os = "macos"), |this| {
                                this.child(
                                    div()
                                        .text_size(px(10.))
                                        .text_color(muted)
                                        .child(format!("v{}", env!("CARGO_PKG_VERSION"))),
                                )
                            }),
                    )
                    .child(
                        h_flex()
                            .ml_auto()
                            .pr_2()
                            // 标题栏整条是 WindowControlArea::Drag（Windows 命中测试返回
                            // HTCAPTION），不阻断的话点击会被当成拖拽窗口，按钮收不到事件。
                            .occlude()
                            .child(
                            Button::new("theme-toggle")
                                .ghost()
                                .small()
                                .icon(Icon::default().path(mdi(if dark {
                                    "white-balance-sunny"
                                } else {
                                    "moon-waning-crescent"
                                })))
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.toggle_theme(window, cx)
                                })),
                        ),
                    ),
            )
            .child(body);

        // 更新提示以模态层叠加在页面之上（与 Vue 版 Modal 一致），不再整页替换。
        if self.show_update {
            root = root.child(self.update_overlay(cx));
        }
        if self.no_update_notice {
            root = root.child(self.no_update_overlay(cx));
        }

        root
    }
}

fn language_button(
    id: &'static str,
    label: &'static str,
    active: bool,
    language: i18n::Language,
    cx: &mut Context<AppShell>,
) -> AnyElement {
    let mut button = Button::new(id).small().label(label);
    button = if active { button.primary() } else { button.ghost() };
    button
        .on_click(cx.listener(move |this, _, _, cx| {
            this.set_language(language, cx)
        }))
        .into_any_element()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------- Dashboard ----------------

struct DashboardPage {
    info: ApiAppInfo,
    checking_update: bool,
    stats: StatsStore,
    last_flow: DataFlow,
    last_udp_flow: DataFlow,
    last_saved: Instant,
    _poll: Task<()>,
}

impl DashboardPage {
    fn new(core: Arc<Core>, cx: &mut Context<Self>) -> Self {
        let info = core.snapshot_app_info().unwrap_or_default();
        let stats = StatsStore::load(&core.state.config_dir);
        let last_flow = info.dataflow.clone();
        let last_udp_flow = core.snapshot_udp_dataflow().unwrap_or_default();

        let poll_core = core.clone();
        let config_dir = core.state.config_dir.clone();
        let poll = cx.spawn(async move |this, cx| loop {
            smol::Timer::after(Duration::from_secs(2)).await;

            let snapshot = poll_core.snapshot_app_info();
            let udp_flow = poll_core.snapshot_udp_dataflow();
            let updated = this.update(cx, |page, cx| {
                let Some(info) = snapshot else {
                    return;
                };

                // Session counters only grow; a smaller value means the proxy
                // restarted inside this process, so start a fresh delta.
                let up = info.dataflow.up.saturating_sub(page.last_flow.up);
                let down = info.dataflow.down.saturating_sub(page.last_flow.down);
                page.last_flow = info.dataflow.clone();

                page.stats.observe_connections(info.connections);
                page.stats.record(&stats::today_key(), up, down);

                // UDP relay traffic feeds its own counters (and the day chart).
                let mut udp_notify = false;
                if let Some(udp) = udp_flow {
                    let up_udp = udp.up.saturating_sub(page.last_udp_flow.up);
                    let down_udp = udp.down.saturating_sub(page.last_udp_flow.down);
                    page.last_udp_flow = udp;
                    if up_udp > 0 || down_udp > 0 {
                        page.stats.record_udp(&stats::today_key(), up_udp, down_udp);
                        udp_notify = true;
                    }
                }

                let changed = page.info != info;
                page.info = info;

                if page.last_saved.elapsed() >= Duration::from_secs(30) {
                    page.stats.save(&config_dir);
                    page.last_saved = Instant::now();
                }

                if changed || udp_notify || up > 0 || down > 0 {
                    cx.notify();
                }
            });

            if updated.is_err() {
                break;
            }
        });

        Self {
            info,
            checking_update: false,
            stats,
            last_flow,
            last_udp_flow,
            last_saved: Instant::now(),
            _poll: poll,
        }
    }

    fn check_update(&mut self, cx: &mut Context<Self>) {
        if self.checking_update {
            return;
        }

        self.checking_update = true;
        UPDATE_REQUESTED.store(true, Ordering::Relaxed);
        cx.notify();
    }
}

impl Render for DashboardPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let proxy = if self.info.proxy_server.is_empty() {
            "—".to_string()
        } else {
            self.info.proxy_server.clone()
        };
        let purple = Hsla::from(rgb(0xaf52de));
        let success = cx.theme().success;
        let warning = cx.theme().warning;
        let total_traffic = self
            .stats
            .total_up
            .saturating_add(self.stats.total_down)
            .saturating_add(self.stats.total_up_udp)
            .saturating_add(self.stats.total_down_udp);
        let days = self.stats.recent(&stats::today_key(), 7);
        let today = days.last().cloned().unwrap_or_default();

        v_flex()
            .size_full()
            .pr_6()
            .child(
                h_flex()
                    .items_center()
                    .justify_between()
                    .mb_4()
                    .child(
                        div()
                            .text_size(px(20.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(i18n::t("APP_INFO")),
                    )
                    .child(
                        h_flex()
                            .items_center()
                            .gap_2()
                            .when(UPDATES_SUPPORTED, |this| {
                                this.child(
                                    Button::new("check-update")
                                        .label(if self.checking_update {
                                            i18n::t("CHECKING_UPDATE")
                                        } else {
                                            i18n::t("CHECK_UPDATE")
                                        })
                                        .icon(Icon::default().path(mdi(if self.checking_update {
                                            "loading"
                                        } else {
                                            "cloud-download-outline"
                                        })))
                                        .disabled(self.checking_update)
                                        .on_click(cx.listener(|this, _, _, cx| {
                                            this.check_update(cx)
                                        })),
                                )
                            })
                            .child(
                                Button::new("quit")
                                    .danger()
                                    .label(i18n::t("QUIT_APP"))
                                    .icon(Icon::default().path(mdi("exit-to-app")))
                                    .on_click(|_, _, cx| cx.quit()),
                            ),
                    ),
            )
            .child(
                v_flex()
                    .gap_3()
                    .child(
                        h_flex()
                            .items_stretch()
                            .gap_3()
                            .child(stat_card(
                                i18n::t("SOCKS_PORT"),
                                self.info.socks_port.to_string(),
                                "serial-port",
                                cx.theme().primary.opacity(0.12),
                                cx.theme().primary,
                                None,
                                cx,
                            ))
                            .child(stat_card(
                                i18n::t("PROXY_SERVER"),
                                proxy,
                                "virtual-private-network",
                                purple.opacity(0.14),
                                purple,
                                None,
                                cx,
                            )),
                    )
                    .child(
                        h_flex()
                            .items_stretch()
                            .gap_3()
                            .child(stat_card(
                                i18n::t("CONNECTIONS"),
                                self.info.connections.to_string(),
                                "link",
                                success.opacity(0.14),
                                success,
                                Some(format!(
                                    "{} {}",
                                    i18n::t("DASH_PEAK"),
                                    self.stats.peak_connections
                                )),
                                cx,
                            ))
                            .child(stat_card(
                                i18n::t("DASH_TOTAL_TRAFFIC"),
                                util::format_bytes(total_traffic),
                                "math-log",
                                warning.opacity(0.14),
                                warning,
                                Some(format!(
                                    "{} {} {} · {} {}",
                                    i18n::t("DASH_TODAY"),
                                    i18n::t("DASH_UP"),
                                    util::format_bytes(today.up),
                                    i18n::t("DASH_DOWN"),
                                    util::format_bytes(today.down)
                                )),
                                cx,
                            )),
                    )
                    .child(traffic_chart_card(&days, cx))
                    .child(dataflow_card(self.info.dataflow.clone(), cx)),
            )
    }
}

fn stat_card(
    title: String,
    value: String,
    icon: &'static str,
    icon_bg: Hsla,
    icon_fg: Hsla,
    hint: Option<String>,
    cx: &App,
) -> AnyElement {
    let hover_bg = theme::card_hover(cx);
    let hover_border = cx.theme().border;

    h_flex()
        .flex_1()
        .items_center()
        .gap_3()
        .py_3()
        .px_4()
        .rounded(px(10.))
        .bg(theme::card(cx))
        .border_1()
        .border_color(theme::border_light(cx))
        .shadow_xs()
        .hover(move |style| style.bg(hover_bg).border_color(hover_border))
        .child(
            div()
                .w(px(40.))
                .h(px(40.))
                .flex_shrink_0()
                .rounded(px(10.))
                .flex()
                .items_center()
                .justify_center()
                .bg(icon_bg)
                .child(
                    Icon::default()
                        .path(mdi(icon))
                        .w(px(22.))
                        .h(px(22.))
                        .text_color(icon_fg),
                ),
        )
        .child(
            v_flex()
                .gap(px(3.))
                .min_w_0()
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(theme::text_muted(cx))
                        .child(title.to_uppercase()),
                )
                .child(
                    div()
                        .text_size(px(14.))
                        .font_weight(FontWeight::MEDIUM)
                        .child(value),
                )
                .when_some(hint, |this, hint| {
                    this.child(
                        div()
                            .text_size(px(10.))
                            .text_color(theme::text_muted(cx))
                            .child(hint),
                    )
                }),
        )
        .into_any_element()
}

/// Seven-day traffic chart: an interactive bar chart with hover tooltips.
fn traffic_chart_card(days: &[stats::DailyTraffic], cx: &App) -> AnyElement {
    let seven_day_total = days.iter().fold(0u64, |sum, day| {
        sum.saturating_add(day.up).saturating_add(day.down)
    });
    let muted = theme::text_muted(cx);
    let primary = cx.theme().primary;
    let success = cx.theme().success;

    let chart: AnyElement = if seven_day_total == 0 {
        h_flex()
            .w_full()
            .h(px(150.))
            .items_center()
            .justify_center()
            .child(
                div()
                    .text_size(px(12.))
                    .text_color(muted)
                    .child(i18n::t("DASH_NO_DATA")),
            )
            .into_any_element()
    } else {
        let up_label = i18n::t("DASH_UP");
        let down_label = i18n::t("DASH_DOWN");
        let total_label = i18n::t("DASH_TOTAL");

        BarChart::new(days.to_vec())
            .name(i18n::t("DASH_TRAFFIC_7D"))
            .band(|day: &stats::DailyTraffic| day.date.clone())
            .value(|day: &stats::DailyTraffic| day.up.saturating_add(day.down) as f64)
            .label(|day: &stats::DailyTraffic| stats::short_label(&day.date))
            .label_color(move |_: &stats::DailyTraffic| muted)
            .label_axis(true)
            .value_axis(true)
            .value_tick_count(3)
            .value_tick_format(|value| util::format_bytes(value.max(0.) as u64))
            .grid(true)
            .grid_dashed(true)
            .corner_radii(Corners::all(px(4.)))
            .fill(move |_: &stats::DailyTraffic, _, _, _| primary)
            .tooltip_title(|day: &stats::DailyTraffic| day.date.clone().into())
            .tooltip_content(move |day: &stats::DailyTraffic, _, cx| {
                let row = |label: String, value: String, color: Hsla| {
                    h_flex()
                        .w_full()
                        .justify_between()
                        .gap_4()
                        .child(
                            div()
                                .text_size(px(12.))
                                .text_color(color)
                                .child(label),
                        )
                        .child(div().text_size(px(12.)).child(value))
                };
                let total = day.up.saturating_add(day.down);
                v_flex()
                    .w(px(180.))
                    .gap_1()
                    .child(row(format!("↑ {up_label}"), util::format_bytes(day.up), success))
                    .child(row(
                        format!("↓ {down_label}"),
                        util::format_bytes(day.down),
                        primary,
                    ))
                    .child(
                        h_flex()
                            .w_full()
                            .justify_between()
                            .gap_4()
                            .pt_1()
                            .border_t_1()
                            .border_color(cx.theme().border)
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .font_weight(FontWeight::MEDIUM)
                                    .child(total_label.clone()),
                            )
                            .child(
                                div()
                                    .text_size(px(12.))
                                    .font_weight(FontWeight::MEDIUM)
                                    .child(util::format_bytes(total)),
                            ),
                    )
            })
            .into_any_element()
    };

    v_flex()
        .w_full()
        .gap_3()
        .p_4()
        .rounded(px(10.))
        .bg(theme::card(cx))
        .border_1()
        .border_color(theme::border_light(cx))
        .shadow_xs()
        .child(
            h_flex()
                .items_start()
                .justify_between()
                .gap_3()
                .child(
                    v_flex()
                        .gap(px(2.))
                        .child(
                            div()
                                .text_size(px(13.))
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(i18n::t("DASH_TRAFFIC_7D")),
                        )
                        .child(
                            div()
                                .text_size(px(10.))
                                .text_color(muted)
                                .child(i18n::t("DASH_CHART_HINT")),
                        ),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(muted)
                        .child(format!(
                            "{} {}",
                            i18n::t("DASH_7D_TOTAL"),
                            util::format_bytes(seven_day_total)
                        )),
                ),
        )
        .child(div().w_full().h(px(150.)).child(chart))
        .into_any_element()
}

fn dataflow_card(flow: crate::core::types::DataFlow, cx: &App) -> AnyElement {
    let hover_bg = theme::card_hover(cx);
    let hover_border = cx.theme().border;

    h_flex()
        .w_full()
        .items_center()
        .gap_3()
        .py_3()
        .px_4()
        .rounded(px(10.))
        .bg(theme::card(cx))
        .border_1()
        .border_color(theme::border_light(cx))
        .shadow_xs()
        .hover(move |style| style.bg(hover_bg).border_color(hover_border))
        .child(
            div()
                .w(px(40.))
                .h(px(40.))
                .flex_shrink_0()
                .rounded(px(10.))
                .flex()
                .items_center()
                .justify_center()
                .bg(cx.theme().warning.opacity(0.14))
                .child(
                    Icon::default()
                        .path(mdi("swap-calls"))
                        .w(px(22.))
                        .h(px(22.))
                        .text_color(cx.theme().warning),
                ),
        )
        .child(
            v_flex()
                .gap(px(3.))
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(theme::text_muted(cx))
                        .child(i18n::t("DATAFLOW").to_uppercase()),
                )
                .child(
                    h_flex()
                        .gap_3()
                        .child(flow_item(
                            "arrow-up-thin",
                            util::format_bytes(flow.up),
                            cx.theme().success,
                        ))
                        .child(flow_item(
                            "arrow-down-thin",
                            util::format_bytes(flow.down),
                            cx.theme().primary,
                        ))
                        .child(flow_item(
                            "swap-calls",
                            util::format_bytes(flow.total),
                            theme::text_secondary(cx),
                        )),
                ),
        )
        .into_any_element()
}

fn flow_item(icon: &'static str, text: String, color: Hsla) -> AnyElement {
    h_flex()
        .items_center()
        .gap(px(3.))
        .text_size(px(12.))
        .text_color(color)
        .child(
            Icon::default()
                .path(mdi(icon))
                .w(px(14.))
                .h(px(14.)),
        )
        .child(text)
        .into_any_element()
}
