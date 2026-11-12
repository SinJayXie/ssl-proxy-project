use crate::core::types::{AppConfig, UdpMode};
use crate::core::Core;
use crate::ui::assets::mdi;
use crate::ui::prefs::Prefs;
use crate::ui::{i18n, theme};
use gpui_kit::base::{h_flex, v_flex};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::combobox::{Combobox, ComboboxState};
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::component::searchable_list::SearchableVec;
use gpui_kit::component::select::{Select, SelectState};
use gpui_kit::component::switch::Switch;
use gpui_kit::component::scroll::ScrollableElement;
use gpui_kit::component::WindowExt as _;
use gpui_kit::component::{ActiveTheme as _, Disableable as _, Icon, IndexPath, Sizable as _};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use once_cell::sync::Lazy;
use regex::Regex;
use std::sync::Arc;

type GeoCombo = Entity<ComboboxState<SearchableVec<SharedString>>>;
type UdpModeSelect = Entity<SelectState<SearchableVec<SharedString>>>;

static IP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(\d{1,3}\.){3}\d{1,3}$").expect("valid ip regex"));

fn udp_mode_labels() -> Vec<SharedString> {
    vec![
        i18n::t("UDP_MODE_OFF").into(),
        i18n::t("UDP_MODE_DIRECT").into(),
        i18n::t("UDP_MODE_PROXY").into(),
    ]
}

fn udp_mode_index(mode: UdpMode) -> usize {
    match mode {
        UdpMode::Off => 0,
        UdpMode::Direct => 1,
        UdpMode::Proxy => 2,
    }
}

fn udp_mode_from_index(index: usize) -> UdpMode {
    match index {
        1 => UdpMode::Direct,
        2 => UdpMode::Proxy,
        _ => UdpMode::Off,
    }
}

struct SettingsInputs {
    socks_port: Entity<InputState>,
    proxy_server: Entity<InputState>,
    proxy_port: Entity<InputState>,
    proxy_password: Entity<InputState>,
    sni_name: Entity<InputState>,
    bind_ips: Vec<Entity<InputState>>,
    dns_servers: Vec<Entity<InputState>>,
    directs: GeoCombo,
    udp_mode: UdpModeSelect,
}

impl SettingsInputs {
    fn new(
        config: &AppConfig,
        countries: &[crate::core::types::CountryCodeItem],
        window: &mut Window,
        cx: &mut Context<SettingsPage>,
    ) -> Self {
        let socks_port = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(config.socks_port.to_string())
                .placeholder("1080")
        });
        let proxy_server = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(config.proxy_server.clone())
                .placeholder("proxy.example.com")
        });
        let proxy_port = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(config.proxy_port.to_string())
                .placeholder("443")
        });
        let proxy_password = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(config.proxy_password.clone())
                .placeholder("****")
                .masked(true)
        });
        let sni_placeholder = if config.proxy_server.is_empty() {
            "proxy.example.com".to_string()
        } else {
            config.proxy_server.clone()
        };
        let sni_name = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value(config.sni_name.clone())
                .placeholder(sni_placeholder)
        });

        let bind_ips = config
            .bind_ips
            .iter()
            .map(|ip| {
                cx.new(|cx| {
                    InputState::new(window, cx)
                        .default_value(ip.clone())
                        .placeholder("0.0.0.0")
                })
            })
            .collect();

        let dns_servers = config
            .dns_servers
            .iter()
            .map(|ip| {
                cx.new(|cx| {
                    InputState::new(window, cx)
                        .default_value(ip.clone())
                        .placeholder("8.8.8.8")
                })
            })
            .collect();

        let labels: Vec<SharedString> = countries
            .iter()
            .map(|country| country_label(country).into())
            .collect();
        let selected: Vec<IndexPath> = config
            .directs
            .iter()
            .filter_map(|code| {
                countries
                    .iter()
                    .position(|country| country.alpha2_code.eq_ignore_ascii_case(code))
                    .map(IndexPath::new)
            })
            .collect();

        let directs = cx.new(|cx| {
            ComboboxState::new(SearchableVec::new(labels), selected, window, cx)
                .multiple(true)
                .searchable(true)
        });

        let udp_labels = udp_mode_labels();
        let udp_selected = IndexPath::new(udp_mode_index(config.udp_mode));
        let udp_mode = cx.new(|cx| {
            SelectState::new(SearchableVec::new(udp_labels), Some(udp_selected), window, cx)
        });

        Self {
            socks_port,
            proxy_server,
            proxy_port,
            proxy_password,
            sni_name,
            bind_ips,
            dns_servers,
            directs,
            udp_mode,
        }
    }
}

pub struct SettingsPage {
    core: Arc<Core>,
    config: AppConfig,
    countries: Vec<crate::core::types::CountryCodeItem>,
    inputs: SettingsInputs,
    tls_skip: bool,
    mux_enabled: bool,
    error: Option<String>,
}

impl SettingsPage {
    pub fn new(core: Arc<Core>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let config = core.snapshot_config().unwrap_or_default();
        let countries = core.geo_countries();
        let inputs = SettingsInputs::new(&config, &countries, window, cx);

        Self {
            core,
            config: config.clone(),
            countries,
            inputs,
            tls_skip: config.danger_accept_invalid_certs,
            mux_enabled: config.mux_enabled,
            error: None,
        }
    }

    fn toggle_tls(&mut self, checked: &bool, cx: &mut Context<Self>) {
        self.tls_skip = *checked;
        cx.notify();
    }

    fn toggle_mux(&mut self, checked: &bool, cx: &mut Context<Self>) {
        self.mux_enabled = *checked;
        cx.notify();
    }

    fn revert(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.inputs = SettingsInputs::new(&self.config, &self.countries, window, cx);
        self.tls_skip = self.config.danger_accept_invalid_certs;
        self.mux_enabled = self.config.mux_enabled;
        self.error = None;
        cx.notify();
    }

    fn read_config(&self, cx: &App) -> Result<AppConfig, String> {
        let socks_port = parse_port(self.inputs.socks_port.read(cx).value().as_str())
            .ok_or_else(|| i18n::t("VALIDATE_PORT_RANGE"))?;

        let proxy_server = self
            .inputs
            .proxy_server
            .read(cx)
            .value()
            .trim()
            .to_string();
        let proxy_port = parse_port(self.inputs.proxy_port.read(cx).value().as_str())
            .ok_or_else(|| i18n::t("VALIDATE_PORT_RANGE"))?;
        let proxy_password = self.inputs.proxy_password.read(cx).value().to_string();
        let sni_name = self.inputs.sni_name.read(cx).value().trim().to_string();

        if proxy_server.is_empty() && !proxy_password.is_empty() {
            return Err(i18n::t("VALIDATE_SERVER_REQUIRED"));
        }
        if !proxy_password.is_empty() && proxy_password.len() < 6 {
            return Err(i18n::t("VALIDATE_PASSWORD_LENGTH"));
        }

        let bind_ips: Vec<String> = self
            .inputs
            .bind_ips
            .iter()
            .map(|state| state.read(cx).value().to_string())
            .collect();
        for ip in &bind_ips {
            if ip.trim().is_empty() {
                return Err(i18n::t("VALIDATE_IP_EMPTY"));
            }
            if !IP_RE.is_match(ip.trim()) {
                return Err(format!("{}: {}", i18n::t("VALIDATE_INVALID_IP"), ip));
            }
        }

        let dns_servers: Vec<String> = self
            .inputs
            .dns_servers
            .iter()
            .map(|state| state.read(cx).value().to_string())
            .collect();
        for ip in &dns_servers {
            if ip.trim().is_empty() {
                return Err(i18n::t("VALIDATE_IP_EMPTY"));
            }
            if !IP_RE.is_match(ip.trim()) {
                return Err(format!("{}: {}", i18n::t("VALIDATE_INVALID_IP"), ip));
            }
        }

        let selected_labels = self.inputs.directs.read(cx).selected_values();
        let directs = selected_labels
            .iter()
            .filter_map(|label| {
                self.countries
                    .iter()
                    .find(|country| country_label(country).as_str() == label.as_ref())
                    .map(|country| country.alpha2_code.clone())
            })
            .collect();

        let udp_mode = {
            let labels = udp_mode_labels();
            let selected = self.inputs.udp_mode.read(cx).selected_value();
            selected
                .and_then(|label| {
                    labels
                        .iter()
                        .position(|l| l.as_ref() == label.as_ref())
                })
                .map(udp_mode_from_index)
                .unwrap_or(UdpMode::Off)
        };

        Ok(AppConfig {
            socks_port,
            proxy_server,
            proxy_port,
            proxy_password,
            directs,
            bind_ips,
            dns_servers,
            danger_accept_invalid_certs: self.tls_skip,
            sni_name,
            mux_enabled: self.mux_enabled,
            udp_mode,
        })
    }

    fn add_bind_ip(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let state = cx.new(|cx| InputState::new(window, cx).placeholder("0.0.0.0"));
        self.inputs.bind_ips.push(state);
        self.error = None;
        cx.notify();
    }

    fn remove_bind_ip(&mut self, index: usize, cx: &mut Context<Self>) {
        if index < self.inputs.bind_ips.len() {
            self.inputs.bind_ips.remove(index);
            self.error = None;
            cx.notify();
        }
    }

    fn add_dns_server(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let state = cx.new(|cx| InputState::new(window, cx).placeholder("8.8.8.8"));
        self.inputs.dns_servers.push(state);
        self.error = None;
        cx.notify();
    }

    fn remove_dns_server(&mut self, index: usize, cx: &mut Context<Self>) {
        if index < self.inputs.dns_servers.len() {
            self.inputs.dns_servers.remove(index);
            self.error = None;
            cx.notify();
        }
    }

    fn collect_config(&mut self, cx: &mut Context<Self>) -> Option<AppConfig> {
        match self.read_config(cx) {
            Ok(config) => Some(config),
            Err(error) => {
                self.error = Some(error);
                cx.notify();
                None
            }
        }
    }

    fn save(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.error = None;
        let Some(config) = self.collect_config(cx) else {
            return;
        };

        let core = self.core.clone();
        window.open_dialog(cx, move |dialog, _, cx| {
            let core = core.clone();
            let config = config.clone();

            dialog
                .w(px(380.))
                .title(i18n::t("CONFIRM_SAVE_TITLE"))
                .child(
                    h_flex()
                        .items_start()
                        .gap_2()
                        .child(
                            Icon::default()
                                .path(mdi("alert"))
                                .w(px(20.))
                                .h(px(20.))
                                .text_color(cx.theme().warning),
                        )
                        .child(
                            div()
                                .text_size(px(12.))
                                .child(i18n::t("CONFIRM_SAVE_PROMPT")),
                        ),
                )
                .footer(
                    h_flex()
                        .justify_end()
                        .gap_2()
                        .child(
                            Button::new("save-cancel")
                                .label(i18n::t("CANCEL"))
                                .on_click(|_, window, cx| window.close_dialog(cx)),
                        )
                        .child(
                            Button::new("save-restart")
                                .primary()
                                .icon(Icon::default().path(mdi("restart")))
                                .label(i18n::t("CONFIRM_SAVE_AND_RESTART"))
                                .on_click(move |_, _, cx| {
                                    let handle = core.save_config(config.clone());
                                    let core = core.clone();
                                    cx.spawn(async move |cx| {
                                        if let Ok(Ok(true)) = handle.await {
                                            if let Err(err) = core.restart_process() {
                                                log::error!("Failed to restart: {err}");
                                            }
                                            cx.update(|cx| cx.quit());
                                        }
                                    })
                                    .detach();
                                }),
                        ),
                )
        });
    }

    fn open_language_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let weak = cx.weak_entity();
        let current = i18n::language();

        window.open_dialog(cx, move |dialog, _, _| {
            dialog
                .w(px(320.))
                .title(i18n::t("LANGUAGE"))
                .child(
                    v_flex()
                        .gap_2()
                        .child(language_option(
                            "settings-lang-en",
                            "English",
                            current == i18n::Language::En,
                            weak.clone(),
                            i18n::Language::En,
                        ))
                        .child(language_option(
                            "settings-lang-zh",
                            "中文",
                            current == i18n::Language::ZhCn,
                            weak.clone(),
                            i18n::Language::ZhCn,
                        )),
                )
                .footer(
                    h_flex().justify_end().child(
                        Button::new("lang-cancel")
                            .label(i18n::t("CANCEL"))
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    ),
                )
        });
    }

    fn set_language(&mut self, language: i18n::Language, cx: &mut Context<Self>) {
        i18n::set_language(language);
        let mut prefs = Prefs::load(&self.core.state.config_dir);
        prefs.set_language(language);
        prefs.save(&self.core.state.config_dir);
        cx.notify();
    }
}

impl Render for SettingsPage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let validation_error = self.read_config(cx).err();
        let has_changes = validation_error.is_none()
            && self
                .read_config(cx)
                .map(|config| config != self.config)
                .unwrap_or(false);

        // 代理：本地端口、上游代理（两列布局）
        let proxy_card = section(
            i18n::t("SETTINGS_PROXY"),
            i18n::t("SETTINGS_PROXY_DESC"),
            cx,
            v_flex()
                .w_full()
                .gap_3()
                .child(
                    h_flex()
                        .items_start()
                        .gap_3()
                        .child(field(
                            i18n::t("LOCAL_PROXY_PORT"),
                            None,
                            cx,
                            Input::new(&self.inputs.socks_port).into_any_element(),
                        ))
                        .child(field(
                            i18n::t("PROXY_SERVER"),
                            None,
                            cx,
                            Input::new(&self.inputs.proxy_server).into_any_element(),
                        )),
                )
                .child(
                    h_flex()
                        .items_start()
                        .gap_3()
                        .child(field(
                            i18n::t("PROXY_PORT"),
                            None,
                            cx,
                            Input::new(&self.inputs.proxy_port).into_any_element(),
                        ))
                        .child(field(
                            i18n::t("PROXY_PASSWORD"),
                            None,
                            cx,
                            Input::new(&self.inputs.proxy_password)
                                .mask_toggle()
                                .into_any_element(),
                        )),
                )
                .into_any_element(),
        );

        // TLS / SNI
        let tls_card = section(
            i18n::t("SETTINGS_TLS"),
            i18n::t("SETTINGS_TLS_DESC"),
            cx,
            v_flex()
                .w_full()
                .gap_3()
                .child(
                    h_flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .child(
                            v_flex()
                                .gap(px(2.))
                                .child(
                                    div()
                                        .text_size(px(13.))
                                        .child(i18n::t("TLS_VERIFY_SKIP")),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(theme::text_muted(cx))
                                        .child(if self.tls_skip {
                                            i18n::t("TLS_VERIFY_SKIP_ON")
                                        } else {
                                            i18n::t("TLS_VERIFY_SKIP_OFF")
                                        }),
                                ),
                        )
                        .child(
                            Switch::new("tls-skip")
                                .checked(self.tls_skip)
                                .on_change(cx.listener(|this, checked, _, cx| {
                                    this.toggle_tls(checked, cx)
                                })),
                        ),
                )
                .child(field(
                    i18n::t("SNI_NAME"),
                    Some(i18n::t("SNI_NAME_HINT")),
                    cx,
                    Input::new(&self.inputs.sni_name).into_any_element(),
                ))
                .child(
                    h_flex()
                        .items_center()
                        .justify_between()
                        .gap_3()
                        .child(
                            v_flex()
                                .gap(px(2.))
                                .child(
                                    div()
                                        .text_size(px(13.))
                                        .child(i18n::t("MUX_ENABLED")),
                                )
                                .child(
                                    div()
                                        .text_size(px(11.))
                                        .text_color(theme::text_muted(cx))
                                        .child(if self.mux_enabled {
                                            i18n::t("MUX_ENABLED_ON")
                                        } else {
                                            i18n::t("MUX_ENABLED_OFF")
                                        }),
                                ),
                        )
                        .child(
                            Switch::new("mux-enabled")
                                .checked(self.mux_enabled)
                                .on_change(cx.listener(|this, checked, _, cx| {
                                    this.toggle_mux(checked, cx)
                                })),
                        ),
                )
                .into_any_element(),
        );

        // 绑定 IP 行
        let mut bind_rows = v_flex().w_full().gap(px(6.));
        for (index, state) in self.inputs.bind_ips.iter().enumerate() {
            let weak = cx.weak_entity();
            bind_rows = bind_rows.child(
                h_flex()
                    .items_center()
                    .gap(px(4.))
                    .child(div().flex_1().min_w_0().child(Input::new(state)))
                    .child(
                        Button::new(ElementId::Name(format!("bind-remove-{index}").into()))
                            .danger()
                            .icon(Icon::default().path(mdi("minus")))
                            .on_click(move |_, _, cx| {
                                let _ = weak.update(cx, |page, cx| {
                                    page.remove_bind_ip(index, cx);
                                });
                            }),
                    ),
            );
        }

        // DNS 服务器行
        let mut dns_rows = v_flex().w_full().gap(px(6.));
        for (index, state) in self.inputs.dns_servers.iter().enumerate() {
            let weak = cx.weak_entity();
            dns_rows = dns_rows.child(
                h_flex()
                    .items_center()
                    .gap(px(4.))
                    .child(div().flex_1().min_w_0().child(Input::new(state)))
                    .child(
                        Button::new(ElementId::Name(format!("dns-remove-{index}").into()))
                            .danger()
                            .icon(Icon::default().path(mdi("minus")))
                            .on_click(move |_, _, cx| {
                                let _ = weak.update(cx, |page, cx| {
                                    page.remove_dns_server(index, cx);
                                });
                            }),
                    ),
            );
        }

        // 网络：绑定地址与 DNS 并排两列
        let network_card = section(
            i18n::t("SETTINGS_NETWORK"),
            i18n::t("SETTINGS_NETWORK_DESC"),
            cx,
            h_flex()
                .items_start()
                .gap_4()
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .gap(px(6.))
                        .child(field_label(i18n::t("BIND_IPS"), cx))
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(theme::text_muted(cx))
                                .child(i18n::t("BIND_IPS_HINT")),
                        )
                        .child(bind_rows)
                        .child(
                            Button::new("bind-add")
                                .small()
                                .icon(Icon::default().path(mdi("plus")))
                                .label(i18n::t("ADD"))
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.add_bind_ip(window, cx)
                                })),
                        ),
                )
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .gap(px(6.))
                        .child(field_label(i18n::t("DNS_SERVERS"), cx))
                        .child(
                            div()
                                .text_size(px(11.))
                                .text_color(theme::text_muted(cx))
                                .child(i18n::t("DNS_SERVERS_HINT")),
                        )
                        .child(dns_rows)
                        .child(
                            Button::new("dns-add")
                                .small()
                                .icon(Icon::default().path(mdi("plus")))
                                .label(i18n::t("ADD"))
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.add_dns_server(window, cx)
                                })),
                        ),
                )
                .into_any_element(),
        );

        // 路由：UDP 模式 + 直连地区
        let routing_card = section(
            i18n::t("SETTINGS_ROUTING"),
            i18n::t("SETTINGS_ROUTING_DESC"),
            cx,
            v_flex()
                .w_full()
                .gap_3()
                .child(field(
                    i18n::t("UDP_MODE"),
                    Some(i18n::t("UDP_MODE_HINT")),
                    cx,
                    div()
                        .w_full()
                        .child(Select::new(&self.inputs.udp_mode))
                        .into_any_element(),
                ))
                .child(
                    div()
                        .w_full()
                        .child(
                            Combobox::new(&self.inputs.directs)
                                .placeholder(i18n::t("SELECT_COUNTRIES")),
                        )
                        .into_any_element(),
                )
                .into_any_element(),
        );

        let mut content = v_flex()
            .w_full()
            .max_w(px(760.))
            .gap_3()
            .pb_4()
            .child(proxy_card)
            .child(tls_card)
            .child(network_card)
            .child(routing_card);

        if let Some(error) = self.error.as_ref().or(validation_error.as_ref()) {
            content = content.child(
                h_flex()
                    .w_full()
                    .items_start()
                    .gap_2()
                    .p_3()
                    .rounded(px(8.))
                    .border_1()
                    .border_color(cx.theme().danger)
                    .child(
                        Icon::default()
                            .path(mdi("alert"))
                            .w(px(16.))
                            .h(px(16.))
                            .text_color(cx.theme().danger),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .text_size(px(12.))
                            .text_color(cx.theme().danger)
                            .child(error.clone()),
                    ),
            );
        }

        v_flex()
            .size_full()
            .gap_4()
            .child(
                v_flex()
                    .gap(px(2.))
                    .pr_6()
                    .child(
                        div()
                            .text_size(px(20.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child(i18n::t("SETTINGS")),
                    )
                    .child(
                        div()
                            .text_size(px(11.))
                            .text_color(theme::text_muted(cx))
                            .child(i18n::t("SETTINGS_RESTART_HINT")),
                    ),
            )
            .child(
                div()
                    .id("settings-scroll")
                    .flex_1()
                    .min_h_0()
                    // 右侧留白由滚动容器自己提供，滚动条才能贴住窗口右缘
                    .pr_6()
                    .overflow_y_scrollbar()
                    .child(content),
            )
            .child(
                h_flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .pr_6()
                    .pt_3()
                    .pb_3()
                    .border_t_1()
                    .border_color(theme::border_light(cx))
                    .bg(cx.theme().background)
                    .child(
                        Button::new("settings-language")
                            .icon(Icon::default().path(mdi("translate")))
                            .label(format!(
                                "{}: {}",
                                i18n::t("LANGUAGE"),
                                current_language_label()
                            ))
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.open_language_dialog(window, cx)
                            })),
                    )
                    .child(
                        h_flex()
                            .items_center()
                            .gap_2()
                            .when(has_changes, |this| {
                                this.child(
                                    Button::new("settings-revert")
                                        .icon(Icon::default().path(mdi("undo")))
                                        .label(i18n::t("REVERT"))
                                        .on_click(cx.listener(|this, _, window, cx| {
                                            this.revert(window, cx)
                                        })),
                                )
                            })
                            .child(
                                Button::new("settings-save")
                                    .primary()
                                    .icon(Icon::default().path(mdi("content-save-outline")))
                                    .disabled(!has_changes)
                                    .label(i18n::t("SAVE"))
                                    .on_click(cx.listener(|this, _, window, cx| {
                                        this.save(window, cx)
                                    })),
                            ),
                    ),
            )
    }
}

fn language_option(
    id: &'static str,
    label: &'static str,
    active: bool,
    weak: WeakEntity<SettingsPage>,
    language: i18n::Language,
) -> AnyElement {
    let mut button = Button::new(id).label(label);
    button = if active { button.primary() } else { button };
    button
        .on_click(move |_, window, cx| {
            let _ = weak.update(cx, |page, cx| page.set_language(language, cx));
            window.close_dialog(cx);
        })
        .into_any_element()
}

fn section(title: String, desc: String, cx: &App, content: AnyElement) -> AnyElement {
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
            v_flex()
                .gap(px(2.))
                .child(
                    div()
                        .text_size(px(13.))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(title),
                )
                .child(
                    div()
                        .text_size(px(11.))
                        .text_color(theme::text_muted(cx))
                        .child(desc),
                ),
        )
        .child(content)
        .into_any_element()
}

fn field(label: String, hint: Option<String>, cx: &App, control: AnyElement) -> AnyElement {
    v_flex()
        .flex_1()
        .min_w_0()
        .gap(px(4.))
        .child(field_label(label, cx))
        .child(div().w_full().child(control))
        .when_some(hint, |this, hint| {
            this.child(
                div()
                    .text_size(px(11.))
                    .text_color(theme::text_muted(cx))
                    .child(hint),
            )
        })
        .into_any_element()
}

fn field_label(text: String, cx: &App) -> AnyElement {
    div()
        .text_size(px(12.))
        .text_color(theme::text_secondary(cx))
        .child(text)
        .into_any_element()
}

fn current_language_label() -> &'static str {
    match i18n::language() {
        i18n::Language::En => "English",
        i18n::Language::ZhCn => "中文",
    }
}

fn parse_port(value: &str) -> Option<u16> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .filter(|port| *port > 0)
}

fn country_label(country: &crate::core::types::CountryCodeItem) -> String {
    format!("{} ({})", country.country, country.alpha2_code)
}
