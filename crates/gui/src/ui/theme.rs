use gpui_kit::component::scroll::ScrollbarMode;
use gpui_kit::component::{ActiveTheme as _, Theme, ThemeMode};
use gpui_kit::{px, rgb, rgba, App, Hsla};

/// Apply the macOS-inspired palette used across the application.
///
/// Light: content `#f5f5f7`, cards `#ffffff`, accent `#007aff`.
/// Dark: content `#1e1e1e`, cards `#2c2c2e`, accent `#0a84ff`.
pub fn apply(cx: &mut App, mode: ThemeMode) {
    let dark = mode.is_dark();
    Theme::change(mode, None, cx);
    // 桌面端常显滚动条：GPUI 默认是 Scrolling（滚动时才淡入），
    // 这里改成 Always，避免用户以为没有滚动条。
    Theme::set_scrollbar_mode(ScrollbarMode::Always, cx);

    Theme::update(cx, move |theme| {
        // macOS controls are pill-ish: 6-7px on inputs/buttons, 12-14px on cards.
        theme.radius = px(7.);
        theme.radius_lg = px(14.);
        theme.font_family = "Segoe UI".into();
        theme.font_size = px(13.);
        theme.mono_font_family = "Consolas".into();
        theme.mono_font_size = px(12.);

        if dark {
            theme.background = rgb(0x1e1e1e).into();
            theme.foreground = rgba(0xffffff_f2).into();
            theme.secondary = rgb(0x2c2c2e).into();
            theme.secondary_hover = rgb(0x323234).into();
            theme.secondary_foreground = rgba(0xffffff_a3).into();
            theme.muted = rgb(0x2d2d2f).into();
            theme.muted_foreground = rgba(0xffffff_8c).into();
            theme.accent = rgb(0x3a3a3c).into();
            theme.border = rgb(0x3a3a3c).into();
            theme.input = rgb(0x48484a).into();
            theme.popover = rgb(0x2c2c2e).into();
            theme.popover_foreground = rgba(0xffffff_f2).into();

            theme.sidebar = rgb(0x252527).into();
            theme.sidebar_border = rgb(0x313134).into();
            theme.sidebar_foreground = rgba(0xffffff_a3).into();
            theme.sidebar_accent = rgb(0x3a3a3c).into();
            theme.sidebar_accent_foreground = rgba(0xffffff_f2).into();
            theme.sidebar_primary = rgb(0x0a84ff).into();
            theme.sidebar_primary_foreground = rgb(0xffffff).into();

            theme.title_bar = rgb(0x252527).into();
            theme.title_bar_border = rgb(0x313134).into();

            theme.primary = rgb(0x0a84ff).into();
            theme.primary_hover = rgb(0x409cff).into();
            theme.primary_active = rgb(0x0071e3).into();
            theme.primary_foreground = rgb(0xffffff).into();
            theme.link = rgb(0x0a84ff).into();
            theme.selection = rgba(0x0a84ff_3d).into();
            theme.danger = rgb(0xff453a).into();
            theme.success = rgb(0x30d158).into();
            theme.warning = rgb(0xffd60a).into();

            theme.scrollbar = rgba(0x000000_00).into();
            theme.scrollbar_thumb = rgba(0xffffff_33).into();
            theme.scrollbar_thumb_hover = rgba(0xffffff_59).into();
        } else {
            theme.background = rgb(0xf5f5f7).into();
            theme.foreground = rgb(0x1d1d1f).into();
            theme.secondary = rgb(0xffffff).into();
            theme.secondary_hover = rgb(0xf0f0f2).into();
            theme.secondary_foreground = rgb(0x6e6e73).into();
            theme.muted = rgb(0xededf0).into();
            theme.muted_foreground = rgb(0x86868b).into();
            theme.accent = rgb(0xe8e8ed).into();
            theme.border = rgb(0xd9d9de).into();
            theme.input = rgb(0xd1d1d6).into();
            theme.popover = rgb(0xffffff).into();
            theme.popover_foreground = rgb(0x1d1d1f).into();

            theme.sidebar = rgb(0xececee).into();
            theme.sidebar_border = rgb(0xdcdce0).into();
            theme.sidebar_foreground = rgb(0x5c5c61).into();
            theme.sidebar_accent = rgb(0xdedee3).into();
            theme.sidebar_accent_foreground = rgb(0x1d1d1f).into();
            theme.sidebar_primary = rgb(0x007aff).into();
            theme.sidebar_primary_foreground = rgb(0xffffff).into();

            theme.title_bar = rgb(0xececee).into();
            theme.title_bar_border = rgb(0xdcdce0).into();

            theme.primary = rgb(0x007aff).into();
            theme.primary_hover = rgb(0x0071e3).into();
            theme.primary_active = rgb(0x0062cc).into();
            theme.primary_foreground = rgb(0xffffff).into();
            theme.link = rgb(0x007aff).into();
            theme.selection = rgba(0x007aff_2e).into();
            theme.danger = rgb(0xff3b30).into();
            theme.success = rgb(0x34c759).into();
            theme.warning = rgb(0xff9f0a).into();

            theme.scrollbar = rgba(0x000000_00).into();
            theme.scrollbar_thumb = rgba(0x000000_26).into();
            theme.scrollbar_thumb_hover = rgba(0x000000_40).into();
        }
    });
}

pub fn is_dark(cx: &App) -> bool {
    cx.theme().mode.is_dark()
}

/// White card surface used by panels and grouped rows.
pub fn card(cx: &App) -> Hsla {
    if is_dark(cx) {
        rgb(0x2c2c2e).into()
    } else {
        rgb(0xffffff).into()
    }
}

pub fn card_hover(cx: &App) -> Hsla {
    if is_dark(cx) {
        rgb(0x323234).into()
    } else {
        rgb(0xfafafa).into()
    }
}

/// Inset surface: chips, empty states, code blocks.
pub fn bg_tertiary(cx: &App) -> Hsla {
    if is_dark(cx) {
        rgb(0x323234).into()
    } else {
        rgb(0xf2f2f4).into()
    }
}

pub fn bg_active(cx: &App) -> Hsla {
    if is_dark(cx) {
        rgb(0x454548).into()
    } else {
        rgb(0xe4e4e9).into()
    }
}

pub fn bg_hover(cx: &App) -> Hsla {
    if is_dark(cx) {
        rgb(0x38383a).into()
    } else {
        rgb(0xededf0).into()
    }
}

pub fn text_secondary(cx: &App) -> Hsla {
    if is_dark(cx) {
        rgba(0xffffff_a3).into()
    } else {
        rgb(0x6e6e73).into()
    }
}

pub fn border_light(cx: &App) -> Hsla {
    if is_dark(cx) {
        rgb(0x3a3a3c).into()
    } else {
        rgb(0xe8e8ec).into()
    }
}

pub fn text_muted(cx: &App) -> Hsla {
    if is_dark(cx) {
        rgba(0xffffff_73).into()
    } else {
        rgb(0x86868b).into()
    }
}

pub fn log_info() -> Hsla {
    rgb(0x007aff).into()
}

pub fn log_warn() -> Hsla {
    rgb(0xff9f0a).into()
}

pub fn log_error() -> Hsla {
    rgb(0xff3b30).into()
}

pub fn log_debug() -> Hsla {
    rgb(0x8e8e93).into()
}
