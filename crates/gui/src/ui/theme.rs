use gpui_kit::component::scroll::ScrollbarMode;
use gpui_kit::component::{ActiveTheme as _, Theme, ThemeMode};
use gpui_kit::{px, rgb, rgba, App, Hsla, WindowBackgroundAppearance};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// 平台默认字体：macOS 用系统无衬线/等宽字体，其它平台沿用 Windows 风格。
#[cfg(target_os = "macos")]
const UI_FONT: &str = "SF Pro Text";
#[cfg(target_os = "macos")]
const MONO_FONT: &str = "SF Mono";
#[cfg(not(target_os = "macos"))]
const UI_FONT: &str = "Segoe UI";
#[cfg(not(target_os = "macos"))]
const MONO_FONT: &str = "Consolas";

/// 亚克力背景不透明度的默认值与下限（百分比）。再低就只剩模糊，字看不清了。
pub const DEFAULT_ACRYLIC_OPACITY: u32 = 72;
pub const MIN_ACRYLIC_OPACITY: u32 = 30;

/// 亚克力（毛玻璃）开关：调色板与 [`card`] 都按它输出半透明色，
/// 窗口自身的模糊由 [`window_background`] + `Window::set_background_appearance` 负责。
static ACRYLIC: AtomicBool = AtomicBool::new(false);
/// 亚克力背景不透明度（百分比），只影响半透明表面色，不影响窗口模糊本身。
static ACRYLIC_OPACITY: AtomicU32 = AtomicU32::new(DEFAULT_ACRYLIC_OPACITY);

pub fn acrylic() -> bool {
    ACRYLIC.load(Ordering::Relaxed)
}

/// 当前亚克力不透明度（30-100）。
pub fn acrylic_opacity() -> u32 {
    ACRYLIC_OPACITY
        .load(Ordering::Relaxed)
        .clamp(MIN_ACRYLIC_OPACITY, 100)
}

/// 当前亚克力不透明度（0.0-1.0），用于颜色 alpha。
fn acrylic_alpha() -> f32 {
    acrylic_opacity() as f32 / 100.0
}

/// 开启/关闭亚克力并立即重算调色板（`Theme::update` 会刷新所有窗口）。
pub fn set_acrylic(cx: &mut App, enabled: bool) {
    if ACRYLIC.swap(enabled, Ordering::Relaxed) == enabled {
        return;
    }
    apply_palette(cx);
}

/// 调整亚克力背景不透明度（百分比）并立即重算调色板。
pub fn set_acrylic_opacity(cx: &mut App, percent: u32) {
    let percent = percent.clamp(MIN_ACRYLIC_OPACITY, 100);
    if ACRYLIC_OPACITY.swap(percent, Ordering::Relaxed) == percent {
        return;
    }
    apply_palette(cx);
}

/// 启动时一次性恢复开关与不透明度，避免连续重算两次调色板。
pub fn restore_acrylic(cx: &mut App, enabled: bool, opacity: u32) {
    ACRYLIC.store(enabled, Ordering::Relaxed);
    ACRYLIC_OPACITY.store(opacity.clamp(MIN_ACRYLIC_OPACITY, 100), Ordering::Relaxed);
    apply_palette(cx);
}

/// 平台窗口背景取值。只有 Windows（Win10 1809+ 走亚克力）与 macOS
/// （`NSVisualEffectView` 毛玻璃）支持 `Blurred`，其它平台保持不透明，
/// 否则窗口会变成没有内容的全透明。
pub fn window_background(enabled: bool) -> WindowBackgroundAppearance {
    #[cfg(any(windows, target_os = "macos"))]
    {
        if enabled {
            WindowBackgroundAppearance::Blurred
        } else {
            WindowBackgroundAppearance::Opaque
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        let _ = enabled;
        WindowBackgroundAppearance::Opaque
    }
}

/// Apply the macOS-inspired palette used across the application.
///
/// Light: content `#f5f5f7`, cards `#ffffff`, accent `#007aff`.
/// Dark: content `#1e1e1e`, cards `#2c2c2e`, accent `#0a84ff`.
pub fn apply(cx: &mut App, mode: ThemeMode) {
    Theme::change(mode, None, cx);
    // 桌面端常显滚动条：GPUI 默认是 Scrolling（滚动时才淡入），
    // 这里改成 Always，避免用户以为没有滚动条。
    Theme::set_scrollbar_mode(ScrollbarMode::Always, cx);
    apply_palette(cx);
}

/// 只按当前模式重算配色（模式不变时用），`Theme::update` 会刷新所有窗口。
fn apply_palette(cx: &mut App) {
    let dark = cx.theme().mode.is_dark();

    Theme::update(cx, move |theme| {
        // macOS controls are pill-ish: 6-7px on inputs/buttons, 12-14px on cards.
        theme.radius = px(7.);
        theme.radius_lg = px(14.);
        theme.font_family = UI_FONT.into();
        theme.font_size = px(13.);
        theme.mono_font_family = MONO_FONT.into();
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

        // 亚克力：主表面退成半透明，让平台窗口背景的模糊透出来。
        if ACRYLIC.load(Ordering::Relaxed) {
            let alpha = acrylic_alpha();
            theme.background = theme.background.opacity(alpha);
            // 侧边栏/标题栏比内容区更深一档，保持层次。
            theme.sidebar = theme.sidebar.opacity(alpha * 0.76);
            theme.title_bar = theme.title_bar.opacity(alpha * 0.76);
        }
    });
}

pub fn is_dark(cx: &App) -> bool {
    cx.theme().mode.is_dark()
}

/// White card surface used by panels and grouped rows.
pub fn card(cx: &App) -> Hsla {
    let base: Hsla = if is_dark(cx) {
        rgb(0x2c2c2e).into()
    } else {
        rgb(0xffffff).into()
    };
    surface(base, 0.5 + acrylic_alpha() * 0.5)
}

pub fn card_hover(cx: &App) -> Hsla {
    let base: Hsla = if is_dark(cx) {
        rgb(0x323234).into()
    } else {
        rgb(0xfafafa).into()
    };
    surface(base, 0.55 + acrylic_alpha() * 0.5)
}

/// 亚克力开启时让表面色保留一点透明度，卡片的模糊感才不会被盖死。
fn surface(base: Hsla, alpha: f32) -> Hsla {
    if acrylic() {
        base.opacity(alpha)
    } else {
        base
    }
}

/// 弹窗表面色：始终不透明。亚克力只作用于窗口背景，不能透到弹窗内容上。
pub fn dialog(cx: &App) -> Hsla {
    cx.theme().popover
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
