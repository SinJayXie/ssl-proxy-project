use crate::ui::assets::mdi;
use crate::ui::theme;
use gpui_kit::component::{ActiveTheme as _, Icon};
use gpui_kit::*;

/// Compact square icon button matching `.conn-group__action-btn` etc.
pub fn icon_button(
    id: impl Into<ElementId>,
    icon: &'static str,
    size: f32,
    icon_size: f32,
    color: Hsla,
    hover_bg: Hsla,
    hover_color: Hsla,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> AnyElement {
    div()
        .id(id)
        .w(px(size))
        .h(px(size))
        .flex()
        .items_center()
        .justify_center()
        .rounded(px(6.))
        .flex_shrink_0()
        .cursor_pointer()
        .text_color(color)
        .hover(move |style| style.bg(hover_bg).text_color(hover_color))
        .child(
            Icon::default()
                .path(mdi(icon))
                .w(px(icon_size))
                .h(px(icon_size)),
        )
        .on_click(on_click)
        .into_any_element()
}

pub fn muted_icon_button(
    id: impl Into<ElementId>,
    icon: &'static str,
    size: f32,
    icon_size: f32,
    cx: &App,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> AnyElement {
    let muted = theme::text_muted(cx);
    let accent = cx.theme().primary;
    let hover = theme::bg_hover(cx);
    icon_button(
        id, icon, size, icon_size, muted, hover, accent, on_click,
    )
}

pub fn danger_icon_button(
    id: impl Into<ElementId>,
    icon: &'static str,
    size: f32,
    icon_size: f32,
    cx: &App,
    on_click: impl Fn(&ClickEvent, &mut Window, &mut App) + 'static,
) -> AnyElement {
    let muted = theme::text_muted(cx);
    let danger = cx.theme().danger;
    icon_button(
        id,
        icon,
        size,
        icon_size,
        muted,
        danger.opacity(0.14),
        danger,
        on_click,
    )
}
