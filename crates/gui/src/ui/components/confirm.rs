use crate::ui::i18n;
use gpui_kit::base::h_flex;
use gpui_kit::component::WindowExt as _;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::*;
use std::sync::Arc;

/// A small confirm dialog: Cancel + Confirm.
pub fn open_confirm(
    window: &mut Window,
    cx: &mut App,
    title: String,
    message: String,
    danger: bool,
    on_confirm: impl Fn(&mut Window, &mut App) + 'static,
) {
    let on_confirm = Arc::new(on_confirm);

    window.open_dialog(cx, move |dialog, _, _| {
        let title = title.clone();
        let message = message.clone();
        let action = on_confirm.clone();
        let mut ok = Button::new("confirm-ok").label(i18n::t("CONFIRM"));
        ok = if danger { ok.danger() } else { ok.primary() };

        dialog
            .w(px(380.))
            .title(title)
            .child(div().text_sm().child(message))
            .footer(
                h_flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("confirm-cancel")
                            .label(i18n::t("CANCEL"))
                            .on_click(|_, window, cx| window.close_dialog(cx)),
                    )
                    .child(ok.on_click(move |_, window, cx| {
                        action(window, cx);
                        window.close_dialog(cx);
                    })),
            )
    });
}
