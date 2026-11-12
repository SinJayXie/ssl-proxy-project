use crate::ui::i18n;
use std::sync::atomic::{AtomicBool, Ordering};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIconBuilder};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, SetTimer, TranslateMessage, MSG,
};

/// Set by the tray thread, polled on the GPUI thread.
pub static QUIT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Spawn the system tray on its own thread.
///
/// `tray-icon` creates a hidden Win32 window; that thread must pump messages
/// for tray/menu events to arrive. Window show/hide is done with Win32 APIs so
/// the tray thread never touches GPUI state.
pub fn spawn() {
    let spawned = std::thread::Builder::new()
        .name("ssl-proxy-tray".into())
        .spawn(move || {
            let menu = Menu::new();
            // 必须显式指定 id：MenuItem::new 会自动生成 id，下面的匹配永远不成立。
            let show = MenuItem::with_id("show", i18n::t("TRAY_SHOW_WINDOW"), true, None);
            let exit = MenuItem::with_id("exit", i18n::t("QUIT_APP"), true, None);
            let _ = menu.append(&show);
            let _ = menu.append(&exit);

            let mut builder = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("SSL Proxy Client");

            if let Some(icon) = load_icon() {
                builder = builder.with_icon(icon);
            }

            let _tray = match builder.build() {
                Ok(tray) => tray,
                Err(err) => {
                    log::error!("Failed to create tray icon: {err}");
                    return;
                }
            };

            // 线程定时器：让消息循环每 500ms 醒一次，以便发现界面语言的切换。
            unsafe { SetTimer(None, 0, 500, None) };
            let mut language_revision = i18n::revision();

            let mut message = MSG::default();
            loop {
                while let Ok(event) = MenuEvent::receiver().try_recv() {
                    match event.id.as_ref() {
                        "show" => crate::platform::window::show_main_window(),
                        "exit" => {
                            QUIT_REQUESTED.store(true, Ordering::Relaxed);
                            return;
                        }
                        _ => {}
                    }
                }

                // 语言在 GPUI 线程切换后，这里同步刷新菜单文案。
                let revision = i18n::revision();
                if revision != language_revision {
                    language_revision = revision;
                    show.set_text(i18n::t("TRAY_SHOW_WINDOW"));
                    exit.set_text(i18n::t("QUIT_APP"));
                    log::debug!(
                        "Tray menu language updated: {:?} / {:?}",
                        show.text(),
                        exit.text()
                    );
                }

                let result = unsafe { GetMessageW(&mut message, None, 0, 0) };
                if !result.as_bool() {
                    break;
                }

                unsafe {
                    let _ = TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
        });

    if let Err(err) = spawned {
        log::error!("Failed to spawn tray thread: {err}");
    }
}

fn load_icon() -> Option<Icon> {
    let image = image::load_from_memory(include_bytes!("../../assets/app-icon.png")).ok()?;
    let rgba = image.to_rgba8();
    let (width, height) = rgba.dimensions();

    match Icon::from_rgba(rgba.into_raw(), width, height) {
        Ok(icon) => Some(icon),
        Err(err) => {
            log::error!("Failed to build tray icon: {err}");
            None
        }
    }
}
