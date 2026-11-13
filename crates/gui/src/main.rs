#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod core;
mod platform;
mod ui;

// Copied core modules still use `crate::state::*`, `crate::types::*`, etc.
pub(crate) use crate::core::{dns, geo, geo_sdk, state, types};

use crate::core::Core;
use gpui_kit::component::TitleBar;
use gpui_kit::*;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    // ---- Single instance (Windows) ----
    // `SSL_PROXY_GUI_MULTI_INSTANCE` skips the mutex for local testing while
    // the Tauri client (which uses the same mutex name) is running.
    //
    // A relaunched process (see `Core::restart_process`) retries for a while,
    // because the previous instance may not have exited yet. A normal second
    // launch fails fast and just activates the existing window.
    #[cfg(windows)]
    let _mutex_guard = if std::env::var_os("SSL_PROXY_GUI_MULTI_INSTANCE").is_some() {
        None
    } else {
        let retries = if std::env::var_os(crate::core::RELAUNCH_ENV).is_some() {
            30
        } else {
            0
        };
        match platform::single_instance::try_acquire(retries) {
            Some(handle) => Some(handle),
            None => return,
        }
    };

    // ---- Single instance (macOS) ----
    // 用配置目录下的 flock 代替 Windows 互斥体，被占用说明已有实例在运行。
    // config_dir() 无副作用，这里先取一次不影响后续初始化。
    //
    // 与 Windows 的 RELAUNCH_ENV 对齐：由「保存并重启」拉起的新进程会重试一段时间，
    // 等待旧进程退出并释放 flock，避免重启静默失败。
    #[cfg(target_os = "macos")]
    let _instance_guard = if std::env::var_os("SSL_PROXY_GUI_MULTI_INSTANCE").is_some() {
        None
    } else {
        let retries = if std::env::var_os(crate::core::RELAUNCH_ENV).is_some() {
            30
        } else {
            0
        };
        let mut guard = None;
        for attempt in 0..=retries {
            if let Some(acquired) = platform::mac::try_acquire(&platform::paths::config_dir()) {
                guard = Some(acquired);
                break;
            }
            if attempt < retries {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        match guard {
            Some(guard) => Some(guard),
            None => return,
        }
    };

    // ---- Paths + logging ----
    let app_path = platform::paths::resolve_app_path();
    let config_dir = platform::paths::config_dir();
    platform::logging::init(&config_dir);

    log::info!("SSL Proxy Client (GPUI) starting...");
    log::info!("App path: {:?}, config dir: {:?}", app_path, config_dir);

    // ---- Core ----
    let core = Arc::new(Core::new(app_path, config_dir));

    if !core.state.app_path.join("GeoDB.dat").exists() {
        log::error!("Required file not found: GeoDB.dat");
        let state = core.state.clone();
        core.handle().spawn(async move {
            state.push_error(2).await;
        });
    }

    if core.consent_exists() {
        core.start_proxy();
    } else {
        log::info!("Consent not yet given, proxy will start after user agrees");
    }

    let prefs = ui::prefs::Prefs::load(&core.state.config_dir);
    ui::i18n::set_language(prefs.language());

    // ---- GPUI ----
    gpui_kit::application()
        // MDI first, then the full Lucide catalog used by gpui-kit internals.
        .with_assets(ui::assets::AppAssets)
        .run(move |cx| {
            // macOS 没有托盘常驻，关闭最后一个窗口即退出，避免留下无窗口的后台进程。
            #[cfg(target_os = "macos")]
            cx.set_quit_mode(QuitMode::LastWindowClosed);

            gpui_kit::init(cx);
            ui::theme::apply(cx, prefs.theme_mode());
            // 亚克力是偏好项，跟随主题一起在启动时恢复。
            ui::theme::restore_acrylic(cx, prefs.acrylic, prefs.acrylic_opacity);

            let options = WindowOptions {
                window_background: ui::theme::window_background(prefs.acrylic),
                window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                    None,
                    size(px(900.), px(650.)),
                    cx,
                ))),
                window_min_size: Some(size(px(800.), px(600.))),
                is_resizable: true,
                ..TitleBar::window_options()
            };

            // macOS 红绿灯在 34px 标题栏内垂直居中（直径约 12px）。
            #[cfg(target_os = "macos")]
            let options = {
                let mut options = options;
                if let Some(titlebar) = options.titlebar.as_mut() {
                    titlebar.traffic_light_position = Some(point(px(12.), px(11.)));
                }
                options
            };

            let shell_core = core.clone();
            let shell_prefs = prefs.clone();
            let (window_handle, _shell) = open_window(options, cx, move |window, cx| {
                // Single-instance activation looks the window up by title.
                window.set_window_title("SSL Proxy Client");

                #[cfg(windows)]
                window.on_window_should_close(cx, |_, _| {
                    platform::window::hide_main_window();
                    false
                });

                cx.new(|cx| {
                    ui::AppShell::new(shell_core.clone(), shell_prefs.clone(), window, cx)
                })
            })
            .expect("failed to open main window");

            #[cfg(windows)]
            platform::tray::spawn();

            // Tray thread cannot touch GPUI state; it sets a flag that we poll.
            #[cfg(windows)]
            cx.spawn(async move |cx| loop {
                smol::Timer::after(Duration::from_millis(250)).await;
                if platform::tray::QUIT_REQUESTED.swap(false, Ordering::Relaxed) {
                    cx.update(|cx| cx.quit());
                    break;
                }
            })
            .detach();

            let _ = window_handle;
        });
}
