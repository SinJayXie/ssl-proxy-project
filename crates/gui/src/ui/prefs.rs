use crate::ui::i18n::Language;
use gpui_kit::component::ThemeMode;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Local UI preferences stored in `$HOME/ssl-proxy-client/ui.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prefs {
    #[serde(default = "default_lang")]
    pub lang: String,
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default, rename = "lastUpdateCheck")]
    pub last_update_check: u64,
}

fn default_lang() -> String {
    "en".to_string()
}

fn default_theme() -> String {
    "dark".to_string()
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            lang: default_lang(),
            theme: default_theme(),
            last_update_check: 0,
        }
    }
}

impl Prefs {
    pub fn path(config_dir: &Path) -> PathBuf {
        config_dir.join("ui.json")
    }

    pub fn load(config_dir: &Path) -> Self {
        std::fs::read_to_string(Self::path(config_dir))
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, config_dir: &Path) {
        match serde_json::to_string_pretty(self) {
            Ok(raw) => {
                if let Err(err) = std::fs::write(Self::path(config_dir), raw) {
                    log::error!("Failed to save ui.json: {err}");
                }
            }
            Err(err) => log::error!("Failed to serialize ui.json: {err}"),
        }
    }

    pub fn language(&self) -> Language {
        Language::from_code(&self.lang)
    }

    pub fn set_language(&mut self, language: Language) {
        self.lang = language.code().to_string();
    }

    pub fn theme_mode(&self) -> ThemeMode {
        if self.theme == "light" {
            ThemeMode::Light
        } else {
            ThemeMode::Dark
        }
    }

    pub fn set_theme(&mut self, dark: bool) {
        self.theme = if dark { "dark" } else { "light" }.to_string();
    }
}
