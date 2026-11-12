use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Language {
    #[default]
    En,
    ZhCn,
}

impl Language {
    pub fn code(self) -> &'static str {
        match self {
            Language::En => "en",
            Language::ZhCn => "zhCn",
        }
    }

    pub fn from_code(code: &str) -> Self {
        match code {
            "zhCn" | "zh-cn" | "zh_CN" | "zh" => Language::ZhCn,
            _ => Language::En,
        }
    }
}

static CURRENT: AtomicU8 = AtomicU8::new(0);
static REVISION: AtomicU64 = AtomicU64::new(0);

static EN: Lazy<HashMap<String, String>> =
    Lazy::new(|| parse(include_str!("../../assets/i18n/en.json")));
static ZH_CN: Lazy<HashMap<String, String>> =
    Lazy::new(|| parse(include_str!("../../assets/i18n/zh-cn.json")));

fn parse(raw: &str) -> HashMap<String, String> {
    serde_json::from_str::<HashMap<String, String>>(raw).unwrap_or_default()
}

pub fn set_language(language: Language) {
    CURRENT.store(language as u8, Ordering::Relaxed);
    REVISION.fetch_add(1, Ordering::Relaxed);
}

/// Monotonic revision used by the shell to refresh all pages on language change.
pub fn revision() -> u64 {
    REVISION.load(Ordering::Relaxed)
}

pub fn language() -> Language {
    match CURRENT.load(Ordering::Relaxed) {
        1 => Language::ZhCn,
        _ => Language::En,
    }
}

/// Translate a key, falling back to English and finally to the key itself.
pub fn t(key: &str) -> String {
    let table = match language() {
        Language::ZhCn => &*ZH_CN,
        Language::En => &*EN,
    };

    table
        .get(key)
        .or_else(|| EN.get(key))
        .cloned()
        .unwrap_or_else(|| key.to_string())
}

/// Translate a key and replace `{name}` placeholders.
pub fn t_with(key: &str, vars: &[(&str, &str)]) -> String {
    let mut text = t(key);
    for (name, value) in vars {
        text = text.replace(&format!("{{{name}}}"), value);
    }
    text
}
