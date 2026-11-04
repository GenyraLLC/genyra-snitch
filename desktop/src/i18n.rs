//! Upstream locale wording is retained with its attribution; native additions
//! live separately. Technical identifiers and captured host data stay intact.
use serde_json::Value;
use std::{cell::Cell, collections::HashMap, sync::OnceLock};
thread_local! { static LANGUAGE: Cell<&'static str> = const { Cell::new("en") }; }
pub(super) const LANGUAGES: &[(&str, &str)] = &[
    ("en", "English"),
    ("fr", "Français"),
    ("de", "Deutsch"),
    ("es", "Español"),
    ("pt-BR", "Português"),
    ("ru", "Русский"),
    ("ja", "日本語"),
    ("zh-CN", "简体中文"),
];
pub(super) fn set_language(code: &str) {
    LANGUAGE.set(
        LANGUAGES
            .iter()
            .find(|(key, _)| *key == code)
            .map(|(key, _)| *key)
            .unwrap_or("en"),
    );
}
fn dictionaries() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        let mut source: Value =
            serde_json::from_str(include_str!("../assets/locales/upstream.json"))
                .expect("bundled upstream locales");
        let custom: Value = serde_json::from_str(include_str!("../assets/locales/native.json"))
            .expect("bundled native locales");
        for (lang, values) in custom.as_object().unwrap() {
            for (key, value) in values.as_object().unwrap() {
                source[lang][key] = value.clone();
            }
        }
        source
    })
}
pub(super) fn tr(key: &str) -> String {
    let data = dictionaries();
    static ENGLISH: OnceLock<HashMap<String, String>> = OnceLock::new();
    let english = ENGLISH.get_or_init(|| {
        data["en"]
            .as_object()
            .unwrap()
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|v| (v.to_string(), k.clone())))
            .collect()
    });
    let lookup = if data["en"].get(key).is_some() {
        key
    } else {
        english.get(key).map(String::as_str).unwrap_or(key)
    };
    LANGUAGE.with(|language| {
        data[language.get()][lookup]
            .as_str()
            .or_else(|| data["en"][lookup].as_str())
            .unwrap_or(key)
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_labels_have_all_eight_locales() {
        let custom: Value =
            serde_json::from_str(include_str!("../assets/locales/native.json")).unwrap();
        for (code, _) in LANGUAGES {
            for key in custom["en"].as_object().unwrap().keys() {
                assert!(
                    custom[*code][key]
                        .as_str()
                        .is_some_and(|s| !s.trim().is_empty()),
                    "{code}: {key}"
                );
            }
        }
        set_language("ja");
        assert_eq!(tr("Network"), "ネットワーク");
        set_language("fr");
        assert_eq!(tr("nav_graph"), "Graphe");
        set_language("en");
    }
}
