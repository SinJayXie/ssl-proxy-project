use std::collections::HashMap;
use std::sync::LazyLock;

use crate::geo_sdk::CountryCode;

/// All country codes loaded from `country_codes.yaml` at compile time.
pub static ALL: LazyLock<Vec<CountryCode>> = LazyLock::new(|| {
    let yaml_str = include_str!("../../country_codes.yaml");
    serde_yaml::from_str(yaml_str).expect("Failed to parse country_codes.yaml")
});

static BY_NUMERIC: LazyLock<HashMap<u16, &CountryCode>> =
    LazyLock::new(|| ALL.iter().map(|c| (c.numeric, c)).collect());

static BY_ALPHA2: LazyLock<HashMap<String, &CountryCode>> =
    LazyLock::new(|| {
        ALL.iter().map(|c| (c.alpha2.to_uppercase(), c)).collect()
    });

impl CountryCode {
    /// Find a country by its numeric code — O(1).
    pub fn find_by_numeric(numeric: u16) -> Option<&'static CountryCode> {
        BY_NUMERIC.get(&numeric).copied()
    }

    /// Find a country by its alpha-2 code (case-insensitive).
    /// Accepts `"cn"`, `"CN"`, etc.
    pub fn find_by_alpha2(alpha2: &str) -> Option<&'static CountryCode> {
        BY_ALPHA2.get(&alpha2.to_uppercase()).copied()
    }

    /// Get the full country name for a numeric code — O(1).
    /// Returns "??" if not found.
    pub fn name_by_numeric(numeric: u16) -> &'static str {
        BY_NUMERIC
            .get(&numeric)
            .map(|c| c.country.as_str())
            .unwrap_or("??")
    }

    /// Get the alpha-2 code for a numeric code — O(1).
    /// Returns "??" if not found.
    pub fn alpha2_by_numeric(numeric: u16) -> &'static str {
        BY_NUMERIC
            .get(&numeric)
            .map(|c| c.alpha2.as_str())
            .unwrap_or("??")
    }

    /// Get the alpha-3 code for a numeric code — O(1).
    /// Returns "??" if not found.
    pub fn alpha3_by_numeric(numeric: u16) -> &'static str {
        BY_NUMERIC
            .get(&numeric)
            .map(|c| c.alpha3.as_str())
            .unwrap_or("??")
    }
}
