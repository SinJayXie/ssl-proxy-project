use crate::types::CountryCodeItem;
use crate::geo_sdk::{CountryCode, GeoDB, COUNTRY_CODES};
use std::path::Path;

/// Thin wrapper around `geo_sdk::GeoDB` that provides
/// the same public API the rest of the app expects.
pub struct GeoManager {
    db: Option<GeoDB>,
}

impl GeoManager {
    pub fn new(app_path: &Path) -> Self {
        let path = app_path.join("GeoDB.dat");
        let db = match path.to_str() {
            Some(s) => match GeoDB::load(s) {
                Ok(db) => {
                    log::info!(
                        "Loaded GeoDB.dat v{:#06X} (built {}): {} records, {} index entries",
                        db.version,
                        db.build_time_formatted(),
                        db.record_count,
                        db.index_entries,
                    );
                    Some(db)
                }
                Err(e) => {
                    log::warn!("GeoDB.dat not loaded: {} — GeoIP lookup will be unavailable", e);
                    None
                }
            },
            None => {
                log::warn!("Invalid GeoDB path: {:?}", path);
                None
            }
        };

        Self { db }
    }

    pub fn get_country_by_ip(&self, ip: &str) -> Option<CountryCodeItem> {
        let db = self.db.as_ref()?;
        let result = db.lookup_str(ip)?;
        Some(CountryCodeItem {
            country: CountryCode::name_by_numeric(result.numeric).to_string(),
            alpha2_code: CountryCode::alpha2_by_numeric(result.numeric).to_string(),
            alpha3_code: CountryCode::alpha3_by_numeric(result.numeric).to_string(),
            numeric: result.numeric as u32,
        })
    }

    pub fn get_all_country_codes(&self) -> Vec<CountryCodeItem> {
        let mut codes: Vec<CountryCodeItem> = COUNTRY_CODES
            .iter()
            .map(|c| CountryCodeItem {
                country: c.country.to_string(),
                alpha2_code: c.alpha2.to_string(),
                alpha3_code: c.alpha3.to_string(),
                numeric: c.numeric as u32,
            })
            .collect();
        codes.sort_by(|a, b| a.numeric.cmp(&b.numeric));
        codes
    }

}
