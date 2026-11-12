// Suppress dead_code warnings — this is an integrated SDK;
// its full API surface is kept available for future use.
#![allow(dead_code)]

mod types;
mod geodb;
mod utils;
mod country_codes;

pub use geodb::GeoDB;
pub use types::CountryCode;
pub use country_codes::ALL as COUNTRY_CODES;
