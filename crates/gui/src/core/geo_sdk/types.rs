use serde::Deserialize;
use std::fmt;

/// ISO 3166-1 country code mapping.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CountryCode {
    /// Full country name, e.g. "China"
    pub country: String,
    /// ISO 3166-1 alpha-2 code, e.g. "CN"
    pub alpha2: String,
    /// ISO 3166-1 alpha-3 code, e.g. "CHN"
    pub alpha3: String,
    /// ISO 3166-1 numeric code, e.g. 156
    pub numeric: u16,
}

impl CountryCode {
    /// Create a new CountryCode (for programmatic use).
    pub fn new(country: &str, alpha2: &str, alpha3: &str, numeric: u16) -> Self {
        Self {
            country: country.to_string(),
            alpha2: alpha2.to_string(),
            alpha3: alpha3.to_string(),
            numeric,
        }
    }
}

impl fmt::Display for CountryCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.country, self.alpha2.to_uppercase())
    }
}

/// Result of a single CIDR lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupResult {
    /// Network base IP as u32 (big-endian), e.g. 0x08080800 for 8.8.8.0
    pub ip: u32,
    /// Subnet mask bits (0-32)
    pub mask: u8,
    /// Country numeric code matching ISO 3166-1
    pub numeric: u16,
}

impl LookupResult {
    /// Create a new LookupResult.
    pub fn new(ip: u32, mask: u8, numeric: u16) -> Self {
        Self { ip, mask, numeric }
    }

    /// Return the CIDR as a string like "8.8.8.0/24".
    pub fn to_cidr(&self) -> String {
        let octets = super::utils::ip_to_octets(self.ip);
        format!("{}.{}.{}.{}/{}", octets[0], octets[1], octets[2], octets[3], self.mask)
    }

    /// Return the IP as a string like "8.8.8.0".
    pub fn to_ip_str(&self) -> String {
        super::utils::ip_to_str(self.ip)
    }

    /// Get the country name for this result.
    /// Returns "??" if the numeric code is unknown.
    pub fn country_name(&self) -> &str {
        super::CountryCode::name_by_numeric(self.numeric)
    }

    /// Get the alpha-2 country code for this result.
    /// Returns "??" if the numeric code is unknown.
    pub fn alpha2(&self) -> &str {
        super::CountryCode::alpha2_by_numeric(self.numeric)
    }

    /// Get the full CountryCode info for this result, if found.
    pub fn country_info(&self) -> Option<&CountryCode> {
        CountryCode::find_by_numeric(self.numeric)
    }
}

impl fmt::Display for LookupResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} ({})",
            self.to_cidr(),
            self.country_name(),
            self.alpha2(),
        )
    }
}
