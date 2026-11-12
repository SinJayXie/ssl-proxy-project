use std::fs;
use std::io::Read;

use flate2::read::GzDecoder;

use super::types::LookupResult;

// Binary format constants
const HEADER_MAGIC: &[u8; 4] = b"GEOD";
const HEADER_SIZE: usize = 32;
const RECORD_SIZE: usize = 9;
#[allow(dead_code)]
const INDEX_STRIDE: usize = 1024;

/// Errors that can occur when loading or parsing a GeoDB file.
#[derive(Debug, thiserror::Error)]
pub enum GeoDBError {
    /// File not found at the given path.
    #[error("{0} not found")]
    NotFound(String),

    /// I/O error during file read.
    #[error("read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Gzip decompression failed.
    #[error("decompress: {0}")]
    Decompress(std::io::Error),

    /// Data too small to contain a valid header.
    #[error("file too small for header")]
    TooSmall,

    /// Invalid magic bytes — not a GeoDB file.
    #[error("invalid GeoDB.dat (bad magic)")]
    BadMagic,

    /// CRC32 checksum mismatch — file may be corrupted.
    #[error("CRC mismatch (file may be corrupted)")]
    CrcMismatch,

    /// Record section is truncated.
    #[error("record section truncated")]
    Truncated,
}

/// Parsed GeoDB — holds decompressed records, index table, and metadata.
///
/// Load from disk via [`GeoDB::load`], then query via [`GeoDB::lookup`].
pub struct GeoDB {
    /// Binary format version (currently 0x0002)
    pub version: u16,
    /// Total number of CIDR records
    pub record_count: usize,
    /// Number of sparse index entries
    pub index_entries: usize,
    /// Unix timestamp when the database was built
    pub build_time: u32,
    /// Full sparse index: (start_ip, byte_offset_in_records)
    pub index: Vec<(u32, usize)>,
    /// Raw records byte slice (record_count × 9 bytes)
    records: Vec<u8>,
}

// ── Internal parsing ──

/// Parsed header fields extracted from a decompressed buffer.
struct ParsedHeader {
    version: u16,
    record_count: usize,
    build_time: u32,
    records: Vec<u8>,
    index: Vec<(u32, usize)>,
    index_entries: usize,
}

/// Shared parsing logic: decompressed bytes → GeoDB fields.
fn parse_data(data: &[u8]) -> Result<ParsedHeader, GeoDBError> {
    if data.len() < HEADER_SIZE {
        return Err(GeoDBError::TooSmall);
    }
    let header = &data[..HEADER_SIZE];
    if &header[0..4] != HEADER_MAGIC {
        return Err(GeoDBError::BadMagic);
    }

    let version = u16::from_be_bytes([header[4], header[5]]);
    let record_count =
        u32::from_be_bytes([header[6], header[7], header[8], header[9]]) as usize;
    let crc_stored = u32::from_be_bytes([header[10], header[11], header[12], header[13]]);
    let build_time = u32::from_be_bytes([header[14], header[15], header[16], header[17]]);

    let crc_body = &data[HEADER_SIZE..];
    if crc32fast::hash(crc_body) != crc_stored {
        return Err(GeoDBError::CrcMismatch);
    }

    let records_size = record_count * RECORD_SIZE;
    if crc_body.len() < records_size + 4 {
        return Err(GeoDBError::Truncated);
    }

    let records = crc_body[..records_size].to_vec();
    let index_and_footer = &crc_body[records_size..];
    let footer_offset = index_and_footer.len().saturating_sub(4);
    let index_entries =
        u32::from_be_bytes(index_and_footer[footer_offset..].try_into().unwrap()) as usize;
    let index_data = &index_and_footer[..footer_offset];

    let index: Vec<(u32, usize)> = (0..index_entries)
        .map(|i| {
            let off = i * 8;
            let ip = u32::from_be_bytes(index_data[off..off + 4].try_into().unwrap());
            let byte_off =
                u32::from_be_bytes(index_data[off + 4..off + 8].try_into().unwrap()) as usize;
            (ip, byte_off)
        })
        .collect();

    Ok(ParsedHeader {
        version,
        record_count,
        build_time,
        records,
        index,
        index_entries,
    })
}

// ── Public API ──

impl GeoDB {
    /// Open the default `./GeoDB.dat` in the current directory.
    ///
    /// This is the recommended way to load the database.
    /// Equivalent to `GeoDB::load("./GeoDB.dat")`.
    pub fn open() -> Result<Self, GeoDBError> {
        Self::load("./GeoDB.dat")
    }

    /// Load and parse a `GeoDB.dat` file from the given path.
    ///
    /// The file is gzip-compressed. Validates magic header and CRC32 checksum.
    pub fn load(path: &str) -> Result<Self, GeoDBError> {
        let p = std::path::Path::new(path);
        if !p.exists() {
            return Err(GeoDBError::NotFound(path.into()));
        }

        let compressed = fs::read(p).map_err(|e| GeoDBError::Io {
            path: path.into(),
            source: e,
        })?;
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut data = Vec::new();
        decoder
            .read_to_end(&mut data)
            .map_err(GeoDBError::Decompress)?;

        let parsed = parse_data(&data)?;
        Ok(Self::from_parsed(parsed))
    }

    /// Load from bytes (already decompressed). Useful for in-memory usage.
    pub fn from_bytes(data: &[u8]) -> Result<Self, GeoDBError> {
        let parsed = parse_data(data)?;
        Ok(Self::from_parsed(parsed))
    }

    fn from_parsed(p: ParsedHeader) -> Self {
        Self {
            version: p.version,
            record_count: p.record_count,
            index_entries: p.index_entries,
            build_time: p.build_time,
            index: p.index,
            records: p.records,
        }
    }

    /// Lookup an IPv4 address (as u32 big-endian).
    ///
    /// Uses index-assisted binary search + linear scan for longest prefix match.
    /// Returns `None` if no record matches.
    pub fn lookup(&self, target: u32) -> Option<LookupResult> {
        if self.records.is_empty() || self.index.is_empty() {
            return None;
        }

        // Binary search index → find rightmost block with start_ip <= target
        let idx_pos = match self.index.binary_search_by_key(&target, |(ip, _)| *ip) {
            Ok(pos) => pos,
            Err(pos) => pos.saturating_sub(1),
        };

        let (_, start_offset) = self.index[idx_pos];
        let block_start = start_offset;
        let block_end = if idx_pos + 1 < self.index.len() {
            self.index[idx_pos + 1].1
        } else {
            self.records.len()
        };

        let mut best: Option<LookupResult> = None;

        for chunk in self.records[block_start..block_end].chunks_exact(RECORD_SIZE) {
            let rec_ip = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            let mask = chunk[6];
            let numeric = u16::from_be_bytes([chunk[7], chunk[8]]);

            let mask_u32: u32 = match mask {
                0 => 0,
                32 => u32::MAX,
                m => !((1u32 << (32 - m)) - 1),
            };

            if (target & mask_u32) == (rec_ip & mask_u32) {
                match &best {
                    None => {
                        best = Some(LookupResult::new(rec_ip, mask, numeric));
                    }
                    Some(b) if mask > b.mask => {
                        best = Some(LookupResult::new(rec_ip, mask, numeric));
                    }
                    _ => {}
                }
            }

            if rec_ip > target {
                break;
            }
        }

        best
    }

    /// Lookup an IP address from a string like "8.8.8.8".
    ///
    /// Returns `None` if the string is not a valid IPv4 address or no record matches.
    pub fn lookup_str(&self, ip_str: &str) -> Option<LookupResult> {
        let ip = super::utils::str_to_ip(ip_str)?;
        self.lookup(ip)
    }

    /// Lookup a hostname or IP string, with DNS resolution for domain names.
    ///
    /// Returns `None` if resolution fails or no record matches.
    pub fn lookup_host(&self, host: &str) -> Option<LookupResult> {
        let ip = super::utils::resolve_host(host)?;
        self.lookup(ip)
    }

    /// Format the build timestamp as a human-readable UTC date string.
    ///
    /// Returns `"YYYY-MM-DD HH:MM:SS"`.
    pub fn build_time_formatted(&self) -> String {
        format_timestamp(self.build_time)
    }

    /// Returns the number of records in the database.
    pub fn len(&self) -> usize {
        self.record_count
    }

    /// Returns true if the database contains no records.
    pub fn is_empty(&self) -> bool {
        self.record_count == 0
    }

    /// Iterate over all records as `LookupResult` values.
    pub fn iter(&self) -> GeoDBIter<'_> {
        GeoDBIter {
            db: self,
            offset: 0,
        }
    }
}

/// Iterator over all CIDR records in the database.
pub struct GeoDBIter<'a> {
    db: &'a GeoDB,
    offset: usize,
}

impl<'a> Iterator for GeoDBIter<'a> {
    type Item = LookupResult;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + RECORD_SIZE > self.db.records.len() {
            return None;
        }
        let chunk = &self.db.records[self.offset..self.offset + RECORD_SIZE];
        self.offset += RECORD_SIZE;
        let ip = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
        let mask = chunk[6];
        let numeric = u16::from_be_bytes([chunk[7], chunk[8]]);
        Some(LookupResult::new(ip, mask, numeric))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.db.records.len() - self.offset) / RECORD_SIZE;
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for GeoDBIter<'a> {}

/// Format a Unix timestamp (seconds since 1970-01-01) as `"YYYY-MM-DD HH:MM:SS"`.
fn format_timestamp(ts: u32) -> String {
    let secs = ts as i64;
    let hms = secs % 86400;
    let days = (secs / 86400) as i64;
    let (year, month) = days_to_year_month(days);
    let day = (days - days_before_year_month(year, month) + 1) as u32;
    let h = (hms / 3600) as u32;
    let m = ((hms % 3600) / 60) as u32;
    let s = (hms % 60) as u32;
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, h, m, s)
}

fn days_to_year_month(days: i64) -> (i64, i64) {
    let mut year = 1970i64;
    let mut remaining = days;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }
    let month_days = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1i64;
    for &md in month_days.iter() {
        if remaining < md {
            break;
        }
        remaining -= md;
        month += 1;
    }
    (year, month)
}

fn days_before_year_month(year: i64, month: i64) -> i64 {
    let mut total = 0i64;
    for y in 1970..year {
        total += if is_leap(y) { 366 } else { 365 };
    }
    let month_days = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    for m in 1..month {
        total += month_days[(m - 1) as usize];
    }
    total
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}
