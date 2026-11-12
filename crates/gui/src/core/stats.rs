use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(not(windows))]
use std::time::{SystemTime, UNIX_EPOCH};

/// Traffic accumulated for one calendar day (local time, `YYYY-MM-DD`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DailyTraffic {
    pub date: String,
    pub up: u64,
    pub down: u64,
}

/// Long-lived usage statistics persisted next to `setting.yaml`.
///
/// Session counters live in `AppState::total_dataflow` and reset on restart;
/// this store keeps the cross-session totals plus a per-day breakdown used by
/// the Dashboard chart.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StatsStore {
    #[serde(default)]
    pub total_up: u64,
    #[serde(default)]
    pub total_down: u64,
    #[serde(default)]
    pub peak_connections: usize,
    #[serde(default)]
    pub days: Vec<DailyTraffic>,
}

/// Keep a month of history; enough for the 7-day chart and future views.
const MAX_DAYS: usize = 30;

impl StatsStore {
    pub fn load(config_dir: &Path) -> Self {
        let path = config_dir.join("stats.json");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|content| serde_json::from_str(&content).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, config_dir: &Path) {
        let path = config_dir.join("stats.json");
        match serde_json::to_string_pretty(self) {
            Ok(content) => {
                if let Err(err) = std::fs::write(&path, content) {
                    log::error!("Failed to save stats.json: {err}");
                }
            }
            Err(err) => log::error!("Failed to serialize stats: {err}"),
        }
    }

    /// Accumulate new session bytes into the totals and the given day bucket.
    pub fn record(&mut self, date: &str, up: u64, down: u64) {
        if up == 0 && down == 0 {
            return;
        }

        self.total_up = self.total_up.saturating_add(up);
        self.total_down = self.total_down.saturating_add(down);

        if let Some(day) = self.days.iter_mut().find(|day| day.date == date) {
            day.up = day.up.saturating_add(up);
            day.down = day.down.saturating_add(down);
            return;
        }

        self.days.push(DailyTraffic {
            date: date.to_string(),
            up,
            down,
        });
        self.days.sort_by(|a, b| a.date.cmp(&b.date));
        if self.days.len() > MAX_DAYS {
            let excess = self.days.len() - MAX_DAYS;
            self.days.drain(0..excess);
        }
    }

    pub fn observe_connections(&mut self, current: usize) {
        if current > self.peak_connections {
            self.peak_connections = current;
        }
    }

    /// Last `count` days ending at `today`, oldest first, zero-filled.
    pub fn recent(&self, today: &str, count: usize) -> Vec<DailyTraffic> {
        let Some(today_days) = parse_date_days(today) else {
            return Vec::new();
        };

        (0..count)
            .rev()
            .map(|offset| {
                let date = date_from_days(today_days - offset as i64);
                self.days
                    .iter()
                    .find(|day| day.date == date)
                    .cloned()
                    .unwrap_or(DailyTraffic {
                        date,
                        up: 0,
                        down: 0,
                    })
            })
            .collect()
    }
}

/// Local calendar date used as the bucket key (`YYYY-MM-DD`).
pub fn today_key() -> String {
    local_date_key()
}

/// `2026-11-12` -> `11-12` for compact chart labels.
pub fn short_label(date: &str) -> String {
    date.get(5..).unwrap_or(date).to_string()
}

#[cfg(windows)]
fn local_date_key() -> String {
    use windows::Win32::System::SystemInformation::GetLocalTime;

    let time = unsafe { GetLocalTime() };
    format!(
        "{:04}-{:02}-{:02}",
        time.wYear, time.wMonth, time.wDay
    )
}

#[cfg(not(windows))]
fn local_date_key() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    date_from_days((seconds / 86_400) as i64)
}

fn parse_date_days(date: &str) -> Option<i64> {
    let mut parts = date.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: u32 = parts.next()?.parse().ok()?;
    let day: u32 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some(days_from_civil(year, month, day))
}

fn date_from_days(days: i64) -> String {
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

/// Howard Hinnant's civil date algorithms, valid for the gregorian calendar.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let mp = ((month + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        for (year, month, day) in [
            (1970, 1, 1),
            (2000, 2, 29),
            (2026, 11, 12),
            (2100, 12, 31),
        ] {
            let days = days_from_civil(year, month, day);
            assert_eq!(civil_from_days(days), (year, month, day));
        }
    }

    #[test]
    fn recent_days_are_zero_filled() {
        let mut store = StatsStore::default();
        store.record("2026-11-10", 10, 20);
        store.record("2026-11-12", 5, 5);

        let days = store.recent("2026-11-12", 3);
        assert_eq!(days.len(), 3);
        assert_eq!(days[0].date, "2026-11-10");
        assert_eq!((days[0].up, days[0].down), (10, 20));
        assert_eq!(days[1].date, "2026-11-11");
        assert_eq!((days[1].up, days[1].down), (0, 0));
        assert_eq!(days[2].date, "2026-11-12");
        assert_eq!((days[2].up, days[2].down), (5, 5));
    }

    #[test]
    fn record_updates_totals_and_bucket() {
        let mut store = StatsStore::default();
        store.record("2026-11-12", 100, 200);
        store.record("2026-11-12", 50, 25);

        assert_eq!(store.total_up, 150);
        assert_eq!(store.total_down, 225);
        assert_eq!(store.days.len(), 1);
        assert_eq!((store.days[0].up, store.days[0].down), (150, 225));
    }
}
