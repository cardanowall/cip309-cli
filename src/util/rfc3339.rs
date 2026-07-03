//! Minimal RFC 3339 timestamp parsing, dependency-free.
//!
//! The gateway reports block times as RFC 3339 strings (e.g.
//! `2026-07-03T10:15:30Z`, with optional fractional seconds and a `Z` or
//! numeric offset), while an inclusion certificate anchors on POSIX seconds.
//! This converts the former to the latter without pulling a date-time crate
//! into the CLI for one conversion.

/// Convert an RFC 3339 timestamp to POSIX seconds (UTC).
///
/// Accepts `YYYY-MM-DDTHH:MM:SS`, an optional `.fraction` (ignored — the
/// certificate anchor is whole seconds), and a mandatory `Z`/`z` or `±HH:MM`
/// offset, with `T`, `t`, or a space as the date/time separator.
///
/// # Errors
///
/// Returns a human-readable description of the first malformed component.
pub fn rfc3339_to_epoch_seconds(text: &str) -> Result<i64, String> {
    let bytes = text.trim().as_bytes();
    if bytes.len() < 20 {
        return Err(format!(
            "timestamp \"{}\" is too short for RFC 3339",
            text.trim()
        ));
    }

    let digits = |range: std::ops::Range<usize>| -> Result<i64, String> {
        let slice = &bytes[range.clone()];
        if !slice.iter().all(u8::is_ascii_digit) {
            return Err(format!("non-digit in timestamp position {}", range.start));
        }
        Ok(slice
            .iter()
            .fold(0i64, |acc, b| acc * 10 + i64::from(b - b'0')))
    };
    let expect = |index: usize, expected: &[u8]| -> Result<(), String> {
        if expected.contains(&bytes[index]) {
            Ok(())
        } else {
            Err(format!(
                "expected '{}' at timestamp position {index}",
                String::from_utf8_lossy(expected)
            ))
        }
    };

    let year = digits(0..4)?;
    expect(4, b"-")?;
    let month = digits(5..7)?;
    expect(7, b"-")?;
    let day = digits(8..10)?;
    expect(10, b"Tt ")?;
    let hour = digits(11..13)?;
    expect(13, b":")?;
    let minute = digits(14..16)?;
    expect(16, b":")?;
    let second = digits(17..19)?;

    if !(1..=12).contains(&month) {
        return Err(format!("month {month} out of range"));
    }
    if !(1..=days_in_month(year, month)).contains(&day) {
        return Err(format!("day {day} out of range"));
    }
    // Second 60 (a leap second) is accepted and clamped by the arithmetic below.
    if hour > 23 || minute > 59 || second > 60 {
        return Err("time component out of range".to_string());
    }

    // Skip an optional fractional-seconds part.
    let mut i = 19;
    if bytes[i] == b'.' {
        i += 1;
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return Err("empty fractional seconds".to_string());
        }
    }

    // The offset: 'Z' or ±HH:MM, applied so the result is UTC.
    let offset_seconds: i64 = match bytes.get(i) {
        Some(b'Z' | b'z') if i + 1 == bytes.len() => 0,
        Some(sign @ (b'+' | b'-')) if i + 6 == bytes.len() && bytes[i + 3] == b':' => {
            let oh = digits(i + 1..i + 3)?;
            let om = digits(i + 4..i + 6)?;
            if oh > 23 || om > 59 {
                return Err("UTC offset out of range".to_string());
            }
            let magnitude = oh * 3600 + om * 60;
            if *sign == b'+' {
                magnitude
            } else {
                -magnitude
            }
        }
        _ => return Err("expected a 'Z' or ±HH:MM UTC offset".to_string()),
    };

    let days = days_from_civil(year, month, day);
    Ok(days * 86_400 + hour * 3600 + minute * 60 + second - offset_seconds)
}

/// Days since 1970-01-01 for a proleptic-Gregorian civil date (the standard
/// days-from-civil algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let mp = (month + 9) % 12; // March = 0
    let doy = (153 * mp + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
                29
            } else {
                28
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_utc_forms() {
        assert_eq!(rfc3339_to_epoch_seconds("1970-01-01T00:00:00Z"), Ok(0));
        assert_eq!(
            rfc3339_to_epoch_seconds("2026-07-03T10:15:30Z"),
            Ok(1_783_073_730)
        );
        // Fractional seconds are ignored; lowercase separators are accepted.
        assert_eq!(
            rfc3339_to_epoch_seconds("2026-07-03t10:15:30.123456z"),
            Ok(1_783_073_730)
        );
        assert_eq!(
            rfc3339_to_epoch_seconds("2026-07-03 10:15:30Z"),
            Ok(1_783_073_730)
        );
    }

    #[test]
    fn applies_numeric_offsets() {
        // 12:15:30+02:00 is 10:15:30 UTC.
        assert_eq!(
            rfc3339_to_epoch_seconds("2026-07-03T12:15:30+02:00"),
            Ok(1_783_073_730)
        );
        assert_eq!(
            rfc3339_to_epoch_seconds("2026-07-03T05:45:30-04:30"),
            Ok(1_783_073_730)
        );
    }

    #[test]
    fn covers_leap_years_and_boundaries() {
        assert_eq!(
            rfc3339_to_epoch_seconds("2000-02-29T00:00:00Z"),
            Ok(951_782_400)
        );
        assert_eq!(rfc3339_to_epoch_seconds("1969-12-31T23:59:59Z"), Ok(-1));
    }

    #[test]
    fn rejects_malformed_timestamps() {
        for bad in [
            "",
            "2026-07-03",
            "2026-13-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-07-03T24:00:00Z",
            "2026-07-03T00:00:00",
            "2026-07-03T00:00:00.Z",
            "2026-07-03T00:00:00+2:00",
            "not a timestamp at all",
        ] {
            assert!(rfc3339_to_epoch_seconds(bad).is_err(), "accepted: {bad}");
        }
    }
}
