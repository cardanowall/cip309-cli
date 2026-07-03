//! USD money helpers shared by the anchoring commands: rendering micro-cent
//! decimal strings for humans and parsing user-supplied dollar amounts.
//!
//! Money crosses the gateway wire as decimal strings of USD micro-cents
//! (1 USD = 1,000,000 micros) so values survive without float precision loss;
//! these helpers convert between that representation and the `$X.XX` /
//! `--max-usd 1.50` forms the terminal uses.

/// Render USD micro-cents as `$X.XX` (rounded half-up to whole cents).
#[must_use]
pub fn format_usd_micros(micros_str: &str) -> String {
    let Ok(micros) = micros_str.parse::<i128>() else {
        return micros_str.to_string();
    };
    let negative = micros < 0;
    let abs = micros.unsigned_abs();
    let dollars = abs / 1_000_000;
    let fractional = abs % 1_000_000;
    let cents = (fractional + 5_000) / 10_000;
    let (whole_cents, display_cents) = if cents == 100 {
        (dollars + 1, 0)
    } else {
        (dollars, cents)
    };
    let sign = if negative { "-" } else { "" };
    format!("{sign}${whole_cents}.{display_cents:02}")
}

/// Parse a user-supplied decimal USD amount (`"10"`, `"1.50"`, `"0.000001"`)
/// into micro-cents.
///
/// Accepts an optional leading `$`, requires at least one digit, and allows at
/// most six fraction digits (the micro-cent resolution — anything finer would
/// silently truncate, so it is rejected instead).
///
/// # Errors
///
/// Returns a human-readable description of why the value is not a valid USD
/// amount.
pub fn parse_usd_to_micros(text: &str) -> Result<i128, String> {
    let trimmed = text.trim().strip_prefix('$').unwrap_or(text.trim());
    let (whole, fraction) = match trimmed.split_once('.') {
        Some((w, f)) => (w, f),
        None => (trimmed, ""),
    };
    if whole.is_empty() && fraction.is_empty() {
        return Err("expected a decimal USD amount like 1.50".to_string());
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err("expected only digits and at most one '.'".to_string());
    }
    if fraction.len() > 6 {
        return Err("at most 6 fraction digits are supported (micro-cent resolution)".to_string());
    }
    let dollars: i128 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| "the dollar part is too large".to_string())?
    };
    let mut padded = fraction.to_string();
    while padded.len() < 6 {
        padded.push('0');
    }
    let micros_fraction: i128 = if padded.is_empty() {
        0
    } else {
        padded.parse().expect("six ASCII digits parse")
    };
    dollars
        .checked_mul(1_000_000)
        .and_then(|d| d.checked_add(micros_fraction))
        .ok_or_else(|| "the amount is too large".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_usd_micros() {
        assert_eq!(format_usd_micros("1500000"), "$1.50");
        assert_eq!(format_usd_micros("0"), "$0.00");
        assert_eq!(format_usd_micros("999995"), "$1.00");
        assert_eq!(format_usd_micros("-2500000"), "-$2.50");
        // A non-numeric string passes through untouched rather than panicking.
        assert_eq!(format_usd_micros("n/a"), "n/a");
    }

    #[test]
    fn parses_usd_amounts() {
        assert_eq!(parse_usd_to_micros("10"), Ok(10_000_000));
        assert_eq!(parse_usd_to_micros("1.5"), Ok(1_500_000));
        assert_eq!(parse_usd_to_micros("$1.50"), Ok(1_500_000));
        assert_eq!(parse_usd_to_micros("0.000001"), Ok(1));
        assert_eq!(parse_usd_to_micros(".25"), Ok(250_000));
        assert_eq!(parse_usd_to_micros("3."), Ok(3_000_000));
    }

    #[test]
    fn rejects_malformed_usd_amounts() {
        assert!(parse_usd_to_micros("").is_err());
        assert!(parse_usd_to_micros(".").is_err());
        assert!(parse_usd_to_micros("-1").is_err());
        assert!(parse_usd_to_micros("1.0000001").is_err());
        assert!(parse_usd_to_micros("1,50").is_err());
        assert!(parse_usd_to_micros("1.5e3").is_err());
    }
}
