use crate::error::DecLimiterError;

/// Regex pattern to match datarate strings.
/// Captures integer and fractional parts, unit suffix, and optional "bps".
/// Examples of valid strings: "100Kbps", "1.5M", "2000", "3.25G".
const REGEX: &str = r"^([0-9]+)(?:\.([0-9]+))?([KMGTPkmgpt]?)(bps)?$";

/// Type alias for datarate values in bits per second.
pub type Datarate = u64;

/// Parses a datarate string (e.g., "100Kbps", "1.5M") into its equivalent value in bits per second.
///
/// Acceptable units are:
/// - No suffix: bits per second
/// - K or k or kbps: Kilobits per second (1,000 bps)
/// - M or m or mbps: Megabits per second (1,000,000 bps)
/// - G or g or gbps: Gigabits per second (1,000,000,000 bps)
/// - T or t or tbps: Terabits per second (1,000,000,000,000 bps)
/// - P or p or pbps: Petabits per second (1,000,000,000,000,000 bps)
///
/// # Arguments
/// * `input` - The datarate string to parse.
///
/// # Returns
/// * `Ok(u64)` - The parsed datarate in bits per second.
/// * `Err(DecLimiterError)` - If the input string is invalid or cannot be parsed.
pub fn parse_datarate(input: &str) -> Result<Datarate, DecLimiterError> {
	let re = regex::Regex::new(REGEX)
		.map_err(|e| DecLimiterError::ParseDatarateError(e.to_string()))?;

	let caps = re
		.captures(input)
		.ok_or_else(|| {
			DecLimiterError::ParseDatarateError(format!("Invalid datarate format: {}", input))
		})?;

	let int_part: f64 = caps
		.get(1)
		.unwrap()
		.as_str()
		.parse()?;

	let frac_part: f64 = match caps.get(2) {
		Some(m) => {
			let s = format!("0.{}", m.as_str());
			s.parse()?
		}
		None => 0.0,
	};

	let unit = caps.get(3).map(|m| m.as_str()).unwrap_or("");
	let multiplier = multiple(unit) as f64;

	Ok(((int_part + frac_part) * multiplier) as u64)
}

/// Given a unit suffix, returns the corresponding multiplier for datarate conversion.
fn multiple(unit: &str) -> u64 {
	match unit {
		"" => 1,
		"K" | "k" => 1_000,
		"M" | "m" => 1_000_000,
		"G" | "g" => 1_000_000_000,
		"T" | "t" => 1_000_000_000_000,
		"P" | "p" => 1_000_000_000_000_000,
		_ => 1,
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn test_parse_datarate() {
		use super::parse_datarate;

		assert_eq!(parse_datarate("100").unwrap(), 100);
		assert_eq!(parse_datarate("1K").unwrap(), 1_000);
		assert_eq!(parse_datarate("1.5K").unwrap(), 1_500);
		assert_eq!(parse_datarate("2M").unwrap(), 2_000_000);
		assert_eq!(parse_datarate("3.25G").unwrap(), 3_250_000_000);
		assert_eq!(parse_datarate("4T").unwrap(), 4_000_000_000_000);
		assert_eq!(parse_datarate("5.75P").unwrap(), 5_750_000_000_000_000);

		assert_eq!(parse_datarate("500bps").unwrap(), 500);
		assert_eq!(parse_datarate("2.5Kbps").unwrap(), 2_500);
		assert_eq!(parse_datarate("1Mbps").unwrap(), 1_000_000);
		assert_eq!(parse_datarate("1.78Mbps").unwrap(), 1_780_000);
	}
}