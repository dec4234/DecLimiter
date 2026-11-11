use std::ffi::OsStr;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
use crate::error::DecLimiterError;
use crate::limiter::ProcessPair;

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

	let unit = caps.get(3).map(|m| m.as_str()).unwrap_or("");
	let multiplier = multiple(unit) as u128;

	// Integer arithmetic keeps decimal values exact. Floating point gives
	// 1000999 for "1.001M", because 1.001 has no exact binary form.
	//
	// The regex accepts only digits, thus a parse can fail only on overflow.
	// A value that is too large saturates.
	let int_part: u128 = caps[1].parse().unwrap_or(u128::MAX);

	// The largest multiplier is 10^15, thus digits after the 18th cannot
	// change the result. The limit also keeps the products below u128::MAX.
	let frac_digits = caps.get(2).map_or("", |m| &m.as_str()[..m.len().min(18)]);
	let frac_part: u128 = if frac_digits.is_empty() {
		0
	} else {
		let numerator: u128 = frac_digits.parse().expect("at most 18 digits fit in u128");
		numerator * multiplier / 10u128.pow(frac_digits.len() as u32)
	};

	let total = int_part.saturating_mul(multiplier).saturating_add(frac_part);
	Ok(u64::try_from(total).unwrap_or(u64::MAX))
}

/// Parses a datarate string in bits per second (see [`parse_datarate`]) and
/// returns the rate in bytes per second, which is the unit of the limiter.
///
/// A rate below 8 bits per second is less than 1 byte per second. The limiter
/// cannot use it, thus it is an error.
///
/// # Examples
/// "8" gives 1, "10Mbps" gives 1 250 000, "1.5K" gives 187.
pub fn parse_byterate(input: &str) -> Result<u64, DecLimiterError> {
	let bytes = parse_datarate(input)? / 8;
	if bytes == 0 {
		return Err(DecLimiterError::ParseDatarateError(format!("Datarate too small: {input} is less than 8 bps (1 byte per second)")));
	}
	Ok(bytes)
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

/// Retrieves the process name for a given PID using the sysinfo crate.
/// Returns None if the PID does not exist or cannot be accessed.
pub fn get_process_name(pid: u32) -> Option<String> {
	let mut sys = System::new().ok()?;

	let sys_pid = Pid::from_u32(pid);
	sys.refresh_processes(ProcessesToUpdate::Some(&[sys_pid]), true);

	sys.process(sys_pid).map(|p| p.name().to_string_lossy().into_owned())
}

/// Finds all processes matching a given process name
///
/// # Arguments
/// * `process_name` - The name of the process to search for (e.g., "chrome.exe").
///
/// # Returns
/// A vector of PIDs (`Vec<(u32, String)>`) found with that name. u32 is pid and String is the process name.
pub fn find_process(process_name: &str) -> Vec<ProcessPair> {
	let refresh_kind = RefreshKind::nothing().with_processes(ProcessRefreshKind::everything());
	let Ok(sys) = System::new_with_specifics(refresh_kind) else {
		return Vec::new();
	};

	let mut vec = Vec::new();

	for p in sys.processes_by_name(OsStr::new(process_name)) {
		vec.push((p.pid().as_u32(), p.name().to_str().unwrap_or("").to_string()));
	}

	vec
}

/// Returns true if this process runs as Administrator (elevated). The packet
/// filter driver needs this.
pub fn is_elevated() -> bool {
	use windows::Win32::Foundation::{CloseHandle, HANDLE};
	use windows::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
	use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

	// Safety: the token handle is valid after OpenProcessToken succeeds and is
	// closed exactly once. The buffer has the size of TOKEN_ELEVATION.
	unsafe {
		let mut token = HANDLE::default();
		if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
			return false;
		}

		let mut elevation = TOKEN_ELEVATION::default();
		let mut size = 0u32;
		let result = GetTokenInformation(token, TokenElevation, Some(&mut elevation as *mut _ as *mut _), size_of::<TOKEN_ELEVATION>() as u32, &mut size);
		let _ = CloseHandle(token);

		result.is_ok() && elevation.TokenIsElevated != 0
	}
}

#[cfg(test)]
mod tests {
	/// The result must agree with Windows: only an elevated process can open
	/// the service manager with full access.
	#[test]
	fn is_elevated_agrees_with_the_service_manager() {
		use windows::Win32::System::Services::{CloseServiceHandle, OpenSCManagerW, SC_MANAGER_ALL_ACCESS};

		let full_access = unsafe { OpenSCManagerW(None, None, SC_MANAGER_ALL_ACCESS) };
		let can_manage = full_access.is_ok();
		if let Ok(handle) = full_access {
			let _ = unsafe { CloseServiceHandle(handle) };
		}

		assert_eq!(super::is_elevated(), can_manage);
	}

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

	#[test]
	fn parse_datarate_accepts_lowercase_units() {
		use super::parse_datarate;

		assert_eq!(parse_datarate("1k").unwrap(), 1_000);
		assert_eq!(parse_datarate("2m").unwrap(), 2_000_000);
		assert_eq!(parse_datarate("3g").unwrap(), 3_000_000_000);
		assert_eq!(parse_datarate("4t").unwrap(), 4_000_000_000_000);
		assert_eq!(parse_datarate("5p").unwrap(), 5_000_000_000_000_000);
		assert_eq!(parse_datarate("10kbps").unwrap(), 10_000);
		assert_eq!(parse_datarate("10mbps").unwrap(), 10_000_000);
	}

	#[test]
	fn parse_datarate_handles_zero_and_fractions() {
		use super::parse_datarate;

		assert_eq!(parse_datarate("0").unwrap(), 0);
		assert_eq!(parse_datarate("0K").unwrap(), 0);
		assert_eq!(parse_datarate("0.5K").unwrap(), 500);
		assert_eq!(parse_datarate("1.05K").unwrap(), 1_050);
		// A fraction of a bit is truncated.
		assert_eq!(parse_datarate("1.9").unwrap(), 1);
		// Leading zeros in the fraction are significant.
		assert_eq!(parse_datarate("1.5005K").unwrap(), 1_500);
	}

	/// Some decimal values have no exact binary form. With floating point, the
	/// product with the multiplier falls a very small amount below the
	/// integer, and the cast to u64 truncates it.
	#[test]
	fn parse_datarate_is_exact_for_decimal_fractions() {
		use super::parse_datarate;

		assert_eq!(parse_datarate("1.001M").unwrap(), 1_001_000);
		assert_eq!(parse_datarate("0.3K").unwrap(), 300);
		assert_eq!(parse_datarate("0.1G").unwrap(), 100_000_000);
		assert_eq!(parse_datarate("2.675M").unwrap(), 2_675_000);
		assert_eq!(parse_datarate("0.000000000000001P").unwrap(), 1);
	}

	#[test]
	fn parse_datarate_saturates_values_that_are_too_large() {
		use super::parse_datarate;

		assert_eq!(parse_datarate("18446744073709551615").unwrap(), u64::MAX);
		assert_eq!(parse_datarate("18446744073709551616").unwrap(), u64::MAX);
		assert_eq!(parse_datarate("99999P").unwrap(), u64::MAX);
		assert_eq!(parse_datarate(&"9".repeat(60)).unwrap(), u64::MAX);
	}

	#[test]
	fn parse_datarate_ignores_digits_that_cannot_change_the_result() {
		use super::parse_datarate;

		let long_fraction = format!("1.{}P", "9".repeat(40));
		assert_eq!(parse_datarate(&long_fraction).unwrap(), 1_999_999_999_999_999);
		assert_eq!(parse_datarate(&format!("7.{}", "9".repeat(40))).unwrap(), 7);
	}

	#[test]
	fn parse_datarate_rejects_invalid_input() {
		use super::parse_datarate;
		use crate::error::DecLimiterError;

		for input in ["", "abc", "K", "Kbps", "bps", "-5", "+5", "1.5.5", "1.", ".5", "10X", "10KB", "10 K", " 10K", "10K ", "10kb", "1,000", "10Mbit", "10Mbpss"] {
			match parse_datarate(input) {
				Err(DecLimiterError::ParseDatarateError(msg)) => assert!(msg.contains(input), "message {msg:?} does not name input {input:?}"),
				other => panic!("input {input:?} must be rejected, got {other:?}"),
			}
		}
	}

	#[test]
	fn parse_byterate_converts_bits_to_bytes() {
		use super::parse_byterate;

		assert_eq!(parse_byterate("8").unwrap(), 1);
		assert_eq!(parse_byterate("15").unwrap(), 1);
		assert_eq!(parse_byterate("16").unwrap(), 2);
		assert_eq!(parse_byterate("10Mbps").unwrap(), 1_250_000);
		assert_eq!(parse_byterate("500k").unwrap(), 62_500);
		assert_eq!(parse_byterate("1.5K").unwrap(), 187);
		assert_eq!(parse_byterate("1G").unwrap(), 125_000_000);
	}

	#[test]
	fn parse_byterate_rejects_less_than_one_byte_per_second() {
		use super::parse_byterate;
		use crate::error::DecLimiterError;

		for input in ["0", "0K", "7", "7bps", "0.007K"] {
			match parse_byterate(input) {
				Err(DecLimiterError::ParseDatarateError(msg)) => assert!(msg.contains("too small") && msg.contains(input), "{msg}"),
				other => panic!("input {input:?} must be rejected, got {other:?}"),
			}
		}
		// The format errors of parse_datarate pass through.
		assert!(matches!(parse_byterate("fast"), Err(DecLimiterError::ParseDatarateError(msg)) if msg.contains("Invalid")));
	}

	#[test]
	fn multiple_maps_every_unit() {
		use super::multiple;

		assert_eq!(multiple(""), 1);
		assert_eq!(multiple("K"), 1_000);
		assert_eq!(multiple("k"), 1_000);
		assert_eq!(multiple("M"), 1_000_000);
		assert_eq!(multiple("m"), 1_000_000);
		assert_eq!(multiple("G"), 1_000_000_000);
		assert_eq!(multiple("g"), 1_000_000_000);
		assert_eq!(multiple("T"), 1_000_000_000_000);
		assert_eq!(multiple("t"), 1_000_000_000_000);
		assert_eq!(multiple("P"), 1_000_000_000_000_000);
		assert_eq!(multiple("p"), 1_000_000_000_000_000);
		// An unknown unit falls back to 1.
		assert_eq!(multiple("X"), 1);
	}

	/// The name of the current process, as sysinfo reports it.
	fn own_name() -> String {
		std::env::current_exe().unwrap().file_name().unwrap().to_string_lossy().into_owned()
	}

	#[test]
	fn get_process_name_finds_the_current_process() {
		use super::get_process_name;

		let name = get_process_name(std::process::id()).expect("the current process must have a name");
		assert_eq!(name.to_lowercase(), own_name().to_lowercase());
	}

	#[test]
	fn get_process_name_returns_none_for_an_unused_pid() {
		use super::get_process_name;

		// Windows PIDs are multiples of 4, thus this PID never exists.
		assert_eq!(get_process_name(u32::MAX - 2), None);
	}

	#[test]
	fn find_process_finds_the_current_process() {
		use super::find_process;

		let pid = std::process::id();
		let found = find_process(&own_name());
		assert!(found.iter().any(|(p, name)| *p == pid && name.eq_ignore_ascii_case(&own_name())), "own PID {pid} not in {found:?}");
	}

	#[test]
	fn find_process_returns_nothing_for_an_unknown_name() {
		use super::find_process;

		assert!(find_process("no-such-process-declimiter-test-0f9a3c.exe").is_empty());
	}
}