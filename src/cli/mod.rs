pub mod gui;
mod icons;
mod process_list;
mod publisher;

use crate::cli::process_list::init_search;
use crate::driver;
use crate::error::LimiterCLIError;
use clap::Parser;
use clap_derive::Parser;
use declimiter_lib::limiter::DecLimiter;
use declimiter_lib::util::parse_byterate;
use futures::try_join;
use std::io::{BufRead, Write};
use std::time::Duration;

/// Hide the console window by detaching from it.
fn hide_console() {
	unsafe {
		windows::Win32::System::Console::FreeConsole().ok();
	}
}

/// Returns Ok(true) if the GUI was launched, Ok(false) for CLI modes.
pub async fn handle_startup() -> Result<bool, LimiterCLIError> {
	let args = DecLimiterArgs::parse();

	// In GUI mode (no args), hide the console unless --console is passed
	if !args.list && args.pid.is_none() && !args.console {
		hide_console();
	}

	if args.list {
		// Interactive TUI process selector + speed limiter
		if let Some((proc, speed)) = init_search()? {
			prepare_driver(args.install_driver)?;
			let limiter = DecLimiter::new()?;

			try_join!(async { limiter.start().await.expect("Task panicked") }, async { limiter.limit_speed_pid(proc.0, Some(speed), None).await.expect("Task panicked") }, async {
				limiter.garbage_collect_flows(Duration::from_secs(60)).await.expect("Task panicked")
			})
			.map_err(|e| LimiterCLIError::ExecutionError(e.to_string()))?;
		} else {
			println!("No process selected. Exiting.");
		}
		Ok(false)
	} else if args.pid.is_some() {
		// Direct CLI mode with explicit PID
		execute(args).await?;
		Ok(false)
	} else {
		// No args: launch GUI
		gui::launch_gui();
		Ok(true)
	}
}

/// Installs the Windows Packet Filter driver if it is missing. Asks the user
/// first, unless `install_without_prompt` is true.
fn prepare_driver(install_without_prompt: bool) -> Result<(), LimiterCLIError> {
	driver::ensure_ready(
		|| install_without_prompt || ask_to_install(&mut std::io::stdin().lock(), &mut std::io::stdout()),
		|| println!("Downloading and installing the Windows Packet Filter driver {}. Please wait...", driver::WPF_VERSION),
	)?;
	Ok(())
}

/// Shows the install prompt and reads the answer. Only "y" or "yes" agrees.
fn ask_to_install(input: &mut impl BufRead, output: &mut impl Write) -> bool {
	let _ = write!(output, "{}\n\nInstall the driver now? [y/N] ", driver::install_prompt());
	let _ = output.flush();

	let mut answer = String::new();
	if input.read_line(&mut answer).is_err() {
		return false;
	}
	matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct DecLimiterArgs {
	/// PID of the process to manage
	#[arg(short, long)]
	pub pid: Option<u32>,

	/// Download speed limit in bits per second (e.g., "10mbps", "500kbps")
	#[arg(short, long, value_parser = parse_byterate)]
	pub download: Option<u64>,

	/// Upload speed limit in bits per second (e.g., "10mbps", "500kbps")
	#[arg(short, long, value_parser = parse_byterate)]
	pub upload: Option<u64>,

	/// Garbage collection interval in seconds
	#[arg(short, long, default_value_t = 60)]
	pub garbage_collect: u32,

	/// Open the interactive TUI process selector
	#[arg(short, long)]
	pub list: bool,

	/// Show the console window (hidden by default in GUI mode)
	#[arg(long)]
	pub console: bool,

	/// Install the Windows Packet Filter driver without a prompt if it is missing
	#[arg(long)]
	pub install_driver: bool,
}

pub async fn execute(args: DecLimiterArgs) -> Result<(), LimiterCLIError> {
	let pid = args.pid.expect("PID is required for direct mode");
	prepare_driver(args.install_driver)?;
	let limiter = DecLimiter::new()?;

	let mut vec = vec![limiter.start(), limiter.garbage_collect_flows(Duration::from_secs(args.garbage_collect as u64))];

	if args.download.is_some() || args.upload.is_some() {
		vec.push(limiter.limit_speed_pid(pid, args.download, args.upload));
	}

	futures::future::try_join_all(vec).await.map_err(|e| LimiterCLIError::ExecutionError(e.to_string()))?;

	Ok(())
}

#[cfg(test)]
mod tests {
	use super::DecLimiterArgs;
	use clap::Parser;

	fn parse(args: &[&str]) -> Result<DecLimiterArgs, clap::Error> {
		DecLimiterArgs::try_parse_from(std::iter::once("declimiter").chain(args.iter().copied()))
	}

	#[test]
	fn no_arguments_give_gui_defaults() {
		let args = parse(&[]).unwrap();
		assert_eq!(args.pid, None);
		assert_eq!(args.download, None);
		assert_eq!(args.upload, None);
		assert_eq!(args.garbage_collect, 60);
		assert!(!args.list);
		assert!(!args.console);
		assert!(!args.install_driver);
	}

	#[test]
	fn long_options_are_parsed() {
		let args = parse(&["--pid", "1234", "--download", "10M", "--upload", "500kbps", "--garbage-collect", "30", "--console"]).unwrap();
		assert_eq!(args.pid, Some(1234));
		// The limits are in bits per second; the fields hold bytes per second.
		assert_eq!(args.download, Some(1_250_000));
		assert_eq!(args.upload, Some(62_500));
		assert_eq!(args.garbage_collect, 30);
		assert!(args.console);
		assert!(!args.list);
	}

	#[test]
	fn short_options_are_parsed() {
		let args = parse(&["-p", "8", "-d", "1.5K", "-u", "2m", "-g", "5", "-l"]).unwrap();
		assert_eq!(args.pid, Some(8));
		assert_eq!(args.download, Some(187));
		assert_eq!(args.upload, Some(250_000));
		assert_eq!(args.garbage_collect, 5);
		assert!(args.list);
	}

	#[test]
	fn invalid_values_are_rejected() {
		for args in [&["--pid", "abc"][..], &["--pid", "-1"], &["--download", "fast"], &["--upload", "10 MB"], &["--download", "0"], &["--upload", "7bps"], &["--garbage-collect", "-5"], &["--no-such-flag"]] {
			assert!(parse(args).is_err(), "{args:?} must be rejected");
		}
	}

	#[test]
	fn datarate_error_names_the_bad_value() {
		let err = parse(&["--download", "fast"]).unwrap_err().to_string();
		assert!(err.contains("fast"), "{err}");
	}

	#[test]
	fn install_driver_flag_is_parsed() {
		assert!(parse(&["--pid", "1", "--install-driver"]).unwrap().install_driver);
	}

	#[test]
	fn install_prompt_needs_a_yes() {
		let ask = |text: &str| {
			let mut output = Vec::new();
			let agreed = super::ask_to_install(&mut text.as_bytes(), &mut output);
			let shown = String::from_utf8(output).unwrap();
			assert!(shown.contains("Windows Packet Filter"), "{shown}");
			assert!(shown.ends_with("[y/N] "), "{shown}");
			agreed
		};

		for yes in ["y\n", "Y\r\n", "yes\n", "  YES  \n"] {
			assert!(ask(yes), "{yes:?} must agree");
		}
		for no in ["\n", "n\n", "no\n", "yep\n", ""] {
			assert!(!ask(no), "{no:?} must not agree");
		}
	}
}
