pub mod gui;
mod process_list;

use crate::cli::process_list::init_search;
use crate::error::LimiterCLIError;
use clap::Parser;
use clap_derive::Parser;
use declimiter_lib::limiter::DecLimiter;
use declimiter_lib::util::Datarate;
use declimiter_lib::util::parse_datarate;
use futures::try_join;
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
			let limiter = DecLimiter::new()?;

			try_join!(
				async { limiter.start().await.expect("Task panicked") },
				async { limiter.limit_speed_pid(proc.0, Some(speed), None).await.expect("Task panicked") },
				async { limiter.garbage_collect_flows(Duration::from_secs(60)).await.expect("Task panicked") }
			)
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

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct DecLimiterArgs {
	/// PID of the process to manage
	#[arg(short, long)]
	pub pid: Option<u32>,

	/// Download speed limit (e.g., "10mbps", "500kbps")
	#[arg(short, long, value_parser = parse_datarate)]
	pub download: Option<Datarate>,

	/// Upload speed limit (e.g., "10mbps", "500kbps")
	#[arg(short, long, value_parser = parse_datarate)]
	pub upload: Option<Datarate>,

	/// Garbage collection interval in seconds
	#[arg(short, long, default_value_t = 60)]
	pub garbage_collect: u32,

	/// Open the interactive TUI process selector
	#[arg(short, long)]
	pub list: bool,

	/// Show the console window (hidden by default in GUI mode)
	#[arg(long)]
	pub console: bool,
}

pub async fn execute(args: DecLimiterArgs) -> Result<(), LimiterCLIError> {
	let pid = args.pid.expect("PID is required for direct mode");
	let limiter = DecLimiter::new()?;

	let mut vec = vec![
		limiter.start(),
		limiter.garbage_collect_flows(Duration::from_secs(args.garbage_collect as u64)),
	];

	if args.download.is_some() || args.upload.is_some() {
		vec.push(limiter.limit_speed_pid(pid, args.download, args.upload));
	}

	futures::future::try_join_all(vec).await.map_err(|e| LimiterCLIError::ExecutionError(e.to_string()))?;

	Ok(())
}
