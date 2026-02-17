mod process_list;

use std::time::Duration;
use clap::Parser;
use declimiter_lib::util::parse_datarate;
use clap_derive::{Parser};
use futures::try_join;
use declimiter_lib::limiter::DecLimiter;
use declimiter_lib::util::Datarate;
use crate::cli::process_list::init_search;
use crate::error::LimiterCLIError;

pub async fn handle_startup() -> Result<(), Box<dyn std::error::Error>> {
	if let Ok(args) = DecLimiterArgs::try_parse() {
		execute(args).await?;
	} else {
		if let Some((proc, speed)) = init_search()? {
			let limiter = DecLimiter::new();
			// todo: return handle for more precise management
			try_join!(limiter.start(), limiter.limit_speed_pid(proc.0, speed), limiter.garbage_collect_flows(Duration::from_secs(60)))?;
		} else {
			println!("No process selected. Exiting.");
		}
	}

	Ok(())
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct DecLimiterArgs {
	/// PID of the process to manage
	#[arg(short, long)]
	pub pid: u32,
	
	/// Download speed limit (e.g., "10mbps", "500kbps")
	#[arg(short, long, value_parser = parse_datarate)]
	pub download: Option<Datarate>,

	/// Upload speed limit (e.g., "10mbps", "500kbps")
	#[arg(short, long, value_parser = parse_datarate)]
	pub upload: Option<Datarate>,

	/// Garbage collection interval in seconds
	#[arg(short, long, default_value_t = 60)]
	pub garbage_collect: u32
}

pub async fn execute(args: DecLimiterArgs) -> Result<(), LimiterCLIError> {
	let limiter = DecLimiter::new();

	let mut vec = vec![limiter.garbage_collect_flows(Duration::from_secs(args.garbage_collect as u64))];

	if let Some(download_rate) = args.download {
		vec.push(limiter.limit_speed_pid(args.pid, download_rate));
	}

	// todo: implement upload limiting
	/*if let Some(upload_rate) = args.upload {
		vec.push(limiter.limit_speed_pid(args.pid, upload_rate));
	}*/

	futures::future::try_join_all(vec).await.map_err(|e| LimiterCLIError::ExecutionError(e.to_string()))?;

	Ok(())
}