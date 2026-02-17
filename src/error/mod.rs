use thiserror::Error;

#[derive(Debug, Error)]
pub enum LimiterCLIError {
	#[error("Provided PID is invalid: {0}")]
	PIDInvalid(String),
	#[error("Failed to parse datarate: {0}")]
	ExecutionError(String),
	#[error("IO error: {0}")]
	IOError(#[from] std::io::Error),
	#[error("User aborted the operation")]
	UserAbort
}