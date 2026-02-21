use thiserror::Error;

#[derive(Debug, Error)]
pub enum LimiterCLIError {
	#[error("Failed to parse datarate: {0}")]
	ExecutionError(String),
	#[error("IO error: {0}")]
	IOError(#[from] std::io::Error),
	#[error("User aborted the operation")]
	UserAbort,
	#[error("Join error: {0}")]
	JoinError(#[from] tokio::task::JoinError),
	#[error("DecLimiter error: {0}")]
	DecLimiterError(#[from] declimiter_lib::error::DecLimiterError),
}