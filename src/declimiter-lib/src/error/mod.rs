use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecLimiterError {
	#[error("Failed to parse datarate: {0}")]
	ParseDatarateError(String),
	#[error("Failed to parse integer: {0}")]
	ParseFloatError(#[from] std::num::ParseFloatError),
}