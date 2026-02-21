use thiserror::Error;
use windivert::error::WinDivertError;

#[derive(Debug, Error)]
pub enum DecLimiterError {
	#[error("Failed to parse datarate: {0}")]
	ParseDatarateError(String),
	#[error("Failed to parse integer: {0}")]
	ParseFloatError(#[from] std::num::ParseFloatError),
	#[error("WinDivert error: {0}")]
	WinDivertError(#[from] WinDivertError),
}