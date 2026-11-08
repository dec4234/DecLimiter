use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecLimiterError {
	#[error("Failed to parse datarate: {0}")]
	ParseDatarateError(String),
	#[error("Failed to parse integer: {0}")]
	ParseFloatError(#[from] std::num::ParseFloatError),
	#[error("Windows error: {0}")]
	WindowsError(#[from] windows::core::Error),
	#[error("No network adapter found")]
	NoAdapterFound,
}

#[cfg(test)]
mod tests {
	use super::DecLimiterError;

	#[test]
	fn messages_name_the_cause() {
		assert_eq!(DecLimiterError::ParseDatarateError("bad".into()).to_string(), "Failed to parse datarate: bad");
		assert_eq!(DecLimiterError::NoAdapterFound.to_string(), "No network adapter found");

		let float_err = "x".parse::<f64>().unwrap_err();
		let err: DecLimiterError = float_err.clone().into();
		assert!(matches!(err, DecLimiterError::ParseFloatError(_)));
		assert_eq!(err.to_string(), format!("Failed to parse integer: {float_err}"));

		let win_err = windows::core::Error::from_hresult(windows::core::HRESULT(0x80070005u32 as i32));
		let err: DecLimiterError = win_err.into();
		assert!(matches!(err, DecLimiterError::WindowsError(_)));
		assert!(err.to_string().starts_with("Windows error: "));
	}
}
