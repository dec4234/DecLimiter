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

#[cfg(test)]
mod tests {
	use super::LimiterCLIError;
	use declimiter_lib::error::DecLimiterError;

	#[test]
	fn messages_name_the_cause() {
		assert_eq!(LimiterCLIError::ExecutionError("boom".into()).to_string(), "Failed to parse datarate: boom");
		assert_eq!(LimiterCLIError::UserAbort.to_string(), "User aborted the operation");

		let err: LimiterCLIError = std::io::Error::other("disk").into();
		assert!(matches!(err, LimiterCLIError::IOError(_)));
		assert_eq!(err.to_string(), "IO error: disk");

		let err: LimiterCLIError = DecLimiterError::NoAdapterFound.into();
		assert!(matches!(err, LimiterCLIError::DecLimiterError(_)));
		assert_eq!(err.to_string(), "DecLimiter error: No network adapter found");
	}

	#[tokio::test]
	async fn join_error_converts() {
		let join_err = tokio::spawn(async { panic!("task failed") }).await.unwrap_err();
		let err: LimiterCLIError = join_err.into();
		assert!(matches!(err, LimiterCLIError::JoinError(_)));
		assert!(err.to_string().starts_with("Join error: "));
	}
}
