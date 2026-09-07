#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    Precondition(String),
    #[error("{0}")]
    Denied(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}
pub type Result<T> = std::result::Result<T, AppError>;
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        if matches!(e, sqlx::Error::RowNotFound) {
            Self::NotFound("对象不存在".into())
        } else {
            Self::Internal(e.into())
        }
    }
}
impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        Self::Internal(e.into())
    }
}
impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        Self::Internal(e.into())
    }
}
impl From<AppError> for connectrpc::ConnectError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::Invalid(s) => Self::invalid_argument(s),
            AppError::NotFound(s) => Self::not_found(s),
            AppError::Conflict(s) => Self::already_exists(s),
            AppError::Precondition(s) => Self::failed_precondition(s),
            AppError::Denied(s) => Self::permission_denied(s),
            AppError::Internal(error) => {
                tracing::error!(error=?error,"request failed");
                Self::internal("内部错误；请查看服务端日志")
            }
        }
    }
}
