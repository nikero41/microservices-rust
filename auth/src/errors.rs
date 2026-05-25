use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Internal error")]
    InternalError(String),
    #[error("Username already exists")]
    UsernameAlreadyExists,
    #[error("Invalid request")]
    InvalidRequest,
}
