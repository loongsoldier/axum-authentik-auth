use apiresponse::{ApiResponse, Response};
use axum::response::{IntoResponse, Response as AxumResponse};

/// Error type for authentik authentication failures.
///
/// Derives [`Response`] from the `apiresponse` crate, which provides
/// structured error codes, module-prefixed messages, and HTTP status codes.
/// Error responses are always JSON via [`ApiResponse`].
///
/// All variants implement [`IntoResponse`], so they can be returned directly
/// from handler functions as `Result<T, AuthentikError>`.
///
/// # Error codes
///
/// | Variant          | Code | HTTP Status |
/// |------------------|------|-------------|
/// | `Unauthenticated`| 1000 | 401         |
/// | `Forbidden`      | 1001 | 403         |
#[derive(Debug, thiserror::Error, Response)]
#[response(module = "authentik")]
pub enum AuthentikError {
    /// The user is not authenticated (missing or invalid auth headers).
    #[error("missing authentication headers")]
    #[response(code = 1000, status = 401)]
    Unauthenticated,

    /// The user is authenticated but does not have the required permissions.
    #[error("user does not have required group: {required_group}")]
    #[response(code = 1001, status = 403)]
    Forbidden {
        /// The group that the user was required to belong to.
        required_group: String,
    },
}

impl IntoResponse for AuthentikError {
    fn into_response(self) -> AxumResponse {
        // ApiResponse produces JSON: { "code": 1000, "message": "[authentik] ...", "data": null }
        // HTTP status code is set automatically from self.http_status_code().
        let result: Result<(), Self> = Err(self);
        ApiResponse::from(result).into_response()
    }
}
