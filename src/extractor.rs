use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use std::future::Future;

use crate::error::AuthentikError;
use crate::user::AuthentikUser;

const DEFAULT_HEADER_PREFIX: &str = "x-authentik";

/// Build an `AuthentikUser` from the parts of an HTTP request by reading
/// the configured authentik proxy headers.
///
/// The default header prefix is `x-authentik`. Override by using the tower
/// [`crate::layer::AuthentikLayer`] (requires the `layer` feature).
///
/// # Extractor usage
///
/// When the default header prefix is used, `AuthentikUser` implements
/// [`FromRequestParts`] directly and can be used as a handler parameter:
///
/// ```ignore
/// async fn me(user: AuthentikUser) -> Json<AuthentikUser> {
///     Json(user)
/// }
/// ```
pub(crate) fn read_user_from_parts(
    parts: &Parts,
    header_prefix: &str,
) -> Result<AuthentikUser, AuthentikError> {
    let prefix = format!("{}-", header_prefix);

    let username = get_header(parts, &prefix, "username")?;
    let email = get_header(parts, &prefix, "email")?;
    let name = get_header(parts, &prefix, "name")?;
    let uid = get_header(parts, &prefix, "uid")?;
    let groups = get_header(parts, &prefix, "groups").unwrap_or_default();
    let groups: Vec<String> = groups
        .split('|')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    Ok(AuthentikUser {
        username,
        email,
        name,
        uid,
        groups,
    })
}

fn get_header(parts: &Parts, prefix: &str, suffix: &str) -> Result<String, AuthentikError> {
    let header_name = format!("{}{}", prefix, suffix);
    parts
        .headers
        .get(&header_name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(AuthentikError::Unauthenticated)
}

// ---------------------------------------------------------------------------
// FromRequestParts impl for AuthentikUser
//
// Note: We implement `FromRequestParts` without `async_trait` because
// axum-core 0.5 returns `impl Future + Send` rather than using a named
// lifetime, which is incompatible with the `#[async_trait]` macro.
// ---------------------------------------------------------------------------

impl<S> FromRequestParts<S> for AuthentikUser
where
    S: Send + Sync,
{
    type Rejection = AuthentikError;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let prefix = {
            #[cfg(feature = "layer")]
            {
                parts
                    .extensions
                    .get::<crate::layer::HeaderPrefix>()
                    .map(|p| p.0.clone())
                    .unwrap_or_else(|| DEFAULT_HEADER_PREFIX.to_string())
            }
            #[cfg(not(feature = "layer"))]
            {
                DEFAULT_HEADER_PREFIX.to_string()
            }
        };
        let result = read_user_from_parts(parts, &prefix);
        std::future::ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    fn parts_with_headers(headers: &[(&str, &str)]) -> Parts {
        let mut req = axum::http::Request::new(());
        for (k, v) in headers {
            req.headers_mut().insert(
                header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        let (parts, _) = req.into_parts();
        parts
    }

    #[test]
    fn test_read_user_with_default_prefix() {
        let parts = parts_with_headers(&[
            ("x-authentik-username", "alice"),
            ("x-authentik-email", "alice@example.com"),
            ("x-authentik-name", "Alice Smith"),
            ("x-authentik-uid", "abc-123"),
            ("x-authentik-groups", "admin|users"),
        ]);
        let user = read_user_from_parts(&parts, "x-authentik").unwrap();
        assert_eq!(user.username, "alice");
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.name, "Alice Smith");
        assert_eq!(user.uid, "abc-123");
        assert_eq!(user.groups, vec!["admin", "users"]);
    }

    #[test]
    fn test_read_user_with_custom_prefix() {
        let parts = parts_with_headers(&[
            ("x-myproxy-username", "bob"),
            ("x-myproxy-email", "bob@example.com"),
            ("x-myproxy-name", "Bob"),
            ("x-myproxy-uid", "def-456"),
            ("x-myproxy-groups", "viewers"),
        ]);
        let user = read_user_from_parts(&parts, "x-myproxy").unwrap();
        assert_eq!(user.username, "bob");
        assert_eq!(user.email, "bob@example.com");
        assert_eq!(user.name, "Bob");
        assert_eq!(user.uid, "def-456");
        assert_eq!(user.groups, vec!["viewers"]);
    }

    #[test]
    fn test_missing_required_header() {
        let parts = parts_with_headers(&[
            ("x-authentik-username", "alice"),
            ("x-authentik-email", "alice@example.com"),
            ("x-authentik-name", "Alice Smith"),
            // missing uid
        ]);
        let err = read_user_from_parts(&parts, "x-authentik").unwrap_err();
        assert!(matches!(err, AuthentikError::Unauthenticated));
    }

    #[test]
    fn test_no_groups_header() {
        let parts = parts_with_headers(&[
            ("x-authentik-username", "alice"),
            ("x-authentik-email", "alice@example.com"),
            ("x-authentik-name", "Alice Smith"),
            ("x-authentik-uid", "abc-123"),
        ]);
        let user = read_user_from_parts(&parts, "x-authentik").unwrap();
        assert!(user.groups.is_empty());
    }

    #[test]
    fn test_empty_groups_header() {
        let parts = parts_with_headers(&[
            ("x-authentik-username", "alice"),
            ("x-authentik-email", "alice@example.com"),
            ("x-authentik-name", "Alice Smith"),
            ("x-authentik-uid", "abc-123"),
            ("x-authentik-groups", ""),
        ]);
        let user = read_user_from_parts(&parts, "x-authentik").unwrap();
        assert!(user.groups.is_empty());
    }

    #[test]
    fn test_no_headers_at_all() {
        let parts = parts_with_headers(&[]);
        let err = read_user_from_parts(&parts, "x-authentik").unwrap_err();
        assert!(matches!(err, AuthentikError::Unauthenticated));
    }
}
