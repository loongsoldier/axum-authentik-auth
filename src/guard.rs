use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::response::Response;
use std::future::Future;

use crate::error::AuthentikError;
use crate::user::AuthentikUser;

// ---------------------------------------------------------------------------
// RequireGroup
// ---------------------------------------------------------------------------

/// A permission guard that wraps [`AuthentikUser`].
///
/// Use [`require_group`] to create a handler wrapper that checks group
/// membership, or call [`AuthentikUser::has_group`] manually for maximum
/// flexibility.
///
/// # Example
///
/// ```ignore
/// use axum_authentik_auth::{AuthentikUser, require_group};
///
/// async fn admin_panel(user: AuthentikUser) -> String {
///     format!("Welcome, admin {}!", user.username)
/// }
///
/// // In router setup:
/// // .route("/admin", get(require_group("admin", admin_panel)))
/// ```
#[derive(Debug, Clone)]
pub struct RequireGroup(pub AuthentikUser);

impl std::ops::Deref for RequireGroup {
    type Target = AuthentikUser;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// require_group / require_any_group / require_all_groups handlers
// ---------------------------------------------------------------------------

/// Extractor key stored in request extensions to indicate which group(s) are required.
#[derive(Debug, Clone)]
struct RequiredGroups(Vec<String>);

/// Extractor key stored in request extensions to indicate the matching mode.
#[derive(Debug, Clone, Copy)]
enum GroupMatchMode {
    All,
    Any,
}

impl<S> FromRequestParts<S> for RequireGroup
where
    S: Send + Sync,
{
    type Rejection = AuthentikError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        // Read extensions BEFORE calling from_request_parts to avoid borrow conflict
        let required = parts.extensions.get::<RequiredGroups>().cloned();
        let mode = parts.extensions.get::<GroupMatchMode>().copied();
        let user_fut = AuthentikUser::from_request_parts(parts, state);
        async move {
            let user = user_fut.await?;
            match required {
                Some(groups) if !groups.0.is_empty() => {
                    let passes = match mode.unwrap_or(GroupMatchMode::Any) {
                        GroupMatchMode::All => groups.0.iter().all(|g| user.has_group(g)),
                        GroupMatchMode::Any => groups.0.iter().any(|g| user.has_group(g)),
                    };
                    if passes {
                        Ok(RequireGroup(user))
                    } else {
                        let desc = match mode.unwrap_or(GroupMatchMode::Any) {
                            GroupMatchMode::All => groups.0.join(", "),
                            GroupMatchMode::Any => groups.0.join(" or "),
                        };
                        Err(AuthentikError::Forbidden {
                            required_group: desc,
                        })
                    }
                }
                _ => Ok(RequireGroup(user)),
            }
        }
    }
}

/// Wraps a handler function so that it requires the user to be a member of
/// the given group. The handler must accept a [`RequireGroup`] parameter.
///
/// # Example
///
/// ```ignore
/// use axum::routing::get;
/// use axum_authentik_auth::require_group;
///
/// async fn admin(user: RequireGroup) -> String {
///     format!("Admin: {}", user.username)
/// }
///
/// let app = Router::new()
///     .route("/admin", get(require_group("admin", admin)));
/// ```
pub fn require_group<H, T>(group: &'static str, handler: H) -> GroupGuard<H>
where
    H: axum::handler::Handler<T, ()>,
    T: 'static,
{
    GroupGuard {
        handler,
        groups: vec![group.to_string()],
        mode: GroupMatchMode::Any,
    }
}

/// Wraps a handler function so that it requires the user to be a member of
/// **all** the specified groups.
///
/// # Example
///
/// ```ignore
/// use axum_authentik_auth::require_all_groups;
///
/// async fn superuser(user: RequireGroup) -> String {
///     format!("Superuser: {}", user.username)
/// }
///
/// // .route("/super", get(require_all_groups(&["admin", "superuser"], superuser)))
/// ```
pub fn require_all_groups<H, T>(groups: &[&'static str], handler: H) -> GroupGuard<H>
where
    H: axum::handler::Handler<T, ()>,
    T: 'static,
{
    GroupGuard {
        handler,
        groups: groups.iter().map(|g| g.to_string()).collect(),
        mode: GroupMatchMode::All,
    }
}

/// Wraps a handler function so that it requires the user to be a member of
/// **any** of the specified groups.
///
/// # Example
///
/// ```ignore
/// use axum_authentik_auth::require_any_group;
///
/// async fn staff(user: RequireGroup) -> String {
///     format!("Staff: {}", user.username)
/// }
///
/// // .route("/staff", get(require_any_group(&["admin", "moderator"], staff)))
/// ```
pub fn require_any_group<H, T>(groups: &[&'static str], handler: H) -> GroupGuard<H>
where
    H: axum::handler::Handler<T, ()>,
    T: 'static,
{
    GroupGuard {
        handler,
        groups: groups.iter().map(|g| g.to_string()).collect(),
        mode: GroupMatchMode::Any,
    }
}

/// A handler wrapper that injects required-group information into request
/// extensions before calling the inner handler.
///
/// Created by [`require_group`], [`require_all_groups`], or [`require_any_group`].
pub struct GroupGuard<H> {
    handler: H,
    groups: Vec<String>,
    mode: GroupMatchMode,
}

impl<H: Clone> Clone for GroupGuard<H> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
            groups: self.groups.clone(),
            mode: self.mode,
        }
    }
}

impl<H, T, S> axum::handler::Handler<T, S> for GroupGuard<H>
where
    H: axum::handler::Handler<T, S> + Clone + Send + 'static,
    T: 'static,
    S: Send + Sync + 'static,
{
    type Future = std::pin::Pin<Box<dyn Future<Output = Response> + Send + 'static>>;

    fn call(self, mut req: axum::extract::Request, state: S) -> Self::Future {
        req.extensions_mut()
            .insert(RequiredGroups(self.groups.clone()));
        req.extensions_mut().insert(self.mode);
        let handler = self.handler;
        Box::pin(async move { handler.call(req, state).await })
    }
}
