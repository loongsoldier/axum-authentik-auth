//! # axum-authentik-auth
//!
//! An [axum](https://crates.io/crates/axum) extractor and middleware for
//! [authentik](https://goauthentik.io/) Proxy Provider forward authentication.
//!
//! ## Overview
//!
//! When using authentik's Proxy Provider with forward auth (single application),
//! authentik sits in front of your application via a reverse proxy (like Nginx).
//! After authenticating the user, it forwards user identity information through
//! HTTP headers such as:
//!
//! - `X-authentik-username`
//! - `X-authentik-email`
//! - `X-authentik-name`
//! - `X-authentik-uid`
//! - `X-authentik-groups`
//!
//! This crate parses those headers into a typed [`AuthentikUser`] struct and
//! provides ergonomic extractors for axum handlers.
//!
//! ## Quick Start
//!
//! ```ignore
//! use axum::{routing::get, Router, Json};
//! use axum_authentik_auth::AuthentikUser;
//!
//! async fn me(user: AuthentikUser) -> Json<AuthentikUser> {
//!     Json(user)
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new()
//!         .route("/api/me", get(me));
//!
//!     let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
//!         .await
//!         .unwrap();
//!     axum::serve(listener, app).await.unwrap();
//! }
//! ```
//!
//! ## Extractor variants
//!
//! - `AuthentikUser` — requires authentication, returns 401 if missing
//! - `Option<AuthentikUser>` — optional authentication, returns `None` if missing
//! - [`require_group`] / [`require_all_groups`] / [`require_any_group`] — handler wrappers for group-based access control
//!
//! ## Custom header prefix
//!
//! If your reverse proxy uses a different header prefix, use the tower layer
//! (requires `layer` feature):
//!
//! ```ignore
//! use axum_authentik_auth::layer::{AuthentikLayer, AuthentikConfig};
//!
//! let app = Router::new()
//!     .route("/api/me", get(me))
//!     .layer(AuthentikLayer::with_config(
//!         AuthentikConfig {
//!             header_prefix: "x-myproxy".to_string(),
//!             require_auth: true,
//!         }
//!     ));
//! ```
//!
//! ## Feature flags
//!
//! - `layer`: Enables the tower [`Layer`](tower::Layer) / middleware for custom header prefix injection.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod extractor;
mod user;

#[cfg(feature = "layer")]
/// Tower middleware and configuration for custom authentik header prefixes.
///
/// Enabled by the `layer` feature flag. When the authentik reverse proxy uses
/// a header prefix other than the default `x-authentik`, inject the custom
/// prefix via [`AuthentikLayer`] into each request's extensions.
pub mod layer;

/// Permission guards for group-based access control.
///
/// Provides handler wrappers ([`require_group`], [`require_all_groups`],
/// [`require_any_group`]) that enforce group membership before the wrapped
/// handler executes. The extractor [`RequireGroup`] wraps [`AuthentikUser`]
/// and implements `Deref` for transparent access.
pub mod guard;

// Re-export the primary types for convenience
pub use error::AuthentikError;
pub use guard::{GroupGuard, RequireGroup, require_all_groups, require_any_group, require_group};
pub use user::AuthentikUser;
