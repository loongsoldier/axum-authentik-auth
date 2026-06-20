//! Group-based permission guards example.
//!
//! Run with:
//! ```bash
//! cargo run --example with_group_guard
//! ```
//!
//! Then test with:
//! ```bash
//! # Admin user — should succeed
//! curl -H "x-authentik-username: alice" \
//!      -H "x-authentik-email: alice@example.com" \
//!      -H "x-authentik-name: Alice" \
//!      -H "x-authentik-uid: abc-123" \
//!      -H "x-authentik-groups: admin|users" \
//!      http://localhost:3001/api/admin
//!
//! # Regular user — should get 403
//! curl -H "x-authentik-username: bob" \
//!      -H "x-authentik-email: bob@example.com" \
//!      -H "x-authentik-name: Bob" \
//!      -H "x-authentik-uid: def-456" \
//!      -H "x-authentik-groups: users" \
//!      http://localhost:3001/api/admin
//! ```

use axum::{routing::get, Router};
use axum_authentik_auth::{require_group, AuthentikUser, RequireGroup};

/// Only users in the "admin" group can access this endpoint.
async fn admin_only(RequireGroup(user): RequireGroup) -> String {
    format!("Welcome, admin {}!", user.username)
}

/// This handler uses the raw user to manually check groups.
async fn dashboard(user: AuthentikUser) -> String {
    if user.has_any_group(&["admin", "editor"]) {
        format!("Dashboard for {}", user.username)
    } else {
        format!("Read-only view for {}", user.username)
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/admin", get(require_group("admin", admin_only)))
        .route("/api/dashboard", get(dashboard));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .unwrap();
    println!("Listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
