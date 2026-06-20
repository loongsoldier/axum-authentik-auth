//! Simplest usage: extract `AuthentikUser` from default `x-authentik-*` headers.
//!
//! Run with:
//! ```bash
//! cargo run --example basic
//! ```
//!
//! Then test with:
//! ```bash
//! curl -H "x-authentik-username: alice" \
//!      -H "x-authentik-email: alice@example.com" \
//!      -H "x-authentik-name: Alice" \
//!      -H "x-authentik-uid: abc-123" \
//!      -H "x-authentik-groups: admin|users" \
//!      http://localhost:3000/api/me
//! ```

use axum::{Json, Router, routing::get};
use axum_authentik_auth::AuthentikUser;

/// Returns the authenticated user's information as JSON.
async fn me(user: AuthentikUser) -> Json<AuthentikUser> {
    Json(user)
}

/// Checks group membership manually.
async fn dashboard(user: AuthentikUser) -> String {
    if user.has_any_group(&["admin", "editor"]) {
        format!("Dashboard for {} (privileged)", user.username)
    } else {
        format!("Read-only view for {}", user.username)
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/me", get(me))
        .route("/api/dashboard", get(dashboard));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("Listening on http://{}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
