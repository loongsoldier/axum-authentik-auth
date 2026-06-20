# axum-authentik-auth

[![Crates.io](https://img.shields.io/crates/v/axum-authentik-auth)](https://crates.io/crates/axum-authentik-auth)
[![License](https://img.shields.io/crates/l/axum-authentik-auth)](LICENSE)

Axum extractor and middleware for [authentik](https://goauthentik.io/) Proxy Provider
forward authentication.

## What it solves

When you use authentik's **Proxy Provider** with forward auth (single application),
authentik sits in front of your app behind Nginx. After authenticating the user,
it forwards identity information via HTTP headers:

```
X-authentik-username: alice
X-authentik-email:    alice@example.com
X-authentik-name:     Alice
X-authentik-uid:      abc-123
X-authentik-groups:   admin|users
```

This crate parses those headers into a typed `AuthentikUser` and exposes it as an
axum extractor, so your handler code is clean and type-safe.

## Prerequisites

### Nginx configuration

This crate assumes you have authentik's Proxy Provider set up with forward auth.
A minimal Nginx config looks like this:

```nginx
server {
    listen 443 ssl;
    server_name app.example.com;

    # Forward authentication to authentik
    auth_request /outpost.goauthentik.io/auth/nginx;
    error_page 401 = @goauthentik_proxy_signin;

    # Pass authentik headers to the backend
    auth_request_set $authentik_username $upstream_http_x_authentik_username;
    auth_request_set $authentik_email    $upstream_http_x_authentik_email;
    auth_request_set $authentik_name     $upstream_http_x_authentik_name;
    auth_request_set $authentik_uid      $upstream_http_x_authentik_uid;
    auth_request_set $authentik_groups   $upstream_http_x_authentik_groups;

    proxy_set_header X-authentik-username $authentik_username;
    proxy_set_header X-authentik-email    $authentik_email;
    proxy_set_header X-authentik-name     $authentik_name;
    proxy_set_header X-authentik-uid      $authentik_uid;
    proxy_set_header X-authentik-groups   $authentik_groups;

    location / {
        proxy_pass http://localhost:3000;
    }

    # authentik sign-in redirect
    location @goauthentik_proxy_signin {
        return 302 /outpost.goauthentik.io/signin?rd=$scheme://$http_host$request_uri;
    }

    # authentik proxy endpoints
    location /outpost.goauthentik.io {
        proxy_pass http://authentik-server:9000/outpost.goauthentik.io;
    }
}
```

> **Important**: This crate reads headers, it does **not** perform authentication.
> Your reverse proxy must be configured to reject unauthenticated requests before
> they reach your application.

## Installation

```toml
[dependencies]
axum-authentik-auth = "0.1"
```

For custom header prefix support:

```toml
[dependencies]
axum-authentik-auth = { version = "0.1", features = ["layer"] }
```

## Quick Start

```rust
use axum::{routing::get, Json, Router};
use axum_authentik_auth::AuthentikUser;

async fn me(user: AuthentikUser) -> Json<AuthentikUser> {
    Json(user)
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/api/me", get(me));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

## API Overview

### `AuthentikUser`

The core struct extracted from authentik headers:

```rust
pub struct AuthentikUser {
    pub username: String,
    pub email:    String,
    pub name:     String,
    pub uid:      String,
    pub groups:   Vec<String>,
}
```

**Extractor usage**:

| Pattern | Behavior |
|---|---|
| `user: AuthentikUser` | Requires auth, returns 401 if missing |
| `user: Option<AuthentikUser>` | Optional auth, returns `None` if missing |

**Group check methods**:

```rust
user.has_group("admin")                      // → bool
user.has_all_groups(&["admin", "editor"])    // → bool
user.has_any_group(&["admin", "moderator"])  // → bool
```

### Group Guards

Handler wrappers for declarative group-based access control:

```rust
use axum_authentik_auth::{require_group, RequireGroup};

async fn admin(RequireGroup(user): RequireGroup) -> String {
    format!("Welcome, admin {}!", user.username)
}

let app = Router::new()
    .route("/admin", get(require_group("admin", admin)));
```

Also available:

- `require_all_groups(&["admin", "editor"], handler)` — must be in **all** groups
- `require_any_group(&["admin", "moderator"], handler)` — must be in **any** group

### Error Responses

Errors are returned as structured JSON:

```json
// 401 Unauthorized
{ "code": 1000, "message": "[authentik] missing authentication headers", "data": null }

// 403 Forbidden
{ "code": 1001, "message": "[authentik] user does not have required group: admin", "data": null }
```

Error codes:

| Variant | Code | HTTP Status |
|---|---|---|
| `AuthentikError::Unauthenticated` | 1000 | 401 |
| `AuthentikError::Forbidden` | 1001 | 403 |

### Custom Header Prefix

If your proxy uses a different header prefix (e.g. `X-MyProxy-*`), enable the
`layer` feature and use `AuthentikLayer`:

```rust
use axum_authentik_auth::layer::{AuthentikLayer, AuthentikConfig};

let app = Router::new()
    .route("/api/me", get(me))
    .layer(AuthentikLayer::with_config(
        AuthentikConfig {
            header_prefix: "x-myproxy".to_string(),
            require_auth: true,
        }
    ));
```

## Feature Flags

| Feature | Description |
|---|---|
| `layer` | Enables `AuthentikLayer` / tower middleware for custom header prefixes |

## Version Compatibility

| axum-authentik-auth | axum | Rust |
|---|---|---|
| 0.1 | 0.8 | 1.70+ |

## License

MIT OR Apache-2.0
