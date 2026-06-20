use axum::{Json, Router, body::Body, http::Request, routing::get};
use axum_authentik_auth::{
    AuthentikUser, RequireGroup, require_all_groups, require_any_group, require_group,
};
use serde_json::Value;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a request with the given authentik headers.
fn request_with_headers(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    use axum::http::HeaderName;
    let mut req = Request::get(uri).body(Body::empty()).unwrap();
    for (k, v) in headers {
        req.headers_mut().insert(
            HeaderName::from_bytes(k.as_bytes()).unwrap(),
            v.parse().unwrap(),
        );
    }
    req
}

/// Full set of valid authentik headers (admin user).
const ADMIN_HEADERS: &[(&str, &str)] = &[
    ("x-authentik-username", "alice"),
    ("x-authentik-email", "alice@example.com"),
    ("x-authentik-name", "Alice"),
    ("x-authentik-uid", "abc-123"),
    ("x-authentik-groups", "admin|users"),
];

/// Full set of valid authentik headers (regular user, no admin).
const USER_HEADERS: &[(&str, &str)] = &[
    ("x-authentik-username", "bob"),
    ("x-authentik-email", "bob@example.com"),
    ("x-authentik-name", "Bob"),
    ("x-authentik-uid", "xyz-456"),
    ("x-authentik-groups", "users"),
];

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ---------------------------------------------------------------------------
// Group 1: Extractor behaviour
// ---------------------------------------------------------------------------

#[tokio::test]
async fn full_headers_returns_user_json() {
    async fn handler(user: AuthentikUser) -> Json<AuthentikUser> {
        Json(user)
    }

    let app = Router::new().route("/me", get(handler));
    let resp = app
        .oneshot(request_with_headers("/me", ADMIN_HEADERS))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["username"], "alice");
    assert_eq!(json["email"], "alice@example.com");
    assert_eq!(json["name"], "Alice");
    assert_eq!(json["uid"], "abc-123");
    assert_eq!(json["groups"][0], "admin");
    assert_eq!(json["groups"][1], "users");
}

#[tokio::test]
async fn missing_required_header_returns_401() {
    async fn handler(_user: AuthentikUser) -> &'static str {
        "ok"
    }

    let app = Router::new().route("/me", get(handler));

    // Missing uid header
    let resp = app
        .oneshot(request_with_headers(
            "/me",
            &[
                ("x-authentik-username", "alice"),
                ("x-authentik-email", "alice@example.com"),
                ("x-authentik-name", "Alice"),
            ],
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let json = body_json(resp).await;
    assert_eq!(json["code"], 1000);
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("missing authentication headers")
    );
}

#[tokio::test]
async fn no_groups_header_defaults_to_empty() {
    async fn handler(user: AuthentikUser) -> Json<AuthentikUser> {
        Json(user)
    }

    let app = Router::new().route("/me", get(handler));
    let resp = app
        .oneshot(request_with_headers(
            "/me",
            &[
                ("x-authentik-username", "alice"),
                ("x-authentik-email", "alice@example.com"),
                ("x-authentik-name", "Alice"),
                ("x-authentik-uid", "abc-123"),
            ],
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn empty_groups_header_is_empty_array() {
    async fn handler(user: AuthentikUser) -> Json<AuthentikUser> {
        Json(user)
    }

    let app = Router::new().route("/me", get(handler));
    let resp = app
        .oneshot(request_with_headers(
            "/me",
            &[
                ("x-authentik-username", "alice"),
                ("x-authentik-email", "alice@example.com"),
                ("x-authentik-name", "Alice"),
                ("x-authentik-uid", "abc-123"),
                ("x-authentik-groups", ""),
            ],
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let json = body_json(resp).await;
    assert_eq!(json["groups"].as_array().unwrap().len(), 0);
}

// ---------------------------------------------------------------------------
// Group 2: Error response format
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unauthorized_response_format() {
    async fn handler(_user: AuthentikUser) -> &'static str {
        "ok"
    }

    let app = Router::new().route("/me", get(handler));
    let resp = app
        .oneshot(Request::get("/me").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
    let json = body_json(resp).await;
    assert_eq!(json["code"], 1000);
    assert!(
        json["message"]
            .as_str()
            .unwrap()
            .contains("missing authentication headers")
    );
    assert_eq!(json["data"], Value::Null);
}

#[tokio::test]
async fn forbidden_response_format() {
    async fn admin(RequireGroup(user): RequireGroup) -> String {
        format!("admin: {}", user.username)
    }

    let app = Router::new().route("/admin", get(require_group("admin", admin)));
    // Regular user (no admin group) → 403
    let resp = app
        .oneshot(request_with_headers("/admin", USER_HEADERS))
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
    let json = body_json(resp).await;
    assert_eq!(json["code"], 1001);
    assert!(json["message"].as_str().unwrap().contains("admin"));
    assert_eq!(json["data"], Value::Null);
}

// ---------------------------------------------------------------------------
// Group 3: Group guards
// ---------------------------------------------------------------------------

#[tokio::test]
async fn require_group_passes() {
    async fn admin(RequireGroup(user): RequireGroup) -> String {
        format!("admin: {}", user.username)
    }

    let app = Router::new().route("/admin", get(require_group("admin", admin)));
    let resp = app
        .oneshot(request_with_headers("/admin", ADMIN_HEADERS))
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(std::str::from_utf8(&bytes).unwrap(), "admin: alice");
}

#[tokio::test]
async fn require_group_fails() {
    async fn admin(RequireGroup(_user): RequireGroup) -> String {
        "unreachable".into()
    }

    let app = Router::new().route("/admin", get(require_group("admin", admin)));
    let resp = app
        .oneshot(request_with_headers("/admin", USER_HEADERS))
        .await
        .unwrap();

    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn require_all_groups_passes() {
    async fn superuser(RequireGroup(user): RequireGroup) -> String {
        user.username
    }

    let app = Router::new().route(
        "/super",
        get(require_all_groups(&["admin", "users"], superuser)),
    );

    // admin + users → passes
    let resp = app
        .clone()
        .oneshot(request_with_headers("/super", ADMIN_HEADERS))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // users only → fails (missing admin)
    let resp = app
        .oneshot(request_with_headers("/super", USER_HEADERS))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn require_any_group_passes() {
    async fn staff(RequireGroup(user): RequireGroup) -> String {
        user.username
    }

    let app = Router::new().route(
        "/staff",
        get(require_any_group(&["admin", "editor"], staff)),
    );

    // Regular user has none → fails
    let resp = app
        .clone()
        .oneshot(request_with_headers("/staff", USER_HEADERS))
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Admin user has "admin" → passes
    let resp = app
        .oneshot(request_with_headers("/staff", ADMIN_HEADERS))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
