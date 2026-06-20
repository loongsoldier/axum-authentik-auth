use axum::http::Request;
use std::fmt;
use std::task::{Context, Poll};
use tower::Service;

/// A newtype wrapper that holds a custom header prefix for authentik headers.
///
/// Inserted into request extensions by the [`AuthentikLayer`] so that the
/// extractor can pick it up.
#[derive(Debug, Clone)]
pub struct HeaderPrefix(pub String);

/// Configuration for the authentik authentication layer.
///
/// # Example
///
/// ```ignore
/// let config = AuthentikConfig::default();
/// let layer = AuthentikLayer::with_config(config);
/// ```
#[derive(Debug, Clone)]
pub struct AuthentikConfig {
    /// Prefix for authentik proxy headers, defaults to `"x-authentik"`.
    ///
    /// For example, with the default prefix the extractor reads headers like:
    /// `x-authentik-username`, `x-authentik-email`, etc.
    pub header_prefix: String,

    /// If `true` (the default), requests missing auth headers return 401.
    /// If `false`, the extraction is optional (`Option<AuthentikUser>`).
    pub require_auth: bool,
}

impl Default for AuthentikConfig {
    fn default() -> Self {
        Self {
            header_prefix: "x-authentik".to_string(),
            require_auth: true,
        }
    }
}

impl AuthentikConfig {
    /// Creates a new `AuthentikConfig` with the given header prefix.
    pub fn with_prefix(header_prefix: impl Into<String>) -> Self {
        Self {
            header_prefix: header_prefix.into(),
            require_auth: true,
        }
    }
}

/// A tower [`Layer`] that injects the authentik header prefix into request extensions.
///
/// This layer must be added to the router when you use a custom header prefix
/// other than the default `x-authentik`.
///
/// # Example
///
/// ```ignore
/// use axum_authentik_auth::layer::{AuthentikLayer, AuthentikConfig};
///
/// let app = Router::new()
///     .route("/api/me", get(me_handler))
///     .layer(AuthentikLayer::new()); // uses default config
/// ```
pub struct AuthentikLayer {
    config: AuthentikConfig,
}

impl AuthentikLayer {
    /// Creates a new layer with default configuration (prefix `x-authentik`, require auth).
    pub fn new() -> Self {
        Self {
            config: AuthentikConfig::default(),
        }
    }

    /// Creates a new layer with a custom configuration.
    pub fn with_config(config: AuthentikConfig) -> Self {
        Self { config }
    }
}

impl Default for AuthentikLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> tower::Layer<S> for AuthentikLayer {
    type Service = AuthentikMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthentikMiddleware {
            inner,
            config: self.config.clone(),
        }
    }
}

impl fmt::Debug for AuthentikLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthentikLayer")
            .field("header_prefix", &self.config.header_prefix)
            .field("require_auth", &self.config.require_auth)
            .finish()
    }
}

/// Middleware service that injects the custom header prefix into each request.
///
/// You normally don't need to use this directly; prefer [`AuthentikLayer`].
#[derive(Clone)]
pub struct AuthentikMiddleware<S> {
    inner: S,
    config: AuthentikConfig,
}

impl<S, ReqBody> Service<Request<ReqBody>> for AuthentikMiddleware<S>
where
    S: Service<Request<ReqBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = futures_util::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        // Inject the configured header prefix into request extensions
        req.extensions_mut()
            .insert(HeaderPrefix(self.config.header_prefix.clone()));

        let inner = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, inner);

        Box::pin(async move { inner.call(req).await })
    }
}

impl<S: fmt::Debug> fmt::Debug for AuthentikMiddleware<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthentikMiddleware")
            .field("inner", &self.inner)
            .field("header_prefix", &self.config.header_prefix)
            .finish()
    }
}
