use std::time::Duration;

use thiserror::Error;

/// Error from the HTTP transport used to reach Apple's endpoints — a network
/// failure, or a non-2xx HTTP response (status code + raw body). Deliberately
/// narrower than `IdunnError`: this is also what external `HttpTransport`
/// implementors construct, and they shouldn't need to know about idunn's
/// Apple-specific error variants. `Network` is boxed rather than tied to
/// `reqwest::Error` so a non-reqwest `HttpTransport` implementation can report
/// its own underlying error type.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("network error: {0}")]
    Network(Box<dyn std::error::Error + Send + Sync>),
    #[error("HTTP {status} response: {body}")]
    Http { status: u16, body: String },
}

/// Abstraction over GET requests needed to talk to Apple's endpoints (currently just
/// JWKS fetching). Split out from `HttpPostForm` so read-only call sites can bound on
/// this alone, instead of requiring a `post_form` implementation they'd never call.
pub trait HttpGet: Clone + Send + Sync + 'static {
    /// GETs a resource, returning the response body on success (2xx) or a
    /// `TransportError` on failure. No body is sent; `headers` and `timeout` are
    /// mandatory — callers must decide how long they're willing to wait, there is no
    /// implicit default.
    fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        timeout: Duration,
    ) -> impl Future<Output = Result<String, TransportError>> + Send;
}

/// Abstraction over POST-form requests needed to talk to Apple's token endpoints.
/// Split out from `HttpGet` so write-only call sites can bound on this alone.
pub trait HttpPost: Clone + Send + Sync + 'static {
    /// POSTs a body, returning the response body on success (2xx) or a `TransportError`
    /// (network failure, or the raw status/body on non-2xx). `body` is already
    /// url-encoded by idunn — implementors just need to send it, not assemble it
    /// themselves. `headers` are the header key/value pairs the caller wants attached
    /// (e.g. `Content-Type`) — implementors attach them as given, they don't assume or
    /// hardcode a content type themselves. `timeout` is mandatory — callers must decide
    /// how long they're willing to wait, there is no implicit default.
    fn post_form(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &str,
        timeout: Duration,
    ) -> impl Future<Output = Result<String, TransportError>> + Send;
}

/// Combined GET + POST-form capability. Exists so the transport is swappable (idunn
/// consumers may prefer a differently configured or non-reqwest client) and so tests
/// can substitute an in-memory fake instead of hitting the network. Implemented
/// automatically for any type that has both `HttpGet` and `HttpPostForm` — implement
/// those two traits, not this one, directly.
pub trait HttpTransport: HttpGet + HttpPost {}
impl<T: HttpGet + HttpPost> HttpTransport for T {}

#[cfg(feature = "reqwest")]
#[derive(Clone, Default)]
pub struct ReqwestTransport(reqwest::Client);

#[cfg(feature = "reqwest")]
impl ReqwestTransport {
    /// Wraps a caller-configured `reqwest::Client` — e.g. one built with
    /// `.connection_verbose(true)` for wire-level debugging.
    #[cfg(test)]
    pub(crate) fn with_client(client: reqwest::Client) -> Self {
        Self(client)
    }

    fn with_headers(
        mut request: reqwest::RequestBuilder,
        headers: &[(&str, &str)],
    ) -> reqwest::RequestBuilder {
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        request
    }

    async fn send(request: reqwest::RequestBuilder) -> Result<String, TransportError> {
        let resp = request
            .send()
            .await
            .map_err(|e| TransportError::Network(Box::new(e)))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| TransportError::Network(Box::new(e)))?;
        if !status.is_success() {
            return Err(TransportError::Http {
                status: status.as_u16(),
                body,
            });
        }
        Ok(body)
    }
}

#[cfg(feature = "reqwest")]
impl HttpPost for ReqwestTransport {
    async fn post_form(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        body: &str,
        timeout: Duration,
    ) -> Result<String, TransportError> {
        let request =
            Self::with_headers(self.0.post(url).body(body.to_string()), headers).timeout(timeout);
        Self::send(request).await
    }
}

#[cfg(feature = "reqwest")]
impl HttpGet for ReqwestTransport {
    async fn get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        timeout: Duration,
    ) -> Result<String, TransportError> {
        let request = Self::with_headers(self.0.get(url), headers).timeout(timeout);
        Self::send(request).await
    }
}

pub(crate) fn encode_form(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

#[cfg(all(test, feature = "reqwest"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn send_returns_network_error_when_request_fails() {
        let client = reqwest::Client::new();
        let transport = ReqwestTransport::with_client(client);

        let result = transport
            .get("http://127.0.0.1:1", &[], Duration::from_secs(1))
            .await;

        assert!(matches!(result, Err(TransportError::Network(_))));
    }
}
