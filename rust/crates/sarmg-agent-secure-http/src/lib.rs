//! Network policy is a closed enum; production code cannot opt into arbitrary plaintext HTTP.

mod dns;

#[cfg(test)]
mod transport_tests;

/// Maximum encoded bytes in one configured TLS identity or trust-anchor file.
pub const MAX_TLS_INPUT_BYTES: usize = 1024 * 1024;

pub use reqwest::{Certificate, Identity, StatusCode, header};
use reqwest::{Client, Request, Response, redirect::Policy};
use std::sync::Arc;
use std::{net::IpAddr, time::Duration};
use url::Host;
pub use url::Url;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkPolicy {
    PublicHttps,
    PrivateDevice {
        allow_loopback: bool,
        allow_link_local: bool,
    },
    LoopbackDevelopment,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseBudget {
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
}
impl Default for ResponseBudget {
    fn default() -> Self {
        Self {
            max_header_bytes: 64 * 1024,
            max_body_bytes: 1024 * 1024,
        }
    }
}

/// Parsed TLS material, never formatted or serialized. Products select protected
/// input files; the factory owns backend, trust and verification configuration.
#[derive(Clone, Default)]
pub struct TlsConfig {
    pub identity: Option<Identity>,
    pub roots: Vec<Certificate>,
}
impl std::fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsConfig([REDACTED])")
    }
}

const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_RESOLVED_ADDRESSES: usize = 16;
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct SecureHttpClient {
    configuration: Arc<Configuration>,
}
struct Configuration {
    dns: dns::Settings,
    budget: ResponseBudget,
    total_timeout: Duration,
    tls: TlsConfig,
    user_agent: String,
}
impl std::fmt::Debug for SecureHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureHttpClient([REDACTED])")
    }
}
impl SecureHttpClient {
    pub fn new(
        total_timeout: Duration,
        budget: ResponseBudget,
        tls: TlsConfig,
        user_agent: String,
    ) -> Result<Self, Error> {
        if total_timeout.is_zero()
            || budget.max_header_bytes == 0
            || budget.max_header_bytes > 64 * 1024
            || budget.max_body_bytes == 0
            || budget.max_body_bytes > 1024 * 1024
        {
            return Err(Error::InvalidBudget);
        }
        let client = Self {
            configuration: Arc::new(Configuration {
                dns: dns::Settings::default(),
                budget,
                total_timeout,
                tls,
                user_agent,
            }),
        };
        // Read-only construction validation; no DNS, request or state mutation.
        client.client_builder().build()?;
        Ok(client)
    }

    fn client_builder(&self) -> reqwest::ClientBuilder {
        let settings = &self.configuration;
        let mut builder = Client::builder()
            .timeout(settings.total_timeout)
            .connect_timeout(settings.total_timeout.min(MAX_CONNECT_TIMEOUT))
            .redirect(Policy::none())
            // DNS validation/pinning must also control the actual connection.
            // An environment proxy would resolve/connect outside that boundary.
            .no_proxy()
            .dns_resolver(Arc::new(dns::BoundOnly))
            .http2_max_header_list_size(settings.budget.max_header_bytes as u32)
            .user_agent(&settings.user_agent);
        #[cfg(any(windows, target_os = "macos"))]
        {
            builder = builder.tls_backend_native();
        }
        #[cfg(all(not(windows), not(target_os = "macos")))]
        {
            builder = builder.tls_backend_rustls();
        }
        if let Some(identity) = &settings.tls.identity {
            builder = builder.identity(identity.clone());
        }
        for certificate in &settings.tls.roots {
            builder = builder.add_root_certificate(certificate.clone());
        }
        builder
    }

    /// The only execution entry: resolution, connection, headers and complete
    /// bounded body all share one deadline. No raw Response/Client escapes.
    pub async fn execute(
        &self,
        policy: NetworkPolicy,
        mut request: Request,
    ) -> Result<BoundedResponse, Error> {
        validate_url_structure(policy, request.url())?;
        if request.body().is_some_and(|body| {
            body.as_bytes()
                .is_none_or(|bytes| bytes.len() > MAX_REQUEST_BYTES)
        }) {
            return Err(Error::RequestTooLarge);
        }
        for (name, value) in request.headers_mut().iter_mut() {
            if [
                header::AUTHORIZATION,
                header::PROXY_AUTHORIZATION,
                header::COOKIE,
            ]
            .contains(name)
            {
                value.set_sensitive(true);
            }
        }
        let dns_scope = dns::Scope::default();
        let operation = async {
            let host = normalized_host(request.url())?;
            let port = request
                .url()
                .port_or_known_default()
                .ok_or(Error::UnsafeUrl)?;
            let addresses = dns_scope
                .resolve(
                    &self.configuration.dns,
                    &host,
                    port,
                    self.configuration.total_timeout,
                )
                .await?;
            for address in &addresses {
                validate_address(policy, address.ip())?;
            }
            let client = self
                .client_builder()
                .resolve_to_addrs(&host, &addresses)
                .build()?;
            let response = client.execute(request).await?;
            let status = response.status();
            // Validate/count before cloning headers.
            validate_response_headers(&response, self.configuration.budget)?;
            let headers = response.headers().clone();
            let body = bounded_response(response, self.configuration.budget).await?;
            Ok(BoundedResponse {
                status,
                headers,
                body,
            })
        };
        let result = tokio::time::timeout(self.configuration.total_timeout, operation)
            .await
            .map_err(|_| Error::Timeout);
        dns_scope.finish().await;
        result?
    }

    /// Desktop/mobile Agent delivery selects only PublicHttps or the debug-only
    /// loopback policy; a product cannot enable arbitrary remote plaintext.
    pub async fn post_agent(
        &self,
        url: &str,
        headers: header::HeaderMap,
        body: Vec<u8>,
    ) -> Result<BoundedResponse, Error> {
        let url = Url::parse(url).map_err(|_| Error::UnsafeUrl)?;
        let policy = agent_network_policy(&url)?;
        let mut request = Request::new(reqwest::Method::POST, url);
        *request.headers_mut() = headers;
        *request.body_mut() = Some(body.into());
        self.execute(policy, request).await
    }

    /// Synchronous UI-thread adapter, including callers already inside Tokio.
    /// The scoped worker owns its runtime and is joined before returning; there
    /// is no second HTTP implementation or detached request task. DNS uses
    /// request-owned async transports, not uncancellable OS resolver work.
    pub fn get_agent_blocking(
        &self,
        url: &str,
        headers: header::HeaderMap,
    ) -> Result<BoundedResponse, Error> {
        let url = Url::parse(url).map_err(|_| Error::UnsafeUrl)?;
        let policy = agent_network_policy(&url)?;
        let mut request = Request::new(reqwest::Method::GET, url);
        *request.headers_mut() = headers;
        std::thread::scope(|scope| {
            std::thread::Builder::new()
                .name("agent-http-sync".into())
                .spawn_scoped(scope, move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|_| Error::Runtime)?;
                    runtime.block_on(self.execute(policy, request))
                })
                .map_err(|_| Error::Runtime)?
                .join()
                .map_err(|_| Error::Runtime)?
        })
    }
}

pub fn agent_network_policy(url: &Url) -> Result<NetworkPolicy, Error> {
    let policy = if url.scheme() == "https" {
        NetworkPolicy::PublicHttps
    } else {
        NetworkPolicy::LoopbackDevelopment
    };
    validate_url_structure(policy, url)?;
    Ok(policy)
}

pub struct BoundedResponse {
    pub status: reqwest::StatusCode,
    pub headers: header::HeaderMap,
    pub body: Vec<u8>,
}
impl std::fmt::Debug for BoundedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundedResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

pub fn validate_url_structure(policy: NetworkPolicy, url: &Url) -> Result<(), Error> {
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(Error::UnsafeUrl);
    }
    let host = url.host().ok_or(Error::UnsafeUrl)?;
    if url.port_or_known_default().is_none() {
        return Err(Error::UnsafeUrl);
    }
    if policy == NetworkPolicy::LoopbackDevelopment && !cfg!(debug_assertions) {
        return Err(Error::DevelopmentOnly);
    }
    match policy {
        NetworkPolicy::PublicHttps if url.scheme() != "https" => Err(Error::HttpsRequired),
        NetworkPolicy::PrivateDevice { .. } if !matches!(url.scheme(), "http" | "https") => {
            Err(Error::UnsafeScheme)
        }
        NetworkPolicy::LoopbackDevelopment if url.scheme() != "http" => Err(Error::UnsafeScheme),
        NetworkPolicy::LoopbackDevelopment => match host {
            Host::Ipv4(address) if address.is_loopback() => Ok(()),
            Host::Ipv6(address) if address.is_loopback() => Ok(()),
            Host::Domain(domain) if domain.eq_ignore_ascii_case("localhost") => Ok(()),
            _ => Err(Error::UnsafeUrl),
        },
        _ => Ok(()),
    }
}

fn normalized_host(url: &Url) -> Result<String, Error> {
    match url.host().ok_or(Error::UnsafeUrl)? {
        Host::Domain(domain) => Ok(domain.to_owned()),
        Host::Ipv4(address) => Ok(address.to_string()),
        Host::Ipv6(address) => Ok(address.to_string()),
    }
}

fn validate_response_headers(response: &Response, budget: ResponseBudget) -> Result<(), Error> {
    let header_bytes = response
        .headers()
        .iter()
        .try_fold(0usize, |total, (name, value)| {
            total
                .checked_add(name.as_str().len() + value.as_bytes().len() + 4)
                .ok_or(Error::ResponseTooLarge)
        })?;
    if header_bytes > budget.max_header_bytes {
        return Err(Error::ResponseTooLarge);
    }
    if response
        .content_length()
        .is_some_and(|n| n > budget.max_body_bytes as u64)
    {
        return Err(Error::ResponseTooLarge);
    }
    Ok(())
}

async fn bounded_response(
    mut response: Response,
    budget: ResponseBudget,
) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|size| size > budget.max_body_bytes)
        {
            return Err(Error::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate_address(policy: NetworkPolicy, address: IpAddr) -> Result<(), Error> {
    let address = match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        _ => address,
    };
    if is_metadata(address) || address.is_unspecified() || address.is_multicast() {
        return Err(Error::ForbiddenAddress(address));
    }
    match policy {
        NetworkPolicy::PublicHttps => Ok(()),
        NetworkPolicy::LoopbackDevelopment if address.is_loopback() => Ok(()),
        NetworkPolicy::LoopbackDevelopment => Err(Error::ForbiddenAddress(address)),
        NetworkPolicy::PrivateDevice {
            allow_loopback,
            allow_link_local,
        } => {
            if address.is_loopback() && !allow_loopback {
                return Err(Error::ForbiddenAddress(address));
            }
            if is_link_local(address) && !allow_link_local {
                return Err(Error::ForbiddenAddress(address));
            }
            Ok(())
        }
    }
}
fn is_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_link_local(),
        IpAddr::V6(v) => v.is_unicast_link_local(),
    }
}
fn is_metadata(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.octets() == [169, 254, 169, 254],
        IpAddr::V6(v) => v.segments() == [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254],
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTPS is required by this network policy")]
    HttpsRequired,
    #[error("URL scheme is not allowed by this network policy")]
    UnsafeScheme,
    #[error("URL contains forbidden components")]
    UnsafeUrl,
    #[error("address is forbidden by this network policy: {0}")]
    ForbiddenAddress(IpAddr),
    #[error("network policy budget is invalid")]
    InvalidBudget,
    #[error("response exceeds its configured budget")]
    ResponseTooLarge,
    #[error("DNS resolution returned no addresses")]
    ResolveEmpty,
    #[error("DNS resolution failed")]
    Resolve,
    #[error("DNS resolution exceeds its configured budget")]
    ResolveTooLarge,
    #[error("HTTP operation exceeded its total deadline")]
    Timeout,
    #[error("request body exceeds its budget or is not bounded")]
    RequestTooLarge,
    #[error("loopback HTTP is available only in debug builds")]
    DevelopmentOnly,
    #[error("HTTP transport or TLS configuration failed")]
    Http,
    #[error("HTTP runtime could not start or finish")]
    Runtime,
}

impl From<reqwest::Error> for Error {
    fn from(error: reqwest::Error) -> Self {
        // Do not retain backend error sources, URLs or reflected secret values.
        if error.is_timeout() {
            Self::Timeout
        } else {
            Self::Http
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_remote_http_and_metadata() {
        assert!(
            validate_address(
                NetworkPolicy::LoopbackDevelopment,
                "127.0.0.1".parse().unwrap()
            )
            .is_ok()
        );
        assert!(
            validate_address(
                NetworkPolicy::LoopbackDevelopment,
                "192.0.2.1".parse().unwrap()
            )
            .is_err()
        );
        assert!(
            validate_address(
                NetworkPolicy::PrivateDevice {
                    allow_loopback: true,
                    allow_link_local: true
                },
                "169.254.169.254".parse().unwrap()
            )
            .is_err()
        );
    }
}
