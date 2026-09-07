//! Request-owned async DNS. Neither the query nor its background transports use
//! getaddrinfo/spawn_blocking; every spawned DNS future belongs to one scope.
use super::{Error, MAX_RESOLVED_ADDRESSES};
#[cfg(test)]
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::{
    Resolver,
    config::LookupIpStrategy,
    net::runtime::{RuntimeProvider, Spawn, TokioRuntimeProvider},
};
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::task::JoinSet;

const MAX_DNS_TASKS: usize = 32;
const MAX_NAME_SERVERS: usize = 8;

#[derive(Clone, Default)]
pub(super) enum Settings {
    #[default]
    System,
    #[cfg(test)]
    Explicit(ResolverConfig),
}

#[derive(Default)]
struct State {
    tasks: JoinSet<()>,
    closed: bool,
    exhausted: bool,
}

#[derive(Clone, Default)]
pub(super) struct Tasks(Arc<Mutex<State>>);
impl Spawn for Tasks {
    fn spawn_bg(&mut self, future: impl Future<Output = ()> + Send + 'static) {
        let mut state = self.0.lock().unwrap_or_else(|error| error.into_inner());
        while state.tasks.try_join_next().is_some() {}
        if state.closed {
            return;
        }
        if state.tasks.len() >= MAX_DNS_TASKS {
            state.exhausted = true;
            state.closed = true;
            state.tasks.abort_all();
            return;
        }
        state.tasks.spawn(future);
    }
}

#[derive(Default)]
pub(super) struct Scope(Tasks);
impl Scope {
    pub(super) async fn finish(&self) {
        let mut tasks = {
            let mut state = self.0.0.lock().unwrap_or_else(|error| error.into_inner());
            state.closed = true;
            std::mem::take(&mut state.tasks)
        };
        tasks.shutdown().await;
    }

    pub(super) async fn resolve(
        &self,
        settings: &Settings,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<Vec<SocketAddr>, Error> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let provider = Provider {
            tasks: self.0.clone(),
            io: TokioRuntimeProvider::default(),
        };
        let (config, options) = match settings {
            #[cfg(any(unix, windows))]
            Settings::System => {
                hickory_resolver::system_conf::read_system_conf().map_err(|_| Error::Resolve)?
            }
            #[cfg(not(any(unix, windows)))]
            Settings::System => return Err(Error::Resolve),
            #[cfg(test)]
            Settings::Explicit(config) => (config.clone(), Default::default()),
        };
        // No hard-coded public resolver fallback. Local system configuration and
        // hosts are consumed, but no NSS/mDNS/plugin compatibility path exists.
        if config.name_servers().is_empty() {
            return Err(Error::ResolveEmpty);
        }
        if config.name_servers().len() > MAX_NAME_SERVERS {
            return Err(Error::ResolveTooLarge);
        }
        let mut builder = Resolver::builder_with_config(config, provider);
        *builder.options_mut() = options;
        let options = builder.options_mut();
        options.timeout = timeout;
        options.attempts = 1;
        options.num_concurrent_reqs = 2;
        options.max_active_requests = 16;
        options.cache_size = 0;
        options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        options.preserve_intermediates = false;
        #[cfg(test)]
        if matches!(settings, Settings::Explicit(_)) {
            options.use_hosts_file = hickory_resolver::config::ResolveHosts::Never;
        }
        let resolver = builder.build().map_err(|_| Error::Resolve)?;
        let lookup = resolver.lookup_ip(host).await.map_err(|_| Error::Resolve)?;
        let exhausted = self
            .0
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .exhausted;
        if exhausted {
            return Err(Error::ResolveTooLarge);
        }
        let addresses = lookup
            .iter()
            .take(MAX_RESOLVED_ADDRESSES + 1)
            .map(|ip| SocketAddr::new(ip, port))
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(Error::ResolveEmpty);
        }
        if addresses.len() > MAX_RESOLVED_ADDRESSES {
            return Err(Error::ResolveTooLarge);
        }
        Ok(addresses)
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        let mut state = self.0.0.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        state.tasks.abort_all();
    }
}

#[derive(Clone)]
struct Provider {
    tasks: Tasks,
    io: TokioRuntimeProvider,
}
impl RuntimeProvider for Provider {
    type Handle = Tasks;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = <TokioRuntimeProvider as RuntimeProvider>::Udp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;
    fn create_handle(&self) -> Tasks {
        self.tasks.clone()
    }
    fn connect_tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        self.io.connect_tcp(server, bind, timeout)
    }
    fn bind_udp(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        self.io.bind_udp(local, server)
    }
}

/// reqwest may only connect to the override addresses installed by execute.
/// A missed override must fail, never silently invoke its default OS resolver.
pub(super) struct BoundOnly;
impl reqwest::dns::Resolve for BoundOnly {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async { Err("unbound DNS lookup rejected".into()) })
    }
}

#[cfg(test)]
mod tests;
