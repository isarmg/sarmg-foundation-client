use super::*;
use crate::{NetworkPolicy, ResponseBudget, SecureHttpClient, TlsConfig, header};
use hickory_resolver::{
    config::NameServerConfig,
    proto::{
        op::{Message, ResponseCode},
        rr::{
            RData, Record, RecordType,
            rdata::{A, AAAA},
        },
    },
};
use std::{
    io::{Read, Write},
    net::{TcpListener, UdpSocket},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    thread::JoinHandle,
    time::Instant,
};

#[derive(Clone)]
enum Answer {
    Addresses(Vec<IpAddr>),
    Missing,
    Silent,
    Malformed,
    Truncated(Vec<IpAddr>),
}

// All DNS and HTTP peers bind ephemeral loopback ports. No external resolver,
// global resolver configuration, proxy environment or production API override.
struct Peer {
    config: ResolverConfig,
    stop: Arc<AtomicBool>,
    queries: Arc<AtomicUsize>,
    tcp_queries: Arc<AtomicUsize>,
    workers: Vec<JoinHandle<()>>,
}
impl Peer {
    fn new(answer: Answer) -> Self {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind(address).unwrap();
        udp.set_nonblocking(true).unwrap();
        tcp.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let queries = Arc::new(AtomicUsize::new(0));
        let tcp_queries = Arc::new(AtomicUsize::new(0));
        let mut nameserver = NameServerConfig::udp_and_tcp(address.ip());
        for connection in &mut nameserver.connections {
            connection.port = address.port();
        }
        let mut workers = Vec::new();
        {
            let (stop, queries, answer) = (stop.clone(), queries.clone(), answer.clone());
            workers.push(std::thread::spawn(move || {
                let end = Instant::now() + Duration::from_secs(10);
                let mut buffer = [0; 4096];
                while !stop.load(Ordering::SeqCst) && Instant::now() < end {
                    match udp.recv_from(&mut buffer) {
                        Ok((count, sender)) => {
                            queries.fetch_add(1, Ordering::SeqCst);
                            if let Some(response) = reply(&buffer[..count], &answer, false) {
                                udp.send_to(&response, sender).unwrap();
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("DNS fixture receive: {error}"),
                    }
                }
            }));
        }
        {
            let (stop, queries) = (stop.clone(), tcp_queries.clone());
            workers.push(std::thread::spawn(move || {
                let end = Instant::now() + Duration::from_secs(10);
                while !stop.load(Ordering::SeqCst) && Instant::now() < end {
                    match tcp.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            stream
                                .set_write_timeout(Some(Duration::from_millis(100)))
                                .unwrap();
                            while !stop.load(Ordering::SeqCst) && Instant::now() < end {
                                let mut length = [0; 2];
                                if stream.read_exact(&mut length).is_err() {
                                    break;
                                }
                                let length = usize::from(u16::from_be_bytes(length));
                                assert!(length <= 4096);
                                let mut buffer = vec![0; length];
                                if stream.read_exact(&mut buffer).is_err() {
                                    break;
                                }
                                queries.fetch_add(1, Ordering::SeqCst);
                                if let Some(response) = reply(&buffer, &answer, true)
                                    && (stream
                                        .write_all(&(response.len() as u16).to_be_bytes())
                                        .is_err()
                                        || stream.write_all(&response).is_err())
                                {
                                    break;
                                }
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("DNS fixture accept: {error}"),
                    }
                }
            }));
        }
        Self {
            config: ResolverConfig::from_name_servers(vec![nameserver]),
            stop,
            queries,
            tcp_queries,
            workers,
        }
    }

    fn client(&self, timeout: Duration) -> SecureHttpClient {
        let mut client = SecureHttpClient::new(
            timeout,
            ResponseBudget {
                max_header_bytes: 4096,
                max_body_bytes: 4096,
            },
            TlsConfig::default(),
            "dns-test".into(),
        )
        .unwrap();
        Arc::get_mut(&mut client.configuration).unwrap().dns =
            Settings::Explicit(self.config.clone());
        client
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for worker in self.workers.drain(..) {
            worker.join().unwrap();
        }
    }
}

fn reply(bytes: &[u8], answer: &Answer, tcp: bool) -> Option<Vec<u8>> {
    if matches!(answer, Answer::Silent) {
        return None;
    }
    if matches!(answer, Answer::Malformed) {
        return Some(bytes[..4].to_vec());
    }
    let query = Message::from_vec(bytes).unwrap();
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.authoritative = true;
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries = query.queries.clone();
    match answer {
        Answer::Missing => response.metadata.response_code = ResponseCode::NXDomain,
        Answer::Truncated(_) if !tcp => response.metadata.truncation = true,
        Answer::Addresses(addresses) | Answer::Truncated(addresses) => {
            for query in &query.queries {
                for ip in addresses {
                    let data = match (ip, query.query_type()) {
                        (IpAddr::V4(ip), RecordType::A) => RData::A(A(*ip)),
                        (IpAddr::V6(ip), RecordType::AAAA) => RData::AAAA(AAAA(*ip)),
                        _ => continue,
                    };
                    response.add_answer(Record::from_rdata(query.name().clone(), 60, data));
                }
            }
        }
        Answer::Silent | Answer::Malformed => unreachable!(),
    }
    Some(response.to_vec().unwrap())
}

#[tokio::test]
async fn async_dns_answers_and_tcp_fallback_have_owned_cleanup() {
    let addresses = vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()];
    for answer in [
        Answer::Addresses(addresses.clone()),
        Answer::Truncated(addresses.clone()),
    ] {
        let tcp = matches!(answer, Answer::Truncated(_));
        let peer = Peer::new(answer);
        let scope = Scope::default();
        let result = scope
            .resolve(
                &Settings::Explicit(peer.config.clone()),
                "fixture.test.",
                443,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert_eq!(result.len(), 2);
        for address in &addresses {
            assert!(result.contains(&SocketAddr::new(*address, 443)));
        }
        scope.finish().await;
        let state = scope.0.0.lock().unwrap();
        assert!(state.closed && state.tasks.is_empty());
        assert!(peer.queries.load(Ordering::SeqCst) >= 2);
        if tcp {
            assert!(peer.tcp_queries.load(Ordering::SeqCst) >= 2);
        }
    }
}

#[tokio::test]
async fn bound_dns_preserves_http_host_and_rejects_every_unsafe_answer() {
    let policy = NetworkPolicy::PrivateDevice {
        allow_loopback: true,
        allow_link_local: false,
    };
    for addresses in [
        vec!["127.0.0.1".parse().unwrap()],
        vec![
            "127.0.0.1".parse().unwrap(),
            "169.254.169.254".parse().unwrap(),
        ],
        vec![
            "127.0.0.1".parse().unwrap(),
            "::ffff:169.254.169.254".parse().unwrap(),
        ],
        (1..=17)
            .map(|n| IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, n)))
            .collect(),
    ] {
        let expected_success = addresses.len() == 1;
        let overflow = addresses.len() > MAX_RESOLVED_ADDRESSES;
        let peer = Peer::new(Answer::Addresses(addresses));
        let http = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let host = format!("fixture.test:{}", http.local_addr().unwrap().port());
        let request = reqwest::Request::new(
            reqwest::Method::GET,
            format!("http://{host}/health/live").parse().unwrap(),
        );
        let client = peer.client(Duration::from_secs(2));
        if expected_success {
            let server = async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let (mut stream, _) = http.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let mut buffer = [0; 1024];
                    let n = stream.read(&mut buffer).await.unwrap();
                    assert!(n > 0 && request.len() + n <= 4096);
                    request.extend_from_slice(&buffer[..n]);
                }
                assert!(
                    String::from_utf8(request)
                        .unwrap()
                        .to_lowercase()
                        .contains(&format!("host: {host}\r\n"))
                );
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await
                    .unwrap();
            };
            let (result, _) = tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(client.execute(policy, request), server)
            })
            .await
            .unwrap();
            assert_eq!(result.unwrap().body, b"ok");
        } else {
            let result = client.execute(policy, request).await;
            if overflow {
                assert!(matches!(result, Err(Error::ResolveTooLarge)), "{result:?}");
            } else {
                assert!(
                    matches!(result, Err(Error::ForbiddenAddress(_))),
                    "{result:?}"
                );
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(30), http.accept())
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test]
async fn missing_and_silent_dns_fail_without_http_or_resolver_fallback() {
    let peer = Peer::new(Answer::Missing);
    let result = peer
        .client(Duration::from_secs(1))
        .get_client_blocking("https://fixture.test/", header::HeaderMap::new());
    assert!(matches!(result, Err(Error::Resolve)), "{result:?}");
    let peer = Peer::new(Answer::Silent);
    let start = Instant::now();
    let result = peer
        .client(Duration::from_millis(200))
        .post_client(
            "https://fixture.test/",
            header::HeaderMap::new(),
            Vec::new(),
        )
        .await;
    assert!(matches!(result, Err(Error::Timeout)), "{result:?}");
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(peer.queries.load(Ordering::SeqCst) > 0);
    use reqwest::dns::Resolve;
    assert!(
        BoundOnly
            .resolve("fixture.test".parse().unwrap())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn malformed_dns_is_bounded_and_dropped_lookup_aborts_transports() {
    let peer = Peer::new(Answer::Malformed);
    let start = Instant::now();
    let result = peer
        .client(Duration::from_millis(200))
        .post_client(
            "https://fixture.test/",
            header::HeaderMap::new(),
            Vec::new(),
        )
        .await;
    assert!(
        matches!(result, Err(Error::Resolve | Error::Timeout)),
        "{result:?}"
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(peer.queries.load(Ordering::SeqCst) > 0);

    let peer = Peer::new(Answer::Silent);
    let scope = Scope::default();
    let tasks = scope.0.clone();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            scope.resolve(
                &Settings::Explicit(peer.config.clone()),
                "fixture.test.",
                443,
                Duration::from_secs(5)
            )
        )
        .await
        .is_err()
    );
    assert!(peer.queries.load(Ordering::SeqCst) > 0);
    drop(scope);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            {
                let mut state = tasks.0.lock().unwrap();
                assert!(state.closed);
                while state.tasks.try_join_next().is_some() {}
                if state.tasks.is_empty() {
                    break;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let queries = peer.queries.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(peer.queries.load(Ordering::SeqCst), queries);
}

#[tokio::test]
async fn literal_ips_skip_dns_and_invalid_nameserver_budgets_fail_closed() {
    let scope = Scope::default();
    let empty = Settings::Explicit(ResolverConfig::from_name_servers(Vec::new()));
    for ip in ["127.0.0.1", "::1"] {
        assert_eq!(
            scope
                .resolve(&empty, ip, 443, Duration::from_secs(1))
                .await
                .unwrap(),
            vec![SocketAddr::new(ip.parse().unwrap(), 443)]
        );
    }
    assert!(matches!(
        scope
            .resolve(&empty, "fixture.test.", 443, Duration::from_secs(1))
            .await,
        Err(Error::ResolveEmpty)
    ));
    let servers = Settings::Explicit(ResolverConfig::from_name_servers(vec![
        NameServerConfig::udp(
            "127.0.0.1".parse().unwrap()
        );
        MAX_NAME_SERVERS + 1
    ]));
    assert!(matches!(
        scope
            .resolve(&servers, "fixture.test.", 443, Duration::from_secs(1))
            .await,
        Err(Error::ResolveTooLarge)
    ));
    scope.finish().await;
}

struct Dropped(Arc<AtomicUsize>);
impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn tracked(counter: &Arc<AtomicUsize>) -> impl Future<Output = ()> + Send + 'static {
    let guard = Dropped(counter.clone());
    async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    }
}

#[tokio::test]
async fn dns_scope_joins_aborts_caps_and_rejects_late_spawns() {
    let counter = Arc::new(AtomicUsize::new(0));
    let scope = Scope::default();
    let mut handle = scope.0.clone();
    handle.spawn_bg(tracked(&counter));
    scope.finish().await;
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    handle.spawn_bg(tracked(&counter));
    assert_eq!(counter.load(Ordering::SeqCst), 2);
    let scope = Scope::default();
    let mut handle = scope.0.clone();
    handle.spawn_bg(tracked(&counter));
    drop(scope);
    tokio::time::timeout(Duration::from_secs(1), async {
        while counter.load(Ordering::SeqCst) != 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(handle.0.lock().unwrap().closed);
    let scope = Scope::default();
    let mut handle = scope.0.clone();
    for _ in 0..=MAX_DNS_TASKS {
        handle.spawn_bg(tracked(&counter));
    }
    assert!(handle.0.lock().unwrap().exhausted);
    scope.finish().await;
    assert_eq!(counter.load(Ordering::SeqCst), 3 + MAX_DNS_TASKS + 1);
}

#[test]
fn silent_dns_synchronous_runtime_exits_within_watchdog() {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "dns::tests::silent_dns_child",
            "--ignored",
            "--nocapture",
        ])
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("synchronous DNS cancellation/runtime teardown exceeded watchdog");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "executed by watchdog parent"]
fn silent_dns_child() {
    let peer = Peer::new(Answer::Silent);
    let client = peer.client(Duration::from_millis(200));
    for _ in 0..3 {
        let before = peer.queries.load(Ordering::SeqCst);
        let start = Instant::now();
        let result = client.get_client_blocking("https://fixture.test/", header::HeaderMap::new());
        assert!(matches!(result, Err(Error::Timeout)), "{result:?}");
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(peer.queries.load(Ordering::SeqCst) > before);
    }
    let queries = peer.queries.load(Ordering::SeqCst);
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(peer.queries.load(Ordering::SeqCst), queries);
}
