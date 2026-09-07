use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread::JoinHandle,
    time::Instant,
};

fn client(body_limit: usize, header_limit: usize, timeout: Duration) -> SecureHttpClient {
    SecureHttpClient::new(
        timeout,
        ResponseBudget {
            max_header_bytes: header_limit,
            max_body_bytes: body_limit,
        },
        TlsConfig::default(),
        "foundation-test".into(),
    )
    .unwrap()
}

#[test]
fn loopback_http_tracks_build_mode() {
    let url = Url::parse("http://127.0.0.1:8080/").unwrap();
    assert_eq!(client_network_policy(&url).is_ok(), cfg!(debug_assertions));
    assert_eq!(
        validate_url_structure(NetworkPolicy::LoopbackDevelopment, &url).is_ok(),
        cfg!(debug_assertions)
    );
    assert!(client_network_policy(&Url::parse("https://127.0.0.1:8080/").unwrap()).is_ok());
    assert!(client_network_policy(&Url::parse("http://192.0.2.1/").unwrap()).is_err());
    #[cfg(not(debug_assertions))]
    {
        let transport = client(1024, 1024, Duration::from_secs(1));
        assert!(matches!(
            transport.get_client_blocking(url.as_str(), header::HeaderMap::new()),
            Err(Error::DevelopmentOnly)
        ));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        assert!(matches!(
            runtime.block_on(transport.post_client(
                url.as_str(),
                header::HeaderMap::new(),
                Vec::new()
            )),
            Err(Error::DevelopmentOnly)
        ));
    }
}

fn peer(
    response: Vec<u8>,
    body_release: Option<std::sync::mpsc::Receiver<()>>,
) -> (String, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let worker = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("peer accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let mut chunk = [0; 4096];
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0 && request.len() + count <= 16384);
            request.extend_from_slice(&chunk[..count]);
        }
        // Delay only the body: receiving headers must not reset the total clock.
        let end = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let _ = stream.write_all(&response[..end]);
        if let Some(release) = body_release {
            release.recv_timeout(Duration::from_secs(6)).unwrap();
        }
        let _ = stream.write_all(&response[end..]);
        request
    });
    (url, worker)
}

#[tokio::test]
async fn bounded_execution_checks_headers_content_length_and_chunked_body() {
    for (response, body_budget, header_budget, accepted) in [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata".to_vec(),
            4,
            1024,
            true,
        ),
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ndata!".to_vec(),
            4,
            1024,
            false,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ndata\r\n0\r\n\r\n".to_vec(),
            4,
            1024,
            true,
        ),
        (
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\ndata!\r\n0\r\n\r\n"
                .to_vec(),
            4,
            1024,
            false,
        ),
        (
            format!(
                "HTTP/1.1 200 OK\r\nX-Oversized: {}\r\nContent-Length: 0\r\n\r\n",
                "x".repeat(2048)
            )
            .into_bytes(),
            4,
            1024,
            false,
        ),
    ] {
        let (url, worker) = peer(response, None);
        let result = client(body_budget, header_budget, Duration::from_secs(2))
            .post_client(&url, header::HeaderMap::new(), Vec::new())
            .await;
        worker.join().unwrap();
        if accepted {
            assert_eq!(result.unwrap().body, b"data");
        } else {
            assert!(matches!(result, Err(Error::ResponseTooLarge)), "{result:?}");
        }
    }
}

#[tokio::test]
async fn redirects_do_not_replay_requests_or_credentials() {
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let (url, worker) = peer(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{}/secret\r\nContent-Length: 0\r\n\r\n", trap.local_addr().unwrap()).into_bytes(), None);
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        header::HeaderValue::from_static("Bearer fixture-secret"),
    );
    let response = client(1024, 1024, Duration::from_secs(2))
        .post_client(&url, headers, Vec::new())
        .await
        .unwrap();
    let request = worker.join().unwrap();
    assert!(
        String::from_utf8(request)
            .unwrap()
            .to_lowercase()
            .contains("authorization: bearer fixture-secret")
    );
    assert_eq!(response.status, reqwest::StatusCode::TEMPORARY_REDIRECT);
    let redacted = BoundedResponse {
        status: response.status,
        headers: [(
            header::SET_COOKIE,
            header::HeaderValue::from_static("fixture-secret"),
        )]
        .into_iter()
        .collect(),
        body: b"fixture-secret".to_vec(),
    };
    assert!(!format!("{redacted:?}").contains("fixture-secret"));
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn blocking_adapter_can_run_inside_tokio_and_uses_the_bounded_get_path() {
    let (url, worker) = peer(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata".to_vec(),
        None,
    );
    let result = client(4, 1024, Duration::from_secs(3))
        .get_client_blocking(&url, header::HeaderMap::new())
        .unwrap();
    assert_eq!(result.body, b"data");
    assert!(worker.join().unwrap().starts_with(b"GET / HTTP/1.1\r\n"));
    let (url, worker) = peer(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ndata!".to_vec(),
        None,
    );
    let result =
        client(4, 1024, Duration::from_secs(3)).get_client_blocking(&url, header::HeaderMap::new());
    worker.join().unwrap();
    assert!(matches!(result, Err(Error::ResponseTooLarge)));
}

#[tokio::test]
async fn total_timeout_includes_body_reading_and_errors_do_not_keep_sources() {
    let transport = client(4, 1024, Duration::from_secs(2));
    let (release, body_release) = std::sync::mpsc::channel();
    let (url, worker) = peer(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata".to_vec(),
        Some(body_release),
    );
    // The peer cannot finish the body until AFTER the request has failed.
    // This proves the body is inside the deadline without a scheduler-sensitive
    // 350 ms wall-clock assertion (which included TLS constructor startup).
    let result = tokio::time::timeout(
        Duration::from_secs(5),
        transport.post_client(&url, header::HeaderMap::new(), Vec::new()),
    )
    .await;
    release.send(()).unwrap();
    let request = worker.join().unwrap();
    assert!(request.starts_with(b"POST / HTTP/1.1"));
    let error = result
        .expect("outer test deadline, shared deadline did not fire")
        .unwrap_err();
    assert!(matches!(error, Error::Timeout));
    assert!(std::error::Error::source(&error).is_none());
    assert!(!format!("{error:?}/{error}").contains(&url));
}

#[tokio::test]
async fn rejected_requests_do_not_connect_and_mapped_addresses_cannot_bypass_policy() {
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let url = format!("http://{}/", trap.local_addr().unwrap());
    let transport = client(1024, 1024, Duration::from_secs(1));
    assert!(matches!(
        transport
            .post_client(
                &url,
                header::HeaderMap::new(),
                vec![0; MAX_REQUEST_BYTES + 1]
            )
            .await,
        Err(Error::RequestTooLarge)
    ));
    for url in [
        "http://192.0.2.1/",
        "https://169.254.169.254/",
        "https://[::ffff:169.254.169.254]/",
        "https://user:secret@example.com/",
    ] {
        assert!(
            transport
                .post_client(url, header::HeaderMap::new(), Vec::new())
                .await
                .is_err()
        );
    }
    assert_eq!(
        trap.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(
        validate_address(
            NetworkPolicy::LoopbackDevelopment,
            "::ffff:127.0.0.1".parse().unwrap()
        )
        .is_ok()
    );
    assert!(
        validate_address(
            NetworkPolicy::LoopbackDevelopment,
            "::ffff:192.0.2.1".parse().unwrap()
        )
        .is_err()
    );
    assert!(
        SecureHttpClient::new(
            Duration::ZERO,
            ResponseBudget::default(),
            TlsConfig::default(),
            "test".into()
        )
        .is_err()
    );
}
