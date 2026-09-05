# Agent secure HTTP

`sarmg-agent-secure-http` owns client construction and bounded execution, using
reqwest 0.13 with rustls on Linux/other non-native targets and native TLS on
Windows/macOS. No old reqwest adapter or raw-response execution API remains.

Products supply their user agent, total request timeout, bounded response budget
and parsed `TlsConfig`. Products still choose protected TLS input paths and
business DTOs; Host reads those files through Foundation filesystem handles and
the 1 MiB TLS input ceiling. `TlsConfig` and the transport hide secrets in Debug.

`SecureHttpClient::execute` accepts one of the three closed network policies and
a finite request. `post_agent` selects PublicHttps for HTTPS, or the loopback-only
LoopbackDevelopment policy for debug builds. Release builds reject that HTTP
policy, including localhost. PrivateDevice is not selected by Agent delivery.

Execution owns:

- A single total deadline spanning DNS, client construction, connection, response
  headers and body completion; connect timeout is at most 10 seconds and never
  exceeds the total timeout.
- At most 16 resolved addresses, validating every result and pinning those exact
  results for the connection. IPv4-mapped IPv6 is normalized before metadata,
  loopback, unspecified, multicast and link-local policy checks.
- Request-owned asynchronous DNS transports (Hickory 0.26.2), with at most eight
  configured nameservers, 16 active DNS requests and 32 owned background tasks.
  Both A and AAAA results are checked; UDP truncation may use TCP under the same
  deadline. IP literals bypass resolver configuration. No cross-request DNS cache
  or default public resolver is installed. Missing configuration fails closed.
  The HTTP backend rejects any lookup not covered by the validated address pin;
  it cannot fall back to an OS resolver after validation.
- No redirects or environment/system proxies. A proxy would bypass the validated
  destination binding; there is no unvalidated proxy escape hatch.
- Sensitive Authorization/Proxy-Authorization/Cookie request headers; transport
  errors retain neither backend error chains nor URLs. Response Debug contains
  status/body length, not headers, cookies or response data.
- Finite in-memory requests up to 1 MiB; streamed/unbounded bodies are rejected.
  Response limits cannot exceed 64 KiB headers and 1 MiB body. Products can choose
  smaller budgets. Header aggregate and declared body size are checked before
  cloning headers/collecting the body; chunked bodies are checked incrementally.
  HTTP/2 also receives the header-list limit. These are accepted-response limits,
  not a claim that the HTTP parser, resolver or TLS library has zero intermediate
  allocations or a hard process-wide memory limit.

The returned `BoundedResponse` is already fully read and contains status, headers
and a bounded body. The factory does not classify business ACKs, retry, mutate
credentials or enqueue reports. There is no public raw Client/Response bypass.
Current execution rebuilds a pinned client per request; pooling and explicit
validated proxy support are not provided by this implementation.

Host Report/OTLP, create/poll/activate pairing and the Windows tray's public health
probe all use this factory. `get_agent_blocking` adapts synchronous callers with
an owned scoped worker/runtime, including callers already inside Tokio. The
worker is joined, not detached; it executes the same policy and bounded GET path.
DNS queries no longer call OS `getaddrinfo` or Tokio's blocking resolver pool.
Successful, failed and timed-out executions abort and join the request's DNS task
set before returning. Dropping the execution future aborts that set; drop cannot
asynchronously join it. A closed scope rejects late task spawns, and exceeding
the task ceiling closes the scope rather than creating more work.

System resolver configuration and hosts input are still local synchronous reads;
OS scheduling, configuration I/O, TLS construction and CPU work are not hard
real-time operations. The network deadline and owned DNS cleanup are not an
unconditional wall-clock guarantee under arbitrary system failure. NSS plugins,
mDNS and OS-specific split-DNS routing are not emulated. Android's system-config
backend requires an initialized application context; that host integration and
native platform acceptance remain required before mobile adoption. Resolver
configuration comes from the platform, not a product-supplied HTTP builder or
production test override. See the pinned upstream
[resolver source](https://docs.rs/crate/hickory-resolver/0.26.2/source/src/resolver.rs)
and its system configuration backends.

Host no longer depends directly on reqwest. It consumes Foundation's URL, status,
header and TLS types without exposing raw clients. Consumers declaring
https-delivery cannot add a direct reqwest dependency, including aliases,
workspace-inherited dependencies and target-specific declarations. Gates also
reject local transport/budget type definitions and response reader loops; they
are not a proof against arbitrary custom socket code or every HTTP library.
Other client adoption, release artifact execution and Windows/macOS/Android/iOS
native verification remain separate acceptance requirements.

Linux evidence includes real HTTP header/body/redirect/deadline tests and Host
real TLS 1.2/1.3 / mTLS against an independent OpenSSL peer. It does not substitute
for native backends, real Collector or deployment acceptance.
The actual Linux release-profile admission regression also executes synchronous
GET and asynchronous POST and verifies DevelopmentOnly for loopback HTTP. It is
not an acceptance test for the complete Host release binary or installer.
Controlled loopback DNS tests cover A/AAAA answers, TCP fallback, NXDOMAIN,
malformed and silent responses, mixed metadata/mapped-address rejection, the
address and nameserver ceilings, original HTTP Host preservation, scope drop,
abort/join and late-spawn rejection. A watchdog child repeats synchronous calls
through fresh runtimes, verifies timeout return without any DNS response and
checks that no further queries arrive after completion. CI also runs the DNS
suite and loopback admission regression with the real optimized release profile.
