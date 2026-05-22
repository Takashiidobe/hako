use std::io::{self, Write};
use std::net::Ipv4Addr;

use crate::deps::DirFs;

const MAX_HTTP_HEADER_BYTES: usize = 16 * 1024;

pub fn run(
    out: &mut impl Write,
    fs: impl DirFs + Clone + Send + Sync + 'static,
    args: &[String],
) -> io::Result<()> {
    let (dir, port, tls) = parse_args(args)?;
    let scheme = if tls { "https" } else { "http" };
    writeln!(out, "Serving {dir}")?;
    writeln!(out, "  {scheme}://localhost:{port}")?;
    for ip in local_addrs() {
        writeln!(out, "  {scheme}://{ip}:{port}")?;
    }
    writeln!(out)?;
    serve(fs, dir, port, tls)
}

fn parse_args(args: &[String]) -> io::Result<(String, u16, bool)> {
    let tls = args.iter().any(|a| a == "--tls");
    let rest: Vec<&String> = args.iter().filter(|a| *a != "--tls").collect();
    match rest.as_slice() {
        [dir] => Ok(((*dir).clone(), if tls { 8443 } else { 8080 }, tls)),
        [dir, port] => {
            let p = port
                .parse::<u16>()
                .map_err(|_| io::Error::other("invalid port"))?;
            Ok(((*dir).clone(), p, tls))
        }
        _ => Err(io::Error::other("usage: httpserver <dir> [port] [--tls]")),
    }
}

fn serve(
    fs: impl DirFs + Clone + Send + Sync + 'static,
    dir: String,
    port: u16,
    tls: bool,
) -> io::Result<()> {
    if tls {
        return serve_tls(fs, dir, port);
    }
    serve_plain(fs, dir, port)
}

// ----- Plain HTTP -----------------------------------------------------------

#[cfg(feature = "smol-runtime")]
fn serve_plain(
    fs: impl DirFs + Clone + Send + Sync + 'static,
    dir: String,
    port: u16,
) -> io::Result<()> {
    smol::block_on(async move {
        let listener = smol::net::TcpListener::bind(("0.0.0.0", port)).await?;
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let fs = fs.clone();
                    let dir = dir.clone();
                    smol::spawn(async move {
                        let _ = serve_connection_async(&fs, &dir, stream).await;
                    })
                    .detach();
                }
                Err(e) => eprintln!("connection error: {e}"),
            }
        }
    })
}

#[cfg(not(feature = "smol-runtime"))]
fn serve_plain(
    fs: impl DirFs + Clone + Send + Sync + 'static,
    dir: String,
    port: u16,
) -> io::Result<()> {
    use std::net::TcpListener;

    let listener = TcpListener::bind(("0.0.0.0", port))?;
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let fs = fs.clone();
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let _ = serve_connection_sync(&fs, &dir, s);
                });
            }
            Err(e) => eprintln!("connection error: {e}"),
        }
    }
    Ok(())
}

// ----- HTTPS / TLS ----------------------------------------------------------

#[cfg(feature = "embedded-tls")]
fn serve_tls(
    fs: impl DirFs + Clone + Send + Sync + 'static,
    dir: String,
    port: u16,
) -> io::Result<()> {
    use embedded_tls::{Aes128GcmSha256, Certificate, TlsConfig};

    let (cert_der, key_der) = generate_self_signed_cert()?;
    // Leak cert, key, and config — the server runs for the process lifetime.
    let cert_der: &'static [u8] = Box::leak(cert_der.into_boxed_slice());
    let key_der: &'static [u8] = Box::leak(key_der.into_boxed_slice());
    let config: &'static TlsConfig<'static> = Box::leak(Box::new(
        TlsConfig::new()
            .with_cert(Certificate::X509(cert_der))
            .with_priv_key(key_der),
    ));

    serve_tls_inner::<Aes128GcmSha256>(fs, dir, port, config)
}

#[cfg(not(feature = "embedded-tls"))]
fn serve_tls(
    _fs: impl DirFs + Clone + Send + Sync + 'static,
    _dir: String,
    _port: u16,
) -> io::Result<()> {
    Err(io::Error::other(
        "--tls requires the embedded-tls feature (recompile with it enabled)",
    ))
}

#[cfg(feature = "embedded-tls")]
fn generate_self_signed_cert() -> io::Result<(Vec<u8>, Vec<u8>)> {
    Ok((
        include_bytes!(concat!(env!("OUT_DIR"), "/httpserver-cert.der")).to_vec(),
        include_bytes!(concat!(env!("OUT_DIR"), "/httpserver-key.der")).to_vec(),
    ))
}

#[cfg(all(feature = "embedded-tls", feature = "smol-runtime"))]
fn serve_tls_inner<CS>(
    fs: impl DirFs + Clone + Send + Sync + 'static,
    dir: String,
    port: u16,
    config: &'static embedded_tls::TlsConfig<'static>,
) -> io::Result<()>
where
    CS: embedded_tls::TlsCipherSuite + 'static,
{
    // embedded_tls types are !Send, so smol::spawn (which requires Send) can't be used.
    // smol::block_on may also require Send in its thread-pool implementation, so we use
    // futures_lite::future::block_on instead — it runs the future inline on the current
    // thread. LocalExecutor gives cooperative I/O concurrency without requiring Send.
    use std::rc::Rc;
    futures_lite::future::block_on(async move {
        let ex = Rc::new(smol::LocalExecutor::new());
        let listener = smol::net::TcpListener::bind(("0.0.0.0", port)).await?;
        let ex2 = Rc::clone(&ex);
        ex.run(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let fs = fs.clone();
                        let dir = dir.clone();
                        ex2.spawn(async move {
                            let _ =
                                serve_tls_connection_async::<CS>(&fs, &dir, stream, config).await;
                        })
                        .detach();
                    }
                    Err(e) => eprintln!("TLS connection error: {e}"),
                }
            }
        })
        .await
    })
}

#[cfg(all(feature = "embedded-tls", not(feature = "smol-runtime")))]
fn serve_tls_inner<CS>(
    fs: impl DirFs + Clone + Send + Sync + 'static,
    dir: String,
    port: u16,
    config: &'static embedded_tls::TlsConfig<'static>,
) -> io::Result<()>
where
    CS: embedded_tls::TlsCipherSuite + 'static,
{
    use std::net::TcpListener;
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let fs = fs.clone();
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let _ = serve_tls_connection_sync::<CS>(&fs, &dir, s, config);
                });
            }
            Err(e) => eprintln!("TLS connection error: {e}"),
        }
    }
    Ok(())
}

#[cfg(all(feature = "embedded-tls", feature = "smol-runtime"))]
async fn serve_tls_connection_async<CS>(
    fs: &impl DirFs,
    root: &str,
    stream: smol::net::TcpStream,
    config: &embedded_tls::TlsConfig<'_>,
) -> io::Result<()>
where
    CS: embedded_tls::TlsCipherSuite + 'static,
{
    use embedded_io_adapters::futures_03::FromFutures;
    use embedded_tls::{AsyncTlsServerConnection, UnsecureProvider};
    use rand_core::OsRng;

    let mut read_buf = vec![0u8; 16384];
    let mut write_buf = vec![0u8; 16384];
    let wrapped = FromFutures::new(stream);
    let mut tls = AsyncTlsServerConnection::<_, CS>::new(wrapped, &mut read_buf, &mut write_buf);

    tls.accept(config, UnsecureProvider::new::<CS>(OsRng))
        .await
        .map_err(|e| io::Error::other(format!("TLS handshake: {e:?}")))?;

    let request_line = read_http_request_line_async(&mut tls).await?;
    let response = response_for_request(fs, root, &request_line);
    write_all_tls_async(&mut tls, &response.to_bytes()).await?;
    tls.flush()
        .await
        .map_err(|e| io::Error::other(format!("TLS flush: {e:?}")))
}

#[cfg(all(feature = "embedded-tls", not(feature = "smol-runtime")))]
fn serve_tls_connection_sync<CS>(
    fs: &impl DirFs,
    root: &str,
    stream: std::net::TcpStream,
    config: &embedded_tls::TlsConfig<'_>,
) -> io::Result<()>
where
    CS: embedded_tls::TlsCipherSuite + 'static,
{
    use embedded_io_adapters::std::FromStd;
    use embedded_tls::{TlsServerConnection, UnsecureProvider};
    use rand_core::OsRng;

    let mut read_buf = vec![0u8; 16384];
    let mut write_buf = vec![0u8; 16384];
    let wrapped = FromStd::new(stream);
    let mut tls = TlsServerConnection::<_, CS>::new(wrapped, &mut read_buf, &mut write_buf);

    tls.accept(config, UnsecureProvider::new::<CS>(OsRng))
        .map_err(|e| io::Error::other(format!("TLS handshake: {e:?}")))?;

    let request_line = read_http_request_line_sync(&mut tls)?;
    let response = response_for_request(fs, root, &request_line);
    write_all_tls_sync(&mut tls, &response.to_bytes())?;
    tls.flush()
        .map_err(|e| io::Error::other(format!("TLS flush: {e:?}")))
}

// Read bytes until the HTTP header block ends (\r\n\r\n), return the first line.
#[cfg(all(feature = "embedded-tls", feature = "smol-runtime"))]
async fn read_http_request_line_async<S, CS>(
    tls: &mut embedded_tls::AsyncTlsServerConnection<'_, S, CS>,
) -> io::Result<String>
where
    S: embedded_io_async::Read + embedded_io_async::Write,
    CS: embedded_tls::TlsCipherSuite + 'static,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = tls
            .read(&mut chunk)
            .await
            .map_err(|e| io::Error::other(format!("TLS read: {e:?}")))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HTTP_HEADER_BYTES {
            return Err(io::Error::other("HTTP request headers too large"));
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(first_line(&buf))
}

#[cfg(all(feature = "embedded-tls", not(feature = "smol-runtime")))]
fn read_http_request_line_sync<S, CS>(
    tls: &mut embedded_tls::TlsServerConnection<'_, S, CS>,
) -> io::Result<String>
where
    S: embedded_io::Read + embedded_io::Write,
    CS: embedded_tls::TlsCipherSuite + 'static,
{
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let n = tls
            .read(&mut chunk)
            .map_err(|e| io::Error::other(format!("TLS read: {e:?}")))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HTTP_HEADER_BYTES {
            return Err(io::Error::other("HTTP request headers too large"));
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(first_line(&buf))
}

fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .unwrap_or("")
        .to_string()
}

#[cfg(all(feature = "embedded-tls", feature = "smol-runtime"))]
async fn write_all_tls_async<S, CS>(
    tls: &mut embedded_tls::AsyncTlsServerConnection<'_, S, CS>,
    data: &[u8],
) -> io::Result<()>
where
    S: embedded_io_async::Read + embedded_io_async::Write,
    CS: embedded_tls::TlsCipherSuite + 'static,
{
    let mut pos = 0;
    while pos < data.len() {
        let n = tls
            .write(&data[pos..])
            .await
            .map_err(|e| io::Error::other(format!("TLS write: {e:?}")))?;
        if n == 0 {
            return Err(io::Error::other("TLS write stalled"));
        }
        pos += n;
    }
    Ok(())
}

#[cfg(all(feature = "embedded-tls", not(feature = "smol-runtime")))]
fn write_all_tls_sync<S, CS>(
    tls: &mut embedded_tls::TlsServerConnection<'_, S, CS>,
    data: &[u8],
) -> io::Result<()>
where
    S: embedded_io::Read + embedded_io::Write,
    CS: embedded_tls::TlsCipherSuite + 'static,
{
    let mut pos = 0;
    while pos < data.len() {
        let n = tls
            .write(&data[pos..])
            .map_err(|e| io::Error::other(format!("TLS write: {e:?}")))?;
        if n == 0 {
            return Err(io::Error::other("TLS write stalled"));
        }
        pos += n;
    }
    Ok(())
}

// ----- Plain connection handlers --------------------------------------------

#[cfg(feature = "smol-runtime")]
async fn serve_connection_async(
    fs: &impl DirFs,
    root: &str,
    mut stream: smol::net::TcpStream,
) -> io::Result<()> {
    use futures_lite::io::{AsyncWriteExt, BufReader};

    let mut reader = BufReader::new(&mut stream);
    let request_line = read_plain_request_line_async(&mut reader).await?;

    let response = response_for_request(fs, root, &request_line);
    stream.write_all(&response.to_bytes()).await
}

#[cfg(not(feature = "smol-runtime"))]
fn serve_connection_sync(
    fs: &impl DirFs,
    root: &str,
    stream: std::net::TcpStream,
) -> io::Result<()> {
    use std::io::BufReader;

    let mut reader = BufReader::new(&stream);
    let request_line = read_plain_request_line_sync(&mut reader)?;

    response_for_request(fs, root, &request_line).write_to(&stream)
}

// ----- Shared response logic ------------------------------------------------

fn check_header_size(total: &mut usize, n: usize) -> io::Result<()> {
    *total += n;
    if *total > MAX_HTTP_HEADER_BYTES {
        return Err(io::Error::other("HTTP request headers too large"));
    }
    Ok(())
}

#[cfg(any(not(feature = "smol-runtime"), test))]
fn read_plain_request_line_sync(reader: &mut impl std::io::BufRead) -> io::Result<String> {
    let mut total = 0;
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line)?;
    check_header_size(&mut total, n)?;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        check_header_size(&mut total, n)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    Ok(request_line)
}

#[cfg(feature = "smol-runtime")]
async fn read_plain_request_line_async<R>(reader: &mut R) -> io::Result<String>
where
    R: futures_lite::io::AsyncBufRead + Unpin,
{
    use futures_lite::io::AsyncBufReadExt;

    let mut total = 0;
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line).await?;
    check_header_size(&mut total, n)?;

    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await?;
        check_header_size(&mut total, n)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    Ok(request_line)
}

fn response_for_request(fs: &impl DirFs, root: &str, request_line: &str) -> Response {
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");
    match method {
        "GET" => handle_request(fs, root, path),
        "HEAD" => handle_request(fs, root, path).without_body(),
        "OPTIONS" => Response::options(),
        _ => Response::method_not_allowed(),
    }
}

const ALLOWED_METHODS: &str = "GET, HEAD, OPTIONS";

pub(crate) struct Response {
    pub status: u16,
    reason: &'static str,
    content_type: &'static str,
    pub body: Vec<u8>,
    location: Option<String>,
    allow: Option<&'static str>,
    send_body: bool,
}

impl Response {
    pub(crate) fn ok(body: Vec<u8>, content_type: &'static str) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type,
            body,
            location: None,
            allow: None,
            send_body: true,
        }
    }

    pub(crate) fn not_found() -> Self {
        Self {
            status: 404,
            reason: "Not Found",
            content_type: "text/plain",
            body: b"404 Not Found".to_vec(),
            location: None,
            allow: None,
            send_body: true,
        }
    }

    fn method_not_allowed() -> Self {
        Self {
            status: 405,
            reason: "Method Not Allowed",
            content_type: "text/plain",
            body: b"405 Method Not Allowed".to_vec(),
            location: None,
            allow: Some(ALLOWED_METHODS),
            send_body: true,
        }
    }

    fn options() -> Self {
        Self {
            status: 204,
            reason: "No Content",
            content_type: "text/plain",
            body: Vec::new(),
            location: None,
            allow: Some(ALLOWED_METHODS),
            send_body: true,
        }
    }

    fn redirect(location: &str) -> Self {
        let escaped = html_escape(location);
        Self {
            status: 301,
            reason: "Moved Permanently",
            content_type: "text/html",
            body: format!("<a href=\"{escaped}\">{escaped}</a>").into_bytes(),
            location: Some(location.to_string()),
            allow: None,
            send_body: true,
        }
    }

    fn without_body(mut self) -> Self {
        self.send_body = false;
        self
    }

    #[cfg(not(feature = "smol-runtime"))]
    fn write_to(&self, mut w: impl Write) -> io::Result<()> {
        w.write_all(&self.to_bytes())
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write!(out, "HTTP/1.1 {} {}\r\n", self.status, self.reason).unwrap();
        write!(out, "Content-Type: {}\r\n", self.content_type).unwrap();
        write!(out, "Content-Length: {}\r\n", self.body.len()).unwrap();
        if let Some(loc) = &self.location {
            write!(out, "Location: {loc}\r\n").unwrap();
        }
        if let Some(allow) = self.allow {
            write!(out, "Allow: {allow}\r\n").unwrap();
        }
        write!(out, "Connection: close\r\n\r\n").unwrap();
        if self.send_body {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

pub(crate) fn handle_request(fs: &impl DirFs, root: &str, request_path: &str) -> Response {
    let Some(path) = resolve_path(root, request_path) else {
        return Response::not_found();
    };
    let (url_path, query) = split_query(request_path);

    if fs.is_dir(&path) {
        if !url_path.ends_with('/') {
            let location = match query {
                Some(q) => format!("{url_path}/?{q}"),
                None => format!("{url_path}/"),
            };
            return Response::redirect(&location);
        }
        let index = format!("{path}/index.html");
        if let Ok(body) = fs.read_bytes(&index) {
            return Response::ok(body, "text/html");
        }
        return match fs.list_dir(&path) {
            Ok(entries) => Response::ok(
                dir_listing(request_path, &entries).into_bytes(),
                "text/html",
            ),
            Err(_) => Response::not_found(),
        };
    }

    match fs.read_bytes(&path) {
        Ok(body) => Response::ok(body, mime_type(&path)),
        Err(_) => Response::not_found(),
    }
}

fn resolve_path(root: &str, request_path: &str) -> Option<String> {
    let (path, _) = split_query(request_path);
    let segments: Vec<&str> = path
        .split('/')
        .filter(|s| !s.is_empty() && *s != "..")
        .collect();
    let root = root.trim_end_matches('/');
    if segments.is_empty() {
        Some(root.to_string())
    } else {
        Some(format!("{}/{}", root, segments.join("/")))
    }
}

fn split_query(path: &str) -> (&str, Option<&str>) {
    match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    }
}

fn mime_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "text/javascript",
        "json" => "application/json",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "txt" => "text/plain",
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

fn html_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn local_addrs() -> Vec<Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/fib_trie").unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let mut addrs = Vec::new();
    for w in lines.windows(2) {
        if w[1].contains("host LOCAL") {
            let candidate = w[0].split_whitespace().last().unwrap_or("");
            if let Ok(addr) = candidate.parse::<Ipv4Addr>()
                && !addr.is_loopback()
                && !addr.is_unspecified()
            {
                addrs.push(addr);
            }
        }
    }
    addrs.sort();
    addrs.dedup();
    addrs
}

#[cfg(all(unix, not(target_os = "linux")))]
fn local_addrs() -> Vec<Ipv4Addr> {
    let Ok(ifaces) = nix::net::if_::getifaddrs() else {
        return Vec::new();
    };
    let mut addrs: Vec<Ipv4Addr> = ifaces
        .filter_map(|iface| {
            iface
                .address?
                .as_sockaddr_in()
                .map(|sin| Ipv4Addr::from(sin.ip()))
        })
        .filter(|a| !a.is_loopback() && !a.is_unspecified())
        .collect();
    addrs.sort();
    addrs.dedup();
    addrs
}

#[cfg(target_os = "windows")]
fn local_addrs() -> Vec<Ipv4Addr> {
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    let flags = GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

    let mut size: u32 = 0;
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        )
    };
    if ret != ERROR_BUFFER_OVERFLOW {
        return Vec::new();
    }

    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            ptr::null_mut(),
            buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
            &mut size,
        )
    };
    if ret != 0 {
        return Vec::new();
    }

    let mut addrs = Vec::new();
    let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !adapter.is_null() {
        let mut ua = unsafe { (*adapter).FirstUnicastAddress };
        while !ua.is_null() {
            let sa = unsafe { (*ua).Address.lpSockaddr };
            if !sa.is_null() && unsafe { (*sa).sa_family } == AF_INET {
                let sin = sa as *const SOCKADDR_IN;
                let v4 = Ipv4Addr::from(u32::from_be(unsafe { (*sin).sin_addr.S_un.S_addr }));
                if !v4.is_loopback() && !v4.is_unspecified() {
                    addrs.push(v4);
                }
            }
            ua = unsafe { (*ua).Next };
        }
        adapter = unsafe { (*adapter).Next };
    }
    addrs.sort();
    addrs.dedup();
    addrs
}

#[cfg(not(any(unix, target_os = "windows")))]
fn local_addrs() -> Vec<Ipv4Addr> {
    Vec::new()
}

fn dir_listing(request_path: &str, entries: &[String]) -> String {
    let escaped_path = html_escape(request_path);
    let mut html = format!(
        "<html><head><title>Index of {escaped_path}</title></head>\
         <body><h1>Index of {escaped_path}</h1><ul>"
    );
    if request_path != "/" {
        html.push_str("<li><a href=\"..\">..</a></li>");
    }
    for entry in entries {
        let escaped_entry = html_escape(entry);
        html.push_str(&format!(
            "<li><a href=\"{escaped_entry}\">{escaped_entry}</a></li>"
        ));
    }
    html.push_str("</ul></body></html>");
    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::FakeFs;

    #[test]
    fn serves_file() {
        let fs = FakeFs::new(&[("/root/hello.txt", b"hi")], &["/root"]);
        let r = handle_request(&fs, "/root", "/hello.txt");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hi");
    }

    #[test]
    fn post_returns_method_not_allowed() {
        let fs = FakeFs::new(&[("/root/hello.txt", b"hi")], &["/root"]);
        let r = response_for_request(&fs, "/root", "POST /hello.txt HTTP/1.1");
        assert_eq!(r.status, 405);
        assert!(String::from_utf8_lossy(&r.to_bytes()).contains("Allow: GET, HEAD, OPTIONS\r\n"));
    }

    #[test]
    fn mutating_methods_return_method_not_allowed() {
        let fs = FakeFs::new(&[("/root/hello.txt", b"hi")], &["/root"]);
        for method in ["PUT", "PATCH", "DELETE"] {
            let request = format!("{method} /hello.txt HTTP/1.1");
            let r = response_for_request(&fs, "/root", &request);
            assert_eq!(r.status, 405);
            assert!(
                String::from_utf8_lossy(&r.to_bytes()).contains("Allow: GET, HEAD, OPTIONS\r\n")
            );
        }
    }

    #[test]
    fn options_returns_allowed_methods_without_body() {
        let fs = FakeFs::new(&[("/root/hello.txt", b"hi")], &["/root"]);
        let r = response_for_request(&fs, "/root", "OPTIONS /hello.txt HTTP/1.1");
        let bytes = r.to_bytes();
        let text = String::from_utf8_lossy(&bytes);

        assert_eq!(r.status, 204);
        assert!(text.contains("Allow: GET, HEAD, OPTIONS\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(bytes.ends_with(b"\r\n\r\n"));
    }

    #[test]
    fn head_response_omits_body_bytes() {
        let fs = FakeFs::new(&[("/root/hello.txt", b"hi")], &["/root"]);
        let r = response_for_request(&fs, "/root", "HEAD /hello.txt HTTP/1.1");
        let bytes = r.to_bytes();
        assert!(String::from_utf8_lossy(&bytes).contains("Content-Length: 2\r\n"));
        assert!(!bytes.ends_with(b"hi"));
    }

    #[test]
    fn returns_404_for_missing() {
        let fs = FakeFs::new(&[], &["/root"]);
        let r = handle_request(&fs, "/root", "/missing.txt");
        assert_eq!(r.status, 404);
    }

    #[test]
    fn directory_listing() {
        let fs = FakeFs::new(&[("/root/a.txt", b""), ("/root/b.txt", b"")], &["/root"]);
        let r = handle_request(&fs, "/root", "/");
        assert_eq!(r.status, 200);
        let body = String::from_utf8(r.body).unwrap();
        assert!(body.contains("a.txt"));
        assert!(body.contains("b.txt"));
    }

    #[test]
    fn directory_listing_escapes_html() {
        let fs = FakeFs::new(&[("/root/<script>.txt", b"")], &["/root"]);
        let r = handle_request(&fs, "/root", "/");
        let body = String::from_utf8(r.body).unwrap();
        assert!(!body.contains("<script>"));
        assert!(body.contains("&lt;script&gt;.txt"));
    }

    #[test]
    fn redirect_body_escapes_html() {
        let r = Response::redirect("/a\"&<b>/");
        let body = String::from_utf8(r.body).unwrap();
        assert!(!body.contains("/a\"&<b>/"));
        assert!(body.contains("/a&quot;&amp;&lt;b&gt;/"));
    }

    #[test]
    fn serves_index_html_for_dir() {
        let fs = FakeFs::new(&[("/root/index.html", b"<h1>home</h1>")], &["/root"]);
        let r = handle_request(&fs, "/root", "/");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"<h1>home</h1>");
    }

    #[test]
    fn redirects_dir_without_trailing_slash() {
        let fs = FakeFs::new(&[], &["/root/src"]);
        let r = handle_request(&fs, "/root", "/src");
        assert_eq!(r.status, 301);
        assert_eq!(r.location.as_deref(), Some("/src/"));
    }

    #[test]
    fn redirects_dir_query_after_trailing_slash() {
        let fs = FakeFs::new(&[], &["/root/src"]);
        let r = handle_request(&fs, "/root", "/src?x=1");
        assert_eq!(r.status, 301);
        assert_eq!(r.location.as_deref(), Some("/src/?x=1"));
    }

    #[test]
    fn directory_query_with_trailing_slash_does_not_redirect() {
        let fs = FakeFs::new(&[], &["/root/src"]);
        let r = handle_request(&fs, "/root", "/src/?x=1");
        assert_eq!(r.status, 200);
    }

    #[test]
    fn reads_plain_request_line() {
        let request = b"GET /hello.txt HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut reader = std::io::BufReader::new(&request[..]);
        let line = read_plain_request_line_sync(&mut reader).unwrap();
        assert_eq!(line, "GET /hello.txt HTTP/1.1\r\n");
    }

    #[test]
    fn rejects_oversized_plain_headers() {
        let request = format!(
            "GET / HTTP/1.1\r\nX-Fill: {}\r\n\r\n",
            "a".repeat(MAX_HTTP_HEADER_BYTES)
        );
        let mut reader = std::io::BufReader::new(request.as_bytes());
        let err = read_plain_request_line_sync(&mut reader).unwrap_err();
        assert_eq!(err.to_string(), "HTTP request headers too large");
    }

    #[cfg(feature = "smol-runtime")]
    #[test]
    fn async_plain_reader_rejects_oversized_headers() {
        smol::block_on(async {
            let request = format!(
                "GET / HTTP/1.1\r\nX-Fill: {}\r\n\r\n",
                "a".repeat(MAX_HTTP_HEADER_BYTES)
            );
            let cursor = futures_lite::io::Cursor::new(request.into_bytes());
            let mut reader = futures_lite::io::BufReader::new(cursor);
            let err = read_plain_request_line_async(&mut reader)
                .await
                .unwrap_err();
            assert_eq!(err.to_string(), "HTTP request headers too large");
        });
    }

    #[test]
    fn blocks_traversal() {
        let fs = FakeFs::new(&[("/etc/passwd", b"secret")], &[]);
        let r = handle_request(&fs, "/root", "/../../../etc/passwd");
        assert_eq!(r.status, 404);
    }

    #[test]
    fn mime_types() {
        assert_eq!(mime_type("foo.html"), "text/html");
        assert_eq!(mime_type("foo.js"), "text/javascript");
        assert_eq!(mime_type("foo.png"), "image/png");
        assert_eq!(mime_type("foo"), "application/octet-stream");
    }

    #[test]
    fn parse_args_defaults_port() {
        let args = vec!["./public".into()];
        let (dir, port, tls) = parse_args(&args).unwrap();
        assert_eq!(dir, "./public");
        assert_eq!(port, 8080);
        assert!(!tls);
    }

    #[test]
    fn parse_args_custom_port() {
        let args = vec!["./public".into(), "3000".into()];
        let (_, port, _) = parse_args(&args).unwrap();
        assert_eq!(port, 3000);
    }

    #[test]
    fn parse_args_tls_flag() {
        let args = vec!["./public".into(), "--tls".into()];
        let (dir, port, tls) = parse_args(&args).unwrap();
        assert_eq!(dir, "./public");
        assert_eq!(port, 8443);
        assert!(tls);
    }

    #[test]
    fn parse_args_tls_with_port() {
        let args = vec!["./public".into(), "9443".into(), "--tls".into()];
        let (_, port, tls) = parse_args(&args).unwrap();
        assert_eq!(port, 9443);
        assert!(tls);
    }
}
