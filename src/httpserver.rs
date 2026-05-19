use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};

use crate::deps::DirFs;

pub fn run(out: &mut impl Write, fs: &impl DirFs, args: &[String]) -> io::Result<()> {
    let (dir, port) = parse_args(args)?;
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    writeln!(out, "Serving {dir}")?;
    writeln!(out, "  http://localhost:{port}")?;
    for ip in local_addrs() {
        writeln!(out, "  http://{ip}:{port}")?;
    }
    writeln!(out)?;
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let _ = serve_connection(fs, &dir, s);
            }
            Err(e) => eprintln!("connection error: {e}"),
        }
    }
    Ok(())
}

fn parse_args(args: &[String]) -> io::Result<(String, u16)> {
    match args {
        [dir] => Ok((dir.clone(), 8080)),
        [dir, port] => {
            let port = port
                .parse::<u16>()
                .map_err(|_| io::Error::other("invalid port"))?;
            Ok((dir.clone(), port))
        }
        _ => Err(io::Error::other("usage: httpserver <dir> [port]")),
    }
}

fn serve_connection(fs: &impl DirFs, root: &str, stream: TcpStream) -> io::Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    // consume headers
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    let mut parts = request_line.split_whitespace();
    let _method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");

    handle_request(fs, root, path).write_to(&stream)
}

pub(crate) struct Response {
    pub status: u16,
    reason: &'static str,
    content_type: &'static str,
    pub body: Vec<u8>,
    location: Option<String>,
}

impl Response {
    pub(crate) fn ok(body: Vec<u8>, content_type: &'static str) -> Self {
        Self {
            status: 200,
            reason: "OK",
            content_type,
            body,
            location: None,
        }
    }

    pub(crate) fn not_found() -> Self {
        Self {
            status: 404,
            reason: "Not Found",
            content_type: "text/plain",
            body: b"404 Not Found".to_vec(),
            location: None,
        }
    }

    fn redirect(location: &str) -> Self {
        Self {
            status: 301,
            reason: "Moved Permanently",
            content_type: "text/html",
            body: format!("<a href=\"{location}\">{location}</a>").into_bytes(),
            location: Some(location.to_string()),
        }
    }

    fn write_to(&self, mut w: impl Write) -> io::Result<()> {
        write!(w, "HTTP/1.1 {} {}\r\n", self.status, self.reason)?;
        write!(w, "Content-Type: {}\r\n", self.content_type)?;
        write!(w, "Content-Length: {}\r\n", self.body.len())?;
        if let Some(loc) = &self.location {
            write!(w, "Location: {loc}\r\n")?;
        }
        write!(w, "Connection: close\r\n\r\n")?;
        w.write_all(&self.body)
    }
}

pub(crate) fn handle_request(fs: &impl DirFs, root: &str, request_path: &str) -> Response {
    let Some(path) = resolve_path(root, request_path) else {
        return Response::not_found();
    };

    if fs.is_dir(&path) {
        if !request_path.ends_with('/') {
            return Response::redirect(&format!("{request_path}/"));
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

// Strips `..` components to prevent directory traversal.
fn resolve_path(root: &str, request_path: &str) -> Option<String> {
    let path = request_path.split('?').next().unwrap_or("/");
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

#[cfg(target_os = "linux")]
fn local_addrs() -> Vec<Ipv4Addr> {
    let content = std::fs::read_to_string("/proc/net/fib_trie").unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let mut addrs = Vec::new();
    for w in lines.windows(2) {
        if w[1].contains("host LOCAL") {
            let candidate = w[0].split_whitespace().last().unwrap_or("");
            if let Ok(addr) = candidate.parse::<Ipv4Addr>() {
                if !addr.is_loopback() && !addr.is_unspecified() {
                    addrs.push(addr);
                }
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

    // first call with null buffer to get required size
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
    let mut html = format!(
        "<html><head><title>Index of {request_path}</title></head>\
         <body><h1>Index of {request_path}</h1><ul>"
    );
    if request_path != "/" {
        html.push_str("<li><a href=\"..\">..</a></li>");
    }
    for entry in entries {
        html.push_str(&format!("<li><a href=\"{entry}\">{entry}</a></li>"));
    }
    html.push_str("</ul></body></html>");
    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::{DirFs, Fs};
    use std::collections::HashMap;

    struct FakeFs {
        files: HashMap<String, Vec<u8>>,
        dirs: Vec<String>,
    }

    impl FakeFs {
        fn new(files: &[(&str, &[u8])], dirs: &[&str]) -> Self {
            Self {
                files: files
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_vec()))
                    .collect(),
                dirs: dirs.iter().map(|s| s.to_string()).collect(),
            }
        }
    }

    impl Fs for FakeFs {
        fn read(&self, path: &str) -> io::Result<String> {
            self.read_bytes(path)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
        }
        fn write(&self, _: &str, _: &str) -> io::Result<()> {
            unimplemented!()
        }
    }

    impl DirFs for FakeFs {
        fn read_bytes(&self, path: &str) -> io::Result<Vec<u8>> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::other(format!("{path}: not found")))
        }
        fn is_dir(&self, path: &str) -> bool {
            self.dirs.contains(&path.to_string())
        }
        fn list_dir(&self, path: &str) -> io::Result<Vec<String>> {
            let prefix = format!("{path}/");
            let mut entries: Vec<String> = self
                .files
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .map(|k| k[prefix.len()..].to_string())
                .collect();
            entries.sort();
            Ok(entries)
        }
    }

    #[test]
    fn serves_file() {
        let fs = FakeFs::new(&[("/root/hello.txt", b"hi")], &["/root"]);
        let r = handle_request(&fs, "/root", "/hello.txt");
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hi");
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
    fn blocks_traversal() {
        let fs = FakeFs::new(&[("/etc/passwd", b"secret")], &[]);
        let r = handle_request(&fs, "/root", "/../../../etc/passwd");
        // traversal segments are stripped; resolves to /root/etc/passwd which doesn't exist
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
        let (dir, port) = parse_args(&args).unwrap();
        assert_eq!(dir, "./public");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_args_custom_port() {
        let args = vec!["./public".into(), "3000".into()];
        let (_, port) = parse_args(&args).unwrap();
        assert_eq!(port, 3000);
    }
}
