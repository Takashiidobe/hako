use std::net::Ipv4Addr;
use std::time::SystemTime;

pub trait Clock {
    fn now(&self) -> SystemTime;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

pub trait Rng {
    fn next_u64(&mut self) -> u64;
}

pub struct SystemRng {
    state: u64,
}

impl SystemRng {
    pub fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u64;
        Self {
            state: seed ^ 0x9e3779b97f4a7c15,
        }
    }
}

impl Rng for SystemRng {
    fn next_u64(&mut self) -> u64 {
        // xorshift64
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}

pub trait Fs {
    fn read(&self, path: &str) -> std::io::Result<String>;
    fn write(&self, path: &str, content: &str) -> std::io::Result<()>;
}

pub struct SystemFs;

impl Fs for SystemFs {
    fn read(&self, path: &str) -> std::io::Result<String> {
        std::fs::read_to_string(path)
    }
    fn write(&self, path: &str, content: &str) -> std::io::Result<()> {
        std::fs::write(path, content)
    }
}

pub trait Dns {
    fn lookup_a(&self, domain: &str) -> std::io::Result<Vec<Ipv4Addr>>;
}

pub struct UdpDns {
    pub nameserver: Ipv4Addr,
}

impl Default for UdpDns {
    fn default() -> Self {
        Self {
            nameserver: Ipv4Addr::new(8, 8, 8, 8),
        }
    }
}

impl Dns for UdpDns {
    fn lookup_a(&self, domain: &str) -> std::io::Result<Vec<Ipv4Addr>> {
        use std::net::{SocketAddr, UdpSocket};

        let id = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u16;

        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        socket.send_to(
            &build_query(domain, id),
            SocketAddr::from((self.nameserver, 53)),
        )?;

        let mut buf = [0u8; 512];
        let (n, _) = socket.recv_from(&mut buf)?;
        parse_a_records(&buf[..n], id)
    }
}

fn build_query(domain: &str, id: u16) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    buf.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // AN/NS/AR = 0
    for label in domain.trim_end_matches('.').split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // root label
    buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    buf
}

fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        } else if len & 0xc0 == 0xc0 {
            return Some(pos + 2); // compression pointer
        }
        pos += 1 + len;
    }
}

fn parse_a_records(buf: &[u8], id: u16) -> std::io::Result<Vec<Ipv4Addr>> {
    if buf.len() < 12 {
        return Err(std::io::Error::other("response too short"));
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != id {
        return Err(std::io::Error::other("ID mismatch"));
    }
    let rcode = u16::from_be_bytes([buf[2], buf[3]]) & 0xf;
    if rcode != 0 {
        return Err(std::io::Error::other(format!("DNS rcode {rcode}")));
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(buf, pos).ok_or_else(|| std::io::Error::other("malformed question"))?;
        pos += 4; // QTYPE + QCLASS
    }

    let mut addrs = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(buf, pos).ok_or_else(|| std::io::Error::other("malformed answer"))?;
        if pos + 10 > buf.len() {
            return Err(std::io::Error::other("truncated answer"));
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return Err(std::io::Error::other("truncated rdata"));
        }
        if rtype == 1 && rdlen == 4 {
            addrs.push(Ipv4Addr::new(
                buf[pos],
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
            ));
        }
        pos += rdlen;
    }
    Ok(addrs)
}

pub trait DirFs: Fs {
    fn read_bytes(&self, path: &str) -> std::io::Result<Vec<u8>>;
    fn is_dir(&self, path: &str) -> bool;
    fn list_dir(&self, path: &str) -> std::io::Result<Vec<String>>;
}

impl DirFs for SystemFs {
    fn read_bytes(&self, path: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(path)
    }
    fn is_dir(&self, path: &str) -> bool {
        std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
    }
    fn list_dir(&self, path: &str) -> std::io::Result<Vec<String>> {
        let mut entries: Vec<String> = std::fs::read_dir(path)?
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        Ok(entries)
    }
}

#[cfg(feature = "ping")]
pub trait Icmp {
    fn send_ping(&self, dest: std::net::Ipv4Addr, seq: u16, payload: &[u8]) -> std::io::Result<std::time::Duration>;
}

#[cfg(feature = "ping")]
pub struct SystemIcmp;

#[cfg(feature = "ping")]
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(feature = "ping")]
fn build_icmp_echo(seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut pkt = vec![0u8; 8 + payload.len()];
    pkt[0] = 8; // echo request
    let [sh, sl] = seq.to_be_bytes();
    pkt[6] = sh;
    pkt[7] = sl;
    pkt[8..].copy_from_slice(payload);
    let ck = icmp_checksum(&pkt);
    pkt[2] = (ck >> 8) as u8;
    pkt[3] = ck as u8;
    pkt
}

#[cfg(all(feature = "ping", unix))]
impl Icmp for SystemIcmp {
    fn send_ping(&self, dest: std::net::Ipv4Addr, seq: u16, payload: &[u8]) -> std::io::Result<std::time::Duration> {
        use socket2::{Domain, Protocol, Socket, Type};
        use std::mem::MaybeUninit;
        use std::net::SocketAddrV4;
        use std::time::{Duration, Instant};

        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
        sock.set_read_timeout(Some(Duration::from_secs(5)))?;

        let pkt = build_icmp_echo(seq, payload);
        let addr: socket2::SockAddr = SocketAddrV4::new(dest, 0).into();

        let t0 = Instant::now();
        sock.send_to(&pkt, &addr)?;

        let mut buf = [MaybeUninit::<u8>::uninit(); 256];
        let (n, _) = sock.recv_from(&mut buf)?;
        let rtt = t0.elapsed();

        // DGRAM ICMP: kernel strips IP header, data starts at ICMP header
        let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if data.len() < 8 {
            return Err(std::io::Error::other("ICMP response too short"));
        }
        if data[0] != 0 {
            return Err(std::io::Error::other(format!("unexpected ICMP type {}", data[0])));
        }

        Ok(rtt)
    }
}

#[cfg(all(feature = "ping", target_os = "windows"))]
impl Icmp for SystemIcmp {
    fn send_ping(&self, dest: std::net::Ipv4Addr, seq: u16, payload: &[u8]) -> std::io::Result<std::time::Duration> {
        use std::ptr;
        use std::time::Duration;
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY,
        };

        let _ = seq; // Windows API doesn't expose seq; RTT comes from reply struct
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error());
        }

        let dest_addr = u32::from_ne_bytes(dest.octets());
        let reply_size = std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8;
        let mut reply_buf = vec![0u8; reply_size];

        let ret = unsafe {
            IcmpSendEcho(
                handle,
                dest_addr,
                payload.as_ptr() as *mut _,
                payload.len() as u16,
                ptr::null_mut(),
                reply_buf.as_mut_ptr() as *mut _,
                reply_size as u32,
                5000,
            )
        };
        unsafe { IcmpCloseHandle(handle) };

        if ret == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let reply = unsafe { &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };
        Ok(Duration::from_millis(reply.RoundTripTime as u64))
    }
}

#[cfg(all(feature = "ping", not(any(unix, target_os = "windows"))))]
impl Icmp for SystemIcmp {
    fn send_ping(&self, _dest: std::net::Ipv4Addr, _seq: u16, _payload: &[u8]) -> std::io::Result<std::time::Duration> {
        Err(std::io::Error::other("ping not supported on this platform"))
    }
}

#[cfg(feature = "fetch")]
pub trait Net {
    fn get(&self, url: &str) -> std::io::Result<Vec<u8>>;
}

#[cfg(feature = "fetch")]
pub struct SystemNet;

#[cfg(feature = "fetch")]
fn parse_url(url: &str) -> std::io::Result<(bool, String, u16, String)> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(std::io::Error::other(
            "URL must start with http:// or https://",
        ));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| std::io::Error::other("invalid port"))?,
        ),
        None => (authority.to_string(), default_port),
    };
    Ok((tls, host, port, path))
}

#[cfg(feature = "fetch")]
fn http_exchange(mut stream: impl std::io::Read + std::io::Write, host: &str, path: &str) -> std::io::Result<Vec<u8>> {
    use std::io::{BufRead, BufReader, Read};

    write!(stream, "GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n")?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other("invalid HTTP status line"))?;

    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
    }

    if !(200..300).contains(&status) {
        return Err(std::io::Error::other(format!("HTTP {status}")));
    }

    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    Ok(body)
}

#[cfg(feature = "fetch")]
impl Net for SystemNet {
    fn get(&self, url: &str) -> std::io::Result<Vec<u8>> {
        use std::net::TcpStream;
        use std::time::Duration;

        let (tls, host, port, path) = parse_url(url)?;
        let stream = TcpStream::connect((&*host, port))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;

        if tls {
            #[cfg(feature = "native-tls")]
            {
                let connector = native_tls::TlsConnector::new()
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                let tls_stream = connector
                    .connect(&host, stream)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                return http_exchange(tls_stream, &host, &path);
            }

            #[cfg(all(feature = "rustls", not(feature = "native-tls")))]
            {
                use rustls::pki_types::ServerName;
                use std::sync::Arc;

                let mut root_store = rustls::RootCertStore::empty();
                for cert in rustls_native_certs::load_native_certs().certs {
                    root_store.add(cert).ok();
                }
                let config = Arc::new(
                    rustls::ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_no_client_auth(),
                );
                let server_name = ServerName::try_from(host.as_str())
                    .map_err(|e| std::io::Error::other(e.to_string()))?
                    .to_owned();
                let conn = rustls::ClientConnection::new(config, server_name)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                return http_exchange(rustls::StreamOwned::new(conn, stream), &host, &path);
            }

            #[cfg(not(any(feature = "native-tls", feature = "rustls")))]
            return Err(std::io::Error::other(
                "https:// requires the native-tls or rustls feature",
            ));
        }

        http_exchange(stream, &host, &path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_query_encodes_domain() {
        let q = build_query("example.com", 0x1234);
        assert_eq!(&q[0..2], &[0x12, 0x34]); // ID
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD flag
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT=1
        // "example" label
        assert_eq!(q[12], 7);
        assert_eq!(&q[13..20], b"example");
        // "com" label
        assert_eq!(q[20], 3);
        assert_eq!(&q[21..24], b"com");
        // root + QTYPE A + QCLASS IN
        assert_eq!(&q[24..], &[0, 0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn parse_a_records_single() {
        // hand-crafted response: ID=0x1234, one A record 1.2.3.4
        let mut pkt: Vec<u8> = vec![
            0x12, 0x34, // ID
            0x81, 0x80, // flags: QR=1 RD=1 RA=1
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x01, // ANCOUNT=1
            0x00, 0x00, 0x00, 0x00, // NS/AR=0
            // question: example.com A IN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00,
            0x01,
            // answer: compressed name -> offset 12, A, IN, TTL=300, RDLEN=4, 1.2.3.4
            0xc0, 0x0c, 0x00, 0x01, // TYPE=A
            0x00, 0x01, // CLASS=IN
            0x00, 0x00, 0x01, 0x2c, // TTL=300
            0x00, 0x04, // RDLEN=4
            1, 2, 3, 4,
        ];
        let addrs = parse_a_records(&pkt, 0x1234).unwrap();
        assert_eq!(addrs, vec![Ipv4Addr::new(1, 2, 3, 4)]);

        // AAAA records in the answer should be ignored
        pkt[7] = 0; // ANCOUNT=0 answers
        let addrs = parse_a_records(&pkt, 0x1234).unwrap();
        assert!(addrs.is_empty());
    }

    #[test]
    fn parse_rejects_id_mismatch() {
        let pkt = vec![0x00; 12];
        assert!(parse_a_records(&pkt, 0x0001).is_err());
    }

    #[test]
    fn parse_rejects_nonzero_rcode() {
        let mut pkt = vec![0x12, 0x34, 0x81, 0x83]; // rcode=3 NXDOMAIN
        pkt.extend_from_slice(&[0u8; 8]);
        assert!(parse_a_records(&pkt, 0x1234).is_err());
    }
}
