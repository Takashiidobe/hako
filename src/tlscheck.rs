use std::io::{self, Write};

use crate::deps::{TlsCheck, TlsInfo, TlsOptions};

pub fn run(out: &mut impl Write, tls: &impl TlsCheck, args: &[String]) -> io::Result<()> {
    let target = Target::parse(args)?;
    let info = tls.check_tls(
        &target.host,
        target.port,
        &TlsOptions {
            server_name: &target.server_name,
        },
    )?;
    match target.mode {
        Mode::Check => writeln!(out, "{}:{} ok", target.host, target.port),
        Mode::Fingerprint => print_fingerprint(out, &info),
        Mode::Cert => print_cert(out, &info),
        Mode::Chain => print_chain(out, &info),
        Mode::Expiry => print_expiry(out, &target, &info),
    }
}

struct Target {
    host: String,
    port: u16,
    server_name: String,
    mode: Mode,
}

#[derive(Clone, Copy)]
enum Mode {
    Check,
    Fingerprint,
    Cert,
    Chain,
    Expiry,
}

impl Target {
    fn parse(args: &[String]) -> io::Result<Self> {
        let mut port = None;
        let mut host = None;
        let mut server_name = None;
        let mut mode = Mode::Check;
        let mut i = 0;

        while let Some(arg) = args.get(i) {
            match arg.as_str() {
                "-p" => {
                    i += 1;
                    port = Some(parse_port(args.get(i).map(String::as_str))?);
                }
                "--name" => {
                    i += 1;
                    server_name = Some(
                        args.get(i)
                            .filter(|s| !s.is_empty())
                            .cloned()
                            .ok_or_else(usage)?,
                    );
                }
                "--fingerprint" => mode = Mode::Fingerprint,
                "--cert" => mode = Mode::Cert,
                "--chain" => mode = Mode::Chain,
                "--expiry" => mode = Mode::Expiry,
                arg if !arg.starts_with('-') && host.is_none() => {
                    let (h, p) = parse_host(arg)?;
                    host = Some(h);
                    if p.is_some() {
                        port = p;
                    }
                }
                _ => return Err(usage()),
            }
            i += 1;
        }

        let host = host.ok_or_else(usage)?;
        let server_name = server_name.unwrap_or_else(|| host.clone());
        Ok(Self {
            host,
            port: port.unwrap_or(443),
            server_name,
            mode,
        })
    }
}

fn parse_host(raw: &str) -> io::Result<(String, Option<u16>)> {
    let without_scheme = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("tls://"))
        .unwrap_or(raw);
    let authority = without_scheme.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(usage());
    }

    if authority.matches(':').count() == 1
        && let Some((host, port)) = authority.rsplit_once(':')
    {
        if host.is_empty() {
            return Err(usage());
        }
        return Ok((host.to_string(), Some(parse_port(Some(port))?)));
    }

    Ok((authority.to_string(), None))
}

fn parse_port(value: Option<&str>) -> io::Result<u16> {
    let port = value
        .and_then(|v| v.parse::<u16>().ok())
        .ok_or_else(usage)?;
    if port == 0 {
        return Err(usage());
    }
    Ok(port)
}

fn usage() -> io::Error {
    io::Error::other(
        "usage: tlscheck [--cert|--chain|--expiry|--fingerprint] [--name host] [-p port] <host[:port]>",
    )
}

fn leaf(info: &TlsInfo) -> io::Result<&[u8]> {
    info.certs
        .first()
        .map(Vec::as_slice)
        .ok_or_else(|| io::Error::other("server did not provide a certificate"))
}

fn print_fingerprint(out: &mut impl Write, info: &TlsInfo) -> io::Result<()> {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(leaf(info)?);
    writeln!(out, "sha256 {}", hex_colon(&digest))
}

fn print_cert(out: &mut impl Write, info: &TlsInfo) -> io::Result<()> {
    let cert = CertInfo::parse(leaf(info)?)?;
    writeln!(out, "verified {}", if info.verified { "yes" } else { "no" })?;
    writeln!(out, "subject {}", cert.subject)?;
    writeln!(out, "issuer {}", cert.issuer)?;
    writeln!(out, "not_before {}", cert.not_before)?;
    writeln!(out, "not_after {}", cert.not_after)?;
    for name in cert.dns_names {
        writeln!(out, "dns {name}")?;
    }
    Ok(())
}

fn print_chain(out: &mut impl Write, info: &TlsInfo) -> io::Result<()> {
    for (i, der) in info.certs.iter().enumerate() {
        let cert = CertInfo::parse(der)?;
        writeln!(out, "{i} subject={} issuer={}", cert.subject, cert.issuer)?;
    }
    Ok(())
}

fn print_expiry(out: &mut impl Write, target: &Target, info: &TlsInfo) -> io::Result<()> {
    let cert = CertInfo::parse(leaf(info)?)?;
    writeln!(
        out,
        "{}:{} expires {}",
        target.host, target.port, cert.not_after
    )
}

fn hex_colon(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len().saturating_mul(3).saturating_sub(1));
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

struct CertInfo {
    subject: String,
    issuer: String,
    not_before: String,
    not_after: String,
    dns_names: Vec<String>,
}

impl CertInfo {
    fn parse(der: &[u8]) -> io::Result<Self> {
        let cert = Der::new(der)?.expect_tag(0x30)?;
        let mut cert_items = cert.children();
        let tbs = cert_items.next_tag(0x30)?;
        let mut fields = tbs.children();

        if fields.peek_tag() == Some(0xa0) {
            fields.next_any()?;
        }
        fields.next_any()?;
        fields.next_any()?;
        let issuer = parse_name(fields.next_tag(0x30)?.data)?;
        let validity = fields.next_tag(0x30)?;
        let mut validity_items = validity.children();
        let not_before = parse_time(validity_items.next_any()?)?;
        let not_after = parse_time(validity_items.next_any()?)?;
        let subject = parse_name(fields.next_tag(0x30)?.data)?;
        fields.next_any()?;

        let mut dns_names = Vec::new();
        while let Ok(item) = fields.next_any() {
            if item.tag == 0xa3 {
                dns_names = parse_dns_names(item.data)?;
            }
        }

        Ok(Self {
            subject,
            issuer,
            not_before,
            not_after,
            dns_names,
        })
    }
}

#[derive(Clone, Copy)]
struct Der<'a> {
    tag: u8,
    data: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(input: &'a [u8]) -> io::Result<Self> {
        let (item, rest) = read_der(input)?;
        if !rest.is_empty() {
            return Err(io::Error::other("trailing certificate data"));
        }
        Ok(item)
    }

    fn expect_tag(self, tag: u8) -> io::Result<Self> {
        if self.tag == tag {
            Ok(self)
        } else {
            Err(io::Error::other("unexpected certificate field"))
        }
    }

    fn children(self) -> DerItems<'a> {
        DerItems { data: self.data }
    }
}

struct DerItems<'a> {
    data: &'a [u8],
}

impl<'a> DerItems<'a> {
    fn next_any(&mut self) -> io::Result<Der<'a>> {
        let (item, rest) = read_der(self.data)?;
        self.data = rest;
        Ok(item)
    }

    fn next_tag(&mut self, tag: u8) -> io::Result<Der<'a>> {
        self.next_any()?.expect_tag(tag)
    }

    fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }
}

fn read_der(input: &[u8]) -> io::Result<(Der<'_>, &[u8])> {
    let (&tag, rest) = input
        .split_first()
        .ok_or_else(|| io::Error::other("truncated certificate"))?;
    let (&len0, rest) = rest
        .split_first()
        .ok_or_else(|| io::Error::other("truncated certificate length"))?;

    let (len, rest) = if len0 & 0x80 == 0 {
        (usize::from(len0), rest)
    } else {
        let count = usize::from(len0 & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() || rest.len() < count {
            return Err(io::Error::other("invalid certificate length"));
        }
        let mut len = 0usize;
        let (len_bytes, remaining) = rest.split_at(count);
        for b in len_bytes {
            len = (len << 8) | usize::from(*b);
        }
        (len, remaining)
    };

    if rest.len() < len {
        return Err(io::Error::other("truncated certificate value"));
    }
    let (data, remaining) = rest.split_at(len);
    Ok((Der { tag, data }, remaining))
}

fn parse_name(data: &[u8]) -> io::Result<String> {
    let mut parts = Vec::new();
    let mut rdns = Der { tag: 0x30, data }.children();
    while let Ok(set) = rdns.next_tag(0x31) {
        let mut attrs = set.children();
        let attr = attrs.next_tag(0x30)?;
        let mut attr_items = attr.children();
        let oid = attr_items.next_tag(0x06)?;
        let value = attr_items.next_any()?;
        let Some(name) = oid_name(oid.data) else {
            continue;
        };
        parts.push(format!("{name}={}", parse_string(value)?));
    }

    if parts.is_empty() {
        Ok("(empty)".to_string())
    } else {
        Ok(parts.join(","))
    }
}

fn oid_name(oid: &[u8]) -> Option<&'static str> {
    match oid {
        [0x55, 0x04, 0x03] => Some("CN"),
        [0x55, 0x04, 0x06] => Some("C"),
        [0x55, 0x04, 0x07] => Some("L"),
        [0x55, 0x04, 0x08] => Some("ST"),
        [0x55, 0x04, 0x0a] => Some("O"),
        [0x55, 0x04, 0x0b] => Some("OU"),
        _ => None,
    }
}

fn parse_string(item: Der<'_>) -> io::Result<String> {
    match item.tag {
        0x0c | 0x13 | 0x16 => std::str::from_utf8(item.data)
            .map(str::to_string)
            .map_err(|_| io::Error::other("invalid certificate string")),
        _ => Ok(hex_colon(item.data)),
    }
}

fn parse_time(item: Der<'_>) -> io::Result<String> {
    let s =
        std::str::from_utf8(item.data).map_err(|_| io::Error::other("invalid certificate time"))?;
    match item.tag {
        0x17 if s.len() >= 12 => {
            let year = time_part(s, 0, 2)?;
            let prefix = if year >= "50" { "19" } else { "20" };
            Ok(format!(
                "{prefix}{}-{}-{}T{}:{}:{}Z",
                year,
                time_part(s, 2, 4)?,
                time_part(s, 4, 6)?,
                time_part(s, 6, 8)?,
                time_part(s, 8, 10)?,
                time_part(s, 10, 12)?
            ))
        }
        0x18 if s.len() >= 14 => Ok(format!(
            "{}-{}-{}T{}:{}:{}Z",
            time_part(s, 0, 4)?,
            time_part(s, 4, 6)?,
            time_part(s, 6, 8)?,
            time_part(s, 8, 10)?,
            time_part(s, 10, 12)?,
            time_part(s, 12, 14)?
        )),
        _ => Err(io::Error::other("unsupported certificate time")),
    }
}

fn time_part(s: &str, start: usize, end: usize) -> io::Result<&str> {
    s.get(start..end)
        .ok_or_else(|| io::Error::other("invalid certificate time"))
}

fn parse_dns_names(extensions: &[u8]) -> io::Result<Vec<String>> {
    let outer = Der::new(extensions)?.expect_tag(0x30)?;
    let mut result = Vec::new();
    let mut items = outer.children();
    while let Ok(ext) = items.next_tag(0x30) {
        let mut ext_items = ext.children();
        let oid = ext_items.next_tag(0x06)?;
        if ext_items.peek_tag() == Some(0x01) {
            ext_items.next_any()?;
        }
        let value = ext_items.next_tag(0x04)?;
        if oid.data == [0x55, 0x1d, 0x11] {
            let names = Der::new(value.data)?.expect_tag(0x30)?;
            let mut name_items = names.children();
            while let Ok(name) = name_items.next_any() {
                if name.tag == 0x82 {
                    result.push(
                        std::str::from_utf8(name.data)
                            .map_err(|_| io::Error::other("invalid dns name"))?
                            .to_string(),
                    );
                }
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTls;

    impl TlsCheck for FakeTls {
        fn check_tls(
            &self,
            _host: &str,
            _port: u16,
            _options: &TlsOptions<'_>,
        ) -> io::Result<TlsInfo> {
            Ok(TlsInfo {
                certs: vec![test_cert()],
                verified: true,
            })
        }
    }

    struct FailTls;

    impl TlsCheck for FailTls {
        fn check_tls(
            &self,
            _host: &str,
            _port: u16,
            _options: &TlsOptions<'_>,
        ) -> io::Result<TlsInfo> {
            Err(io::Error::other("certificate verify failed"))
        }
    }

    struct CaptureTls;

    impl TlsCheck for CaptureTls {
        fn check_tls(
            &self,
            host: &str,
            port: u16,
            options: &TlsOptions<'_>,
        ) -> io::Result<TlsInfo> {
            Ok(TlsInfo {
                certs: vec![format!("{host}:{port}:{}", options.server_name).into_bytes()],
                verified: true,
            })
        }
    }

    fn test_cert() -> Vec<u8> {
        include_bytes!(concat!(env!("OUT_DIR"), "/httpserver-cert.der")).to_vec()
    }

    #[test]
    fn checks_default_port() {
        let mut out = Vec::new();
        run(&mut out, &FakeTls, &["example.com".into()]).unwrap();
        assert_eq!(out, b"example.com:443 ok\n");
    }

    #[test]
    fn accepts_host_port() {
        let mut out = Vec::new();
        run(&mut out, &FakeTls, &["example.com:8443".into()]).unwrap();
        assert_eq!(out, b"example.com:8443 ok\n");
    }

    #[test]
    fn accepts_port_option() {
        let mut out = Vec::new();
        run(
            &mut out,
            &FakeTls,
            &["-p".into(), "9443".into(), "example.com".into()],
        )
        .unwrap();
        assert_eq!(out, b"example.com:9443 ok\n");
    }

    #[test]
    fn accepts_https_url() {
        let mut out = Vec::new();
        run(&mut out, &FakeTls, &["https://example.com/path".into()]).unwrap();
        assert_eq!(out, b"example.com:443 ok\n");
    }

    #[test]
    fn propagates_tls_error() {
        let mut out = Vec::new();
        let err = run(&mut out, &FailTls, &["example.com".into()]).unwrap_err();
        assert_eq!(err.to_string(), "certificate verify failed");
    }

    #[test]
    fn accepts_server_name_override() {
        let mut out = Vec::new();
        run(
            &mut out,
            &CaptureTls,
            &[
                "--name".into(),
                "example.com".into(),
                "127.0.0.1:8443".into(),
            ],
        )
        .unwrap();
        assert_eq!(out, b"127.0.0.1:8443 ok\n");
    }

    #[test]
    fn prints_fingerprint() {
        let mut out = Vec::new();
        run(
            &mut out,
            &FakeTls,
            &["--fingerprint".into(), "example.com".into()],
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("sha256 "));
        assert_eq!(text.trim().len(), "sha256 ".len() + 95);
    }

    #[test]
    fn prints_certificate_summary() {
        let mut out = Vec::new();
        run(&mut out, &FakeTls, &["--cert".into(), "example.com".into()]).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("subject "));
        assert!(text.contains("issuer "));
        assert!(text.contains("not_before "));
        assert!(text.contains("not_after "));
        assert!(text.contains("dns localhost"));
    }

    #[test]
    fn prints_chain_summary() {
        let mut out = Vec::new();
        run(
            &mut out,
            &FakeTls,
            &["--chain".into(), "example.com".into()],
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("0 "));
        assert!(text.contains("subject="));
    }

    #[test]
    fn prints_expiry() {
        let mut out = Vec::new();
        run(
            &mut out,
            &FakeTls,
            &["--expiry".into(), "example.com".into()],
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("example.com:443 expires "));
    }

    #[test]
    fn wrong_args_error() {
        let mut out = Vec::new();
        assert!(run(&mut out, &FakeTls, &[]).is_err());
        assert!(run(&mut out, &FakeTls, &["-p".into(), "0".into(), "x".into()]).is_err());
        assert!(run(&mut out, &FakeTls, &["x".into(), "y".into()]).is_err());
    }
}
