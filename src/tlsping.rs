use std::io::{self, Write};

use crate::deps::TlsPing;

pub fn run(out: &mut impl Write, net: &impl TlsPing, args: &[String]) -> io::Result<()> {
    let (host, port) = parse_target(args)?;
    let r = net.ping(&host, port)?;
    let total = r.tcp_ms + r.tls_ms;
    writeln!(out, "tcp   {}ms", r.tcp_ms)?;
    writeln!(out, "tls   {}ms", r.tls_ms)?;
    writeln!(out, "total {}ms", total)
}

fn parse_target(args: &[String]) -> io::Result<(String, u16)> {
    let raw = match args {
        [h] => h.as_str(),
        _ => return Err(usage()),
    };
    let without_scheme = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("tls://"))
        .unwrap_or(raw);
    let authority = without_scheme.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(usage());
    }
    if authority.matches(':').count() == 1
        && let Some((host, port_str)) = authority.rsplit_once(':')
    {
        if host.is_empty() {
            return Err(usage());
        }
        let port = port_str
            .parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(usage)?;
        return Ok((host.to_string(), port));
    }
    Ok((authority.to_string(), 443))
}

fn usage() -> io::Error {
    io::Error::other("usage: tlsping <host[:port]>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::net::TlsPingResult;

    struct FakePing {
        tcp_ms: u128,
        tls_ms: u128,
    }

    impl TlsPing for FakePing {
        fn ping(&self, _host: &str, _port: u16) -> io::Result<TlsPingResult> {
            Ok(TlsPingResult { tcp_ms: self.tcp_ms, tls_ms: self.tls_ms })
        }
    }

    struct CapturePing(std::cell::Cell<(String, u16)>);

    impl TlsPing for CapturePing {
        fn ping(&self, host: &str, port: u16) -> io::Result<TlsPingResult> {
            self.0.set((host.to_string(), port));
            Ok(TlsPingResult { tcp_ms: 10, tls_ms: 20 })
        }
    }

    #[test]
    fn prints_timings() {
        let net = FakePing { tcp_ms: 12, tls_ms: 38 };
        let mut out = Vec::new();
        run(&mut out, &net, &["example.com".into()]).unwrap();
        assert_eq!(out, b"tcp   12ms\ntls   38ms\ntotal 50ms\n");
    }

    #[test]
    fn default_port_is_443() {
        let net = CapturePing(std::cell::Cell::new((String::new(), 0)));
        let mut out = Vec::new();
        run(&mut out, &net, &["example.com".into()]).unwrap();
        assert_eq!(net.0.take(), ("example.com".to_string(), 443));
    }

    #[test]
    fn accepts_host_colon_port() {
        let net = CapturePing(std::cell::Cell::new((String::new(), 0)));
        let mut out = Vec::new();
        run(&mut out, &net, &["example.com:8443".into()]).unwrap();
        assert_eq!(net.0.take(), ("example.com".to_string(), 8443));
    }

    #[test]
    fn accepts_https_url() {
        let net = CapturePing(std::cell::Cell::new((String::new(), 0)));
        let mut out = Vec::new();
        run(&mut out, &net, &["https://example.com/path".into()]).unwrap();
        assert_eq!(net.0.take(), ("example.com".to_string(), 443));
    }

    #[test]
    fn wrong_args_error() {
        let net = FakePing { tcp_ms: 0, tls_ms: 0 };
        let mut out = Vec::new();
        assert!(run(&mut out, &net, &[]).is_err());
        assert!(run(&mut out, &net, &["a".into(), "b".into()]).is_err());
    }
}
