use std::io::{self, Write};

use crate::deps::TlsCheck;

pub fn run(out: &mut impl Write, tls: &impl TlsCheck, args: &[String]) -> io::Result<()> {
    let target = Target::parse(args)?;
    tls.check_tls(&target.host, target.port)?;
    writeln!(out, "{}:{} ok", target.host, target.port)
}

struct Target {
    host: String,
    port: u16,
}

impl Target {
    fn parse(args: &[String]) -> io::Result<Self> {
        let mut port = None;
        let mut host = None;
        let mut i = 0;

        while let Some(arg) = args.get(i) {
            match arg.as_str() {
                "-p" => {
                    i += 1;
                    port = Some(parse_port(args.get(i).map(String::as_str))?);
                }
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
        Ok(Self {
            host,
            port: port.unwrap_or(443),
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
    io::Error::other("usage: tlscheck [-p port] <host[:port]>")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTls;

    impl TlsCheck for FakeTls {
        fn check_tls(&self, _host: &str, _port: u16) -> io::Result<()> {
            Ok(())
        }
    }

    struct FailTls;

    impl TlsCheck for FailTls {
        fn check_tls(&self, _host: &str, _port: u16) -> io::Result<()> {
            Err(io::Error::other("certificate verify failed"))
        }
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
    fn wrong_args_error() {
        let mut out = Vec::new();
        assert!(run(&mut out, &FakeTls, &[]).is_err());
        assert!(run(&mut out, &FakeTls, &["-p".into(), "0".into(), "x".into()]).is_err());
        assert!(run(&mut out, &FakeTls, &["x".into(), "y".into()]).is_err());
    }
}
