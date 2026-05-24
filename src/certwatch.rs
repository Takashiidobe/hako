use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::deps::{TlsCheck, TlsInfo, TlsOptions};

pub fn run(out: &mut impl Write, tls: &impl TlsCheck, args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        return Err(io::Error::other(
            "usage: certwatch <host[:port]> [host[:port]...]",
        ));
    }

    let today = today_unix_days();
    let width = args.iter().map(|a| a.len()).max().unwrap_or(0);

    for arg in args {
        let (host, port) = parse_target(arg)?;
        let label = format!("{arg:<width$}");
        match tls.check_tls(&host, port, &TlsOptions { server_name: &host }) {
            Ok(info) => print_expiry(out, &label, &info, today)?,
            Err(e) => writeln!(out, "{label}  error: {e}")?,
        }
    }
    Ok(())
}

fn print_expiry(out: &mut impl Write, label: &str, info: &TlsInfo, today: i64) -> io::Result<()> {
    match crate::tlscheck::leaf_expiry(info) {
        Ok(expiry) => {
            let days = expiry_days(&expiry) - today;
            let date = expiry.get(..10).unwrap_or(&expiry);
            let note = if days < 0 {
                "  EXPIRED"
            } else if days < 30 {
                "  EXPIRING SOON"
            } else {
                ""
            };
            writeln!(out, "{label}  ok   expires {date}  ({days} days){note}")
        }
        Err(e) => writeln!(out, "{label}  error: {e}"),
    }
}

fn parse_target(raw: &str) -> io::Result<(String, u16)> {
    let without_scheme = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("tls://"))
        .unwrap_or(raw);
    let authority = without_scheme.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(io::Error::other("usage: certwatch <host[:port]>"));
    }
    if authority.matches(':').count() == 1
        && let Some((host, port_str)) = authority.rsplit_once(':')
    {
        if host.is_empty() {
            return Err(io::Error::other("usage: certwatch <host[:port]>"));
        }
        let port = port_str
            .parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(|| io::Error::other("invalid port"))?;
        return Ok((host.to_string(), port));
    }
    Ok((authority.to_string(), 443))
}

// returns days since Unix epoch for the date in "YYYY-MM-DDTHH:MM:SSZ"
fn expiry_days(iso: &str) -> i64 {
    let y: i64 = iso.get(0..4).and_then(|s| s.parse().ok()).unwrap_or(0);
    let m: i64 = iso.get(5..7).and_then(|s| s.parse().ok()).unwrap_or(0);
    let d: i64 = iso.get(8..10).and_then(|s| s.parse().ok()).unwrap_or(0);
    ymd_to_unix_days(y, m, d)
}

// standard proleptic Gregorian → Julian Day Number → Unix days
fn ymd_to_unix_days(y: i64, m: i64, d: i64) -> i64 {
    let a = (14 - m) / 12;
    let y = y + 4800 - a;
    let m = m + 12 * a - 3;
    let jdn = d + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32045;
    jdn - 2_440_588 // JDN of 1970-01-01
}

fn today_unix_days() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 86400) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTls {
        certs: Vec<Vec<u8>>,
    }

    impl TlsCheck for FakeTls {
        fn check_tls(
            &self,
            _host: &str,
            _port: u16,
            _opts: &TlsOptions<'_>,
        ) -> io::Result<TlsInfo> {
            Ok(TlsInfo {
                certs: self.certs.clone(),
                verified: true,
            })
        }
    }

    struct FailTls;
    impl TlsCheck for FailTls {
        fn check_tls(&self, _: &str, _: u16, _: &TlsOptions<'_>) -> io::Result<TlsInfo> {
            Err(io::Error::other("connection refused"))
        }
    }

    fn test_cert() -> Vec<u8> {
        include_bytes!(concat!(env!("OUT_DIR"), "/httpserver-cert.der")).to_vec()
    }

    #[test]
    fn prints_expiry_for_valid_cert() {
        let tls = FakeTls {
            certs: vec![test_cert()],
        };
        let mut out = Vec::new();
        run(&mut out, &tls, &["example.com".into()]).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("example.com  ok   expires "));
        assert!(text.contains(" days)"));
    }

    #[test]
    fn prints_error_on_connection_failure() {
        let mut out = Vec::new();
        run(&mut out, &FailTls, &["example.com".into()]).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("error: connection refused"));
    }

    #[test]
    fn accepts_host_colon_port() {
        struct CaptureTls(std::cell::Cell<(String, u16)>);
        impl TlsCheck for CaptureTls {
            fn check_tls(&self, h: &str, p: u16, _: &TlsOptions<'_>) -> io::Result<TlsInfo> {
                self.0.set((h.to_string(), p));
                Err(io::Error::other("ok"))
            }
        }
        let tls = CaptureTls(std::cell::Cell::new((String::new(), 0)));
        let mut out = Vec::new();
        run(&mut out, &tls, &["example.com:8443".into()]).unwrap();
        assert_eq!(tls.0.take(), ("example.com".to_string(), 8443));
    }

    #[test]
    fn aligns_multiple_hosts() {
        let tls = FakeTls {
            certs: vec![test_cert()],
        };
        let mut out = Vec::new();
        run(
            &mut out,
            &tls,
            &["a.com".into(), "longer.example.com".into()],
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        // both lines start with equal-width label
        let col0: usize = lines[0].find("  ok").unwrap();
        let col1: usize = lines[1].find("  ok").unwrap();
        assert_eq!(col0, col1);
    }

    #[test]
    fn wrong_args_error() {
        let tls = FakeTls {
            certs: vec![test_cert()],
        };
        let mut out = Vec::new();
        assert!(run(&mut out, &tls, &[]).is_err());
    }

    #[test]
    fn ymd_unix_days_epoch() {
        assert_eq!(ymd_to_unix_days(1970, 1, 1), 0);
    }

    #[test]
    fn ymd_unix_days_known_date() {
        // 2025-09-01 is 20332 days after Unix epoch
        assert_eq!(ymd_to_unix_days(2025, 9, 1), 20332);
    }
}
