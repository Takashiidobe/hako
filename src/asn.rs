use std::io::{self, Write};
use std::net::Ipv4Addr;

use crate::deps::{Dns, Whois};

const CYMRU_SERVER: &str = "whois.cymru.com";

pub fn run(
    out: &mut impl Write,
    dns: &impl Dns,
    whois: &impl Whois,
    args: &[String],
) -> io::Result<()> {
    let target = match args {
        [target] => target,
        _ => return Err(usage()),
    };

    let ip = target
        .parse::<Ipv4Addr>()
        .map_or_else(|_| resolve_one(dns, target), Ok)?;
    let response = whois.query(CYMRU_SERVER, &format!(" -v {ip}"))?;
    let record = AsnRecord::parse(&response)?;

    writeln!(out, "ip {}", record.ip)?;
    writeln!(out, "asn {}", record.asn)?;
    writeln!(out, "prefix {}", record.prefix)?;
    writeln!(out, "cc {}", record.cc)?;
    writeln!(out, "registry {}", record.registry)?;
    writeln!(out, "allocated {}", record.allocated)?;
    writeln!(out, "name {}", record.name)
}

fn resolve_one(dns: &impl Dns, host: &str) -> io::Result<Ipv4Addr> {
    dns.lookup_a(host)?
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other(format!("{host}: no A records found")))
}

fn usage() -> io::Error {
    io::Error::other("usage: asn <ip|host>")
}

struct AsnRecord {
    asn: String,
    ip: String,
    prefix: String,
    cc: String,
    registry: String,
    allocated: String,
    name: String,
}

impl AsnRecord {
    fn parse(response: &str) -> io::Result<Self> {
        response
            .lines()
            .filter(|line| !line.trim().is_empty())
            .find_map(parse_record_line)
            .ok_or_else(|| io::Error::other("ASN record not found"))
    }
}

fn parse_record_line(line: &str) -> Option<AsnRecord> {
    let cols: Vec<&str> = line.split('|').map(str::trim).collect();
    if cols.len() < 7 || cols.first()?.eq_ignore_ascii_case("as") {
        return None;
    }

    Some(AsnRecord {
        asn: cols.first()?.to_string(),
        ip: cols.get(1)?.to_string(),
        prefix: cols.get(2)?.to_string(),
        cc: cols.get(3)?.to_string(),
        registry: cols.get(4)?.to_string(),
        allocated: cols.get(5)?.to_string(),
        name: cols.get(6)?.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Whois;
    use crate::mock::{FailDns, FakeDns};

    struct FakeWhois {
        response: &'static str,
    }

    impl Whois for FakeWhois {
        fn query(&self, server: &str, query: &str) -> io::Result<String> {
            if server != CYMRU_SERVER {
                return Err(io::Error::other(format!("wrong server: {server}")));
            }
            if query != " -v 1.1.1.1" {
                return Err(io::Error::other(format!("wrong query: {query}")));
            }
            Ok(self.response.to_string())
        }
    }

    struct FailWhois;

    impl Whois for FailWhois {
        fn query(&self, _server: &str, _query: &str) -> io::Result<String> {
            Err(io::Error::other("connection refused"))
        }
    }

    const CYMRU_RESPONSE: &str = "\
AS      | IP               | BGP Prefix          | CC | Registry | Allocated  | AS Name
13335   | 1.1.1.1          | 1.1.1.0/24          | AU | apnic    | 2011-08-11 | CLOUDFLARENET, US
";

    #[test]
    fn prints_asn_record_for_ip() {
        let mut out = Vec::new();
        run(
            &mut out,
            &FakeDns(vec![]),
            &FakeWhois {
                response: CYMRU_RESPONSE,
            },
            &["1.1.1.1".into()],
        )
        .unwrap();
        assert_eq!(
            out,
            b"ip 1.1.1.1\nasn 13335\nprefix 1.1.1.0/24\ncc AU\nregistry apnic\nallocated 2011-08-11\nname CLOUDFLARENET, US\n"
        );
    }

    #[test]
    fn resolves_host_before_querying() {
        let mut out = Vec::new();
        run(
            &mut out,
            &FakeDns(vec![Ipv4Addr::new(1, 1, 1, 1)]),
            &FakeWhois {
                response: CYMRU_RESPONSE,
            },
            &["one.one.one.one".into()],
        )
        .unwrap();
        assert!(String::from_utf8(out).unwrap().contains("asn 13335\n"));
    }

    #[test]
    fn propagates_dns_error() {
        let mut out = Vec::new();
        let err = run(&mut out, &FailDns, &FailWhois, &["bad.example".into()]).unwrap_err();
        assert_eq!(err.to_string(), "timeout");
    }

    #[test]
    fn rejects_empty_dns_result() {
        let mut out = Vec::new();
        let err = run(
            &mut out,
            &FakeDns(vec![]),
            &FailWhois,
            &["empty.example".into()],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "empty.example: no A records found");
    }

    #[test]
    fn propagates_whois_error() {
        let mut out = Vec::new();
        let err = run(&mut out, &FakeDns(vec![]), &FailWhois, &["1.1.1.1".into()]).unwrap_err();
        assert_eq!(err.to_string(), "connection refused");
    }

    #[test]
    fn rejects_malformed_response() {
        let mut out = Vec::new();
        let err = run(
            &mut out,
            &FakeDns(vec![]),
            &FakeWhois { response: "nope\n" },
            &["1.1.1.1".into()],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "ASN record not found");
    }

    #[test]
    fn wrong_arg_count_errors() {
        let mut out = Vec::new();
        assert!(run(&mut out, &FakeDns(vec![]), &FailWhois, &[]).is_err());
        assert!(
            run(
                &mut out,
                &FakeDns(vec![]),
                &FailWhois,
                &["1.1.1.1".into(), "8.8.8.8".into()],
            )
            .is_err()
        );
    }
}
