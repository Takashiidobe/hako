use std::io::{self, Write};

use crate::deps::Dns;

pub fn run(out: &mut impl Write, dns: &impl Dns, args: &[String]) -> io::Result<()> {
    let query = Query::parse(args)?;
    let records = query.record_type.lookup(dns, &query.domain)?;
    if records.is_empty() {
        writeln!(
            out,
            "{}: no {} records found",
            query.domain,
            query.record_type.name()
        )?;
        return Ok(());
    }
    for record in records {
        writeln!(out, "{record}")?;
    }
    Ok(())
}

struct Query {
    domain: String,
    record_type: RecordType,
}

enum RecordType {
    A,
    Aaaa,
    Mx,
    Txt,
    Ns,
    Cname,
}

impl RecordType {
    fn parse(s: &str) -> io::Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::Aaaa),
            "MX" => Ok(Self::Mx),
            "TXT" => Ok(Self::Txt),
            "NS" => Ok(Self::Ns),
            "CNAME" => Ok(Self::Cname),
            _ => Err(io::Error::other(format!("unknown record type: {s}"))),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Mx => "MX",
            Self::Txt => "TXT",
            Self::Ns => "NS",
            Self::Cname => "CNAME",
        }
    }

    fn lookup(&self, dns: &impl Dns, domain: &str) -> io::Result<Vec<String>> {
        match self {
            Self::A => dns
                .lookup_a(domain)
                .map(|v| v.iter().map(|a| a.to_string()).collect()),
            Self::Aaaa => dns.lookup_aaaa(domain),
            Self::Mx => dns.lookup_mx(domain),
            Self::Txt => dns.lookup_txt(domain),
            Self::Ns => dns.lookup_ns(domain),
            Self::Cname => dns.lookup_cname(domain),
        }
    }
}

impl Query {
    fn parse(args: &[String]) -> io::Result<Self> {
        let mut domain = None;
        let mut record_type = RecordType::A;
        let mut i = 0;

        while let Some(arg) = args.get(i) {
            match arg.as_str() {
                "-t" | "--type" => {
                    i += 1;
                    let t = args.get(i).map(String::as_str).ok_or_else(usage)?;
                    record_type = RecordType::parse(t)?;
                }
                arg if !arg.starts_with('-') && domain.is_none() => {
                    domain = Some(strip_url(arg));
                }
                _ => return Err(usage()),
            }
            i += 1;
        }

        let domain = domain.ok_or_else(usage)?;
        Ok(Self {
            domain,
            record_type,
        })
    }
}

fn usage() -> io::Error {
    io::Error::other("usage: dig [-t A|AAAA|MX|TXT|NS|CNAME] <domain>")
}

fn strip_url(s: &str) -> String {
    let without_scheme = s.split_once("://").map(|(_, rest)| rest).unwrap_or(s);
    without_scheme
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or(without_scheme)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{FailDns, FakeDns};
    use std::net::Ipv4Addr;

    struct FakeTypedDns {
        aaaa: Vec<String>,
        mx: Vec<String>,
        txt: Vec<String>,
        ns: Vec<String>,
        cname: Vec<String>,
    }

    impl FakeTypedDns {
        fn new() -> Self {
            Self {
                aaaa: vec![],
                mx: vec![],
                txt: vec![],
                ns: vec![],
                cname: vec![],
            }
        }
    }

    impl Dns for FakeTypedDns {
        fn lookup_a(&self, _: &str) -> io::Result<Vec<Ipv4Addr>> {
            Ok(vec![])
        }
        fn lookup_ptr(&self, _: &Ipv4Addr) -> io::Result<Vec<String>> {
            Ok(vec![])
        }
        fn lookup_aaaa(&self, _: &str) -> io::Result<Vec<String>> {
            Ok(self.aaaa.clone())
        }
        fn lookup_mx(&self, _: &str) -> io::Result<Vec<String>> {
            Ok(self.mx.clone())
        }
        fn lookup_txt(&self, _: &str) -> io::Result<Vec<String>> {
            Ok(self.txt.clone())
        }
        fn lookup_ns(&self, _: &str) -> io::Result<Vec<String>> {
            Ok(self.ns.clone())
        }
        fn lookup_cname(&self, _: &str) -> io::Result<Vec<String>> {
            Ok(self.cname.clone())
        }
    }

    #[test]
    fn prints_a_records_by_default() {
        let mut out = Vec::new();
        let dns = FakeDns(vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)]);
        run(&mut out, &dns, &["example.com".into()]).unwrap();
        assert_eq!(out, b"1.2.3.4\n5.6.7.8\n");
    }

    #[test]
    fn no_a_records() {
        let mut out = Vec::new();
        run(&mut out, &FakeDns(vec![]), &["empty.example".into()]).unwrap();
        assert_eq!(out, b"empty.example: no A records found\n");
    }

    #[test]
    fn explicit_type_a() {
        let mut out = Vec::new();
        let dns = FakeDns(vec![Ipv4Addr::new(9, 9, 9, 9)]);
        run(
            &mut out,
            &dns,
            &["-t".into(), "A".into(), "example.com".into()],
        )
        .unwrap();
        assert_eq!(out, b"9.9.9.9\n");
    }

    #[test]
    fn type_flag_case_insensitive() {
        let mut out = Vec::new();
        let dns = FakeTypedDns {
            mx: vec!["10 mail.example.com".into()],
            ..FakeTypedDns::new()
        };
        run(
            &mut out,
            &dns,
            &["--type".into(), "mx".into(), "example.com".into()],
        )
        .unwrap();
        assert_eq!(out, b"10 mail.example.com\n");
    }

    #[test]
    fn aaaa_records() {
        let mut out = Vec::new();
        let dns = FakeTypedDns {
            aaaa: vec!["2606:4700:4700::1111".into()],
            ..FakeTypedDns::new()
        };
        run(
            &mut out,
            &dns,
            &["-t".into(), "AAAA".into(), "example.com".into()],
        )
        .unwrap();
        assert_eq!(out, b"2606:4700:4700::1111\n");
    }

    #[test]
    fn txt_records() {
        let mut out = Vec::new();
        let dns = FakeTypedDns {
            txt: vec!["v=spf1 include:example.com ~all".into()],
            ..FakeTypedDns::new()
        };
        run(
            &mut out,
            &dns,
            &["-t".into(), "TXT".into(), "example.com".into()],
        )
        .unwrap();
        assert_eq!(out, b"v=spf1 include:example.com ~all\n");
    }

    #[test]
    fn ns_records() {
        let mut out = Vec::new();
        let dns = FakeTypedDns {
            ns: vec!["ns1.example.com".into(), "ns2.example.com".into()],
            ..FakeTypedDns::new()
        };
        run(
            &mut out,
            &dns,
            &["-t".into(), "NS".into(), "example.com".into()],
        )
        .unwrap();
        assert_eq!(out, b"ns1.example.com\nns2.example.com\n");
    }

    #[test]
    fn cname_no_records() {
        let mut out = Vec::new();
        let dns = FakeTypedDns::new();
        run(
            &mut out,
            &dns,
            &["-t".into(), "CNAME".into(), "alias.example".into()],
        )
        .unwrap();
        assert_eq!(out, b"alias.example: no CNAME records found\n");
    }

    #[test]
    fn unknown_type_errors() {
        let mut out = Vec::new();
        let err = run(
            &mut out,
            &FakeDns(vec![]),
            &["-t".into(), "BOGUS".into(), "example.com".into()],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "unknown record type: BOGUS");
    }

    #[test]
    fn dns_error_propagates() {
        let mut out = Vec::new();
        let err = run(&mut out, &FailDns, &["bad.example".into()]).unwrap_err();
        assert_eq!(err.to_string(), "timeout");
    }

    #[test]
    fn no_domain_errors() {
        let mut out = Vec::new();
        assert!(run(&mut out, &FakeDns(vec![]), &[]).is_err());
    }

    #[test]
    fn missing_type_value_errors() {
        let mut out = Vec::new();
        assert!(run(&mut out, &FakeDns(vec![]), &["-t".into()]).is_err());
    }

    #[test]
    fn strips_url_scheme_and_path() {
        assert_eq!(strip_url("https://example.com/foo?x=1"), "example.com");
        assert_eq!(strip_url("http://example.com"), "example.com");
        assert_eq!(strip_url("example.com"), "example.com");
    }

    #[test]
    fn accepts_url_as_domain() {
        let mut out = Vec::new();
        let dns = FakeDns(vec![Ipv4Addr::new(1, 2, 3, 4)]);
        run(&mut out, &dns, &["https://example.com/path".into()]).unwrap();
        assert_eq!(out, b"1.2.3.4\n");
    }
}
