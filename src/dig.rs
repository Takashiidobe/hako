use std::io::{self, Write};

use crate::deps::Dns;

pub fn run(out: &mut impl Write, dns: &impl Dns, args: &[String]) -> io::Result<()> {
    let domain = match args {
        [d] => d.as_str(),
        _ => return Err(io::Error::other("usage: dig <domain>")),
    };

    let records = dns.lookup_a(domain)?;
    if records.is_empty() {
        writeln!(out, "{domain}: no A records found")?;
        return Ok(());
    }

    for addr in records {
        writeln!(out, "{addr}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Dns;
    use std::net::Ipv4Addr;

    struct FakeDns(Vec<Ipv4Addr>);

    impl Dns for FakeDns {
        fn lookup_a(&self, _domain: &str) -> io::Result<Vec<Ipv4Addr>> {
            Ok(self.0.clone())
        }
    }

    struct FailDns;

    impl Dns for FailDns {
        fn lookup_a(&self, _domain: &str) -> io::Result<Vec<Ipv4Addr>> {
            Err(io::Error::other("timeout"))
        }
    }

    #[test]
    fn prints_each_record() {
        let mut out = Vec::new();
        let dns = FakeDns(vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)]);
        run(&mut out, &dns, &["example.com".into()]).unwrap();
        assert_eq!(out, b"1.2.3.4\n5.6.7.8\n");
    }

    #[test]
    fn no_records() {
        let mut out = Vec::new();
        run(&mut out, &FakeDns(vec![]), &["empty.example".into()]).unwrap();
        assert_eq!(out, b"empty.example: no A records found\n");
    }

    #[test]
    fn dns_error_propagates() {
        let mut out = Vec::new();
        let err = run(&mut out, &FailDns, &["bad.example".into()]).unwrap_err();
        assert_eq!(err.to_string(), "timeout");
    }

    #[test]
    fn wrong_arg_count_errors() {
        let mut out = Vec::new();
        assert!(run(&mut out, &FakeDns(vec![]), &[]).is_err());
        assert!(run(&mut out, &FakeDns(vec![]), &["a".into(), "b".into()]).is_err());
    }
}
