use std::io::{self, Write};
use std::net::Ipv4Addr;

use crate::deps::Dns;

pub fn run(out: &mut impl Write, dns: &impl Dns, args: &[String]) -> io::Result<()> {
    let ip = match args {
        [ip] => ip.as_str(),
        _ => return Err(io::Error::other("usage: dnsname <ip>")),
    };
    let addr: Ipv4Addr = ip
        .parse()
        .map_err(|_| io::Error::other("invalid IPv4 address"))?;

    let names = dns.lookup_ptr(&addr)?;
    if names.is_empty() {
        writeln!(out, "{ip}: no PTR records found")?;
        return Ok(());
    }
    for name in names {
        writeln!(out, "{name}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{FailDns, FakePtrDns};

    #[test]
    fn prints_each_name() {
        let mut out = Vec::new();
        let dns = FakePtrDns(vec!["host.example.com".into(), "alt.example.com".into()]);
        run(&mut out, &dns, &["1.2.3.4".into()]).unwrap();
        assert_eq!(out, b"host.example.com\nalt.example.com\n");
    }

    #[test]
    fn no_records() {
        let mut out = Vec::new();
        run(&mut out, &FakePtrDns(vec![]), &["1.2.3.4".into()]).unwrap();
        assert_eq!(out, b"1.2.3.4: no PTR records found\n");
    }

    #[test]
    fn dns_error_propagates() {
        let mut out = Vec::new();
        let err = run(&mut out, &FailDns, &["1.2.3.4".into()]).unwrap_err();
        assert_eq!(err.to_string(), "timeout");
    }

    #[test]
    fn invalid_ip_errors() {
        let mut out = Vec::new();
        assert!(run(&mut out, &FakePtrDns(vec![]), &["not-an-ip".into()]).is_err());
    }

    #[test]
    fn wrong_arg_count_errors() {
        let mut out = Vec::new();
        assert!(run(&mut out, &FakePtrDns(vec![]), &[]).is_err());
        assert!(
            run(
                &mut out,
                &FakePtrDns(vec![]),
                &["1.2.3.4".into(), "extra".into()]
            )
            .is_err()
        );
    }
}
