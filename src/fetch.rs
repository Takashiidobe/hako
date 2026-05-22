use std::io::{self, Write};

use crate::deps::Net;

pub fn run(out: &mut impl Write, net: &impl Net, args: &[String]) -> io::Result<()> {
    match args {
        [] => Err(io::Error::other("usage: fetch <url> [url...]")),
        [url] => {
            // single URL: goes through the Net trait so mocks work in tests
            let body = net.get(url)?;
            out.write_all(&body)
        }
        urls => fetch_many(out, net, urls),
    }
}

fn fetch_many(out: &mut impl Write, net: &impl Net, urls: &[String]) -> io::Result<()> {
    for url in urls {
        out.write_all(&net.get(url)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{FailNet, FakeNet};

    #[test]
    fn prints_body() {
        let mut out = Vec::new();
        let net = FakeNet(b"hello world".to_vec());
        run(&mut out, &net, &["http://example.com".into()]).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn net_error_propagates() {
        let mut out = Vec::new();
        let err = run(&mut out, &FailNet, &["http://bad.example".into()]).unwrap_err();
        assert_eq!(err.to_string(), "connection refused");
    }

    #[test]
    fn no_args_errors() {
        let mut out = Vec::new();
        assert!(run(&mut out, &FakeNet(vec![]), &[]).is_err());
    }

    #[test]
    fn multiple_urls_concatenates_bodies() {
        let mut out = Vec::new();
        let net = FakeNet(b"hi".to_vec());
        run(
            &mut out,
            &net,
            &["http://a.com".into(), "http://b.com".into()],
        )
        .unwrap();
        assert_eq!(out, b"hihi");
    }

    #[test]
    fn multiple_urls_propagates_error() {
        let mut out = Vec::new();
        let err = run(
            &mut out,
            &FailNet,
            &["http://a.com".into(), "http://b.com".into()],
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "connection refused");
    }
}
