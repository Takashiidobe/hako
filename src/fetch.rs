use std::io::{self, Write};

use crate::deps::Net;

pub fn run(out: &mut impl Write, net: &impl Net, args: &[String]) -> io::Result<()> {
    let url = match args {
        [u] => u.as_str(),
        _ => return Err(io::Error::other("usage: fetch <url>")),
    };
    let body = net.get(url)?;
    out.write_all(&body)
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
    fn wrong_arg_count_errors() {
        let mut out = Vec::new();
        assert!(run(&mut out, &FakeNet(vec![]), &[]).is_err());
        assert!(
            run(
                &mut out,
                &FakeNet(vec![]),
                &["http://a.com".into(), "extra".into()]
            )
            .is_err()
        );
    }
}
