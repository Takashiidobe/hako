use std::io::{self, Write};

use crate::deps::{Redirect, RedirectStep};

pub fn run(out: &mut impl Write, net: &impl Redirect, args: &[String]) -> io::Result<()> {
    let raw = match args {
        [u] => u.as_str(),
        _ => return Err(io::Error::other("usage: redirect <url>")),
    };

    let url = if raw.starts_with("http://") || raw.starts_with("https://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };

    let steps = net.follow(&url)?;
    print_steps(out, &steps)
}

fn print_steps(out: &mut impl Write, steps: &[RedirectStep]) -> io::Result<()> {
    for (i, step) in steps.iter().enumerate() {
        if (300..400).contains(&step.status) {
            let next = steps.get(i + 1).map(|s| s.url.as_str()).unwrap_or("?");
            writeln!(out, "{}  {}  →  {}", step.status, step.url, next)?;
        } else {
            writeln!(out, "{}  {}", step.status, step.url)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeRedirect(Vec<(u16, &'static str)>);

    impl Redirect for FakeRedirect {
        fn follow(&self, _url: &str) -> io::Result<Vec<RedirectStep>> {
            Ok(self
                .0
                .iter()
                .map(|&(status, url)| RedirectStep { status, url: url.to_string() })
                .collect())
        }
    }

    #[test]
    fn prints_direct_response() {
        let net = FakeRedirect(vec![(200, "http://example.com")]);
        let mut out = Vec::new();
        run(&mut out, &net, &["http://example.com".into()]).unwrap();
        assert_eq!(out, b"200  http://example.com\n");
    }

    #[test]
    fn prints_redirect_chain() {
        let net = FakeRedirect(vec![
            (301, "http://example.com"),
            (200, "https://example.com/"),
        ]);
        let mut out = Vec::new();
        run(&mut out, &net, &["http://example.com".into()]).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "301  http://example.com  →  https://example.com/\n\
             200  https://example.com/\n"
        );
    }

    #[test]
    fn auto_prefixes_http_scheme() {
        struct CaptureFake(std::cell::Cell<String>);
        impl Redirect for CaptureFake {
            fn follow(&self, url: &str) -> io::Result<Vec<RedirectStep>> {
                self.0.set(url.to_string());
                Ok(vec![RedirectStep { status: 200, url: url.to_string() }])
            }
        }
        let net = CaptureFake(std::cell::Cell::new(String::new()));
        let mut out = Vec::new();
        run(&mut out, &net, &["example.com".into()]).unwrap();
        assert_eq!(net.0.take(), "http://example.com");
    }

    #[test]
    fn wrong_args_error() {
        let net = FakeRedirect(vec![]);
        let mut out = Vec::new();
        assert!(run(&mut out, &net, &[]).is_err());
        assert!(run(&mut out, &net, &["a".into(), "b".into()]).is_err());
    }
}
