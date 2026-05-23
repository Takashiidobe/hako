use std::io::{self, Write};

use crate::deps::Net;

pub fn run(out: &mut impl Write, net: &impl Net, args: &[String]) -> io::Result<()> {
    let request = FetchRequest::parse(args)?;
    fetch_many(out, net, &request)
}

struct FetchRequest<'a> {
    method: &'a str,
    body: &'a [u8],
    urls: Vec<&'a str>,
}

impl<'a> FetchRequest<'a> {
    fn parse(args: &'a [String]) -> io::Result<Self> {
        let mut method = "GET";
        let mut body = [].as_slice();
        let mut urls = Vec::new();
        let mut i = 0;

        while let Some(arg) = args.get(i) {
            match arg.as_str() {
                "-X" | "--request" => {
                    i += 1;
                    method = args.get(i).map(String::as_str).ok_or_else(|| {
                        io::Error::other("usage: fetch [-X METHOD] [-d BODY] <url> [url...]")
                    })?;
                    validate_method(method)?;
                }
                "-d" | "--data" => {
                    i += 1;
                    body = args.get(i).map(String::as_bytes).ok_or_else(|| {
                        io::Error::other("usage: fetch [-X METHOD] [-d BODY] <url> [url...]")
                    })?;
                    if method == "GET" {
                        method = "POST";
                    }
                }
                arg => urls.push(arg),
            }
            i += 1;
        }

        if urls.is_empty() {
            return Err(io::Error::other(
                "usage: fetch [-X METHOD] [-d BODY] <url> [url...]",
            ));
        }

        Ok(Self { method, body, urls })
    }
}

fn validate_method(method: &str) -> io::Result<()> {
    match method {
        "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" => Ok(()),
        _ => Err(io::Error::other("unsupported HTTP method")),
    }
}

fn fetch_many(out: &mut impl Write, net: &impl Net, request: &FetchRequest<'_>) -> io::Result<()> {
    for url in &request.urls {
        out.write_all(&net.request(request.method, url, request.body)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{FailNet, FakeNet};
    use std::cell::RefCell;

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

    #[test]
    fn request_method_is_passed_to_net() {
        let mut out = Vec::new();
        let net = RecordingNet::new(b"ok".to_vec());

        run(
            &mut out,
            &net,
            &["-X".into(), "DELETE".into(), "http://example.com".into()],
        )
        .unwrap();

        assert_eq!(out, b"ok");
        assert_eq!(
            net.calls(),
            vec![(
                "DELETE".to_string(),
                "http://example.com".to_string(),
                vec![]
            )]
        );
    }

    #[test]
    fn data_defaults_to_post_and_is_passed_to_net() {
        let mut out = Vec::new();
        let net = RecordingNet::new(b"created".to_vec());

        run(
            &mut out,
            &net,
            &["-d".into(), "name=hako".into(), "http://example.com".into()],
        )
        .unwrap();

        assert_eq!(out, b"created");
        assert_eq!(
            net.calls(),
            vec![(
                "POST".to_string(),
                "http://example.com".to_string(),
                b"name=hako".to_vec()
            )]
        );
    }

    #[test]
    fn explicit_method_with_data_is_preserved() {
        let mut out = Vec::new();
        let net = RecordingNet::new(b"updated".to_vec());

        run(
            &mut out,
            &net,
            &[
                "-X".into(),
                "PUT".into(),
                "-d".into(),
                "name=hako".into(),
                "http://example.com".into(),
            ],
        )
        .unwrap();

        assert_eq!(
            net.calls(),
            vec![(
                "PUT".to_string(),
                "http://example.com".to_string(),
                b"name=hako".to_vec()
            )]
        );
    }

    #[test]
    fn unsupported_method_errors() {
        let mut out = Vec::new();
        let err = run(
            &mut out,
            &FakeNet(vec![]),
            &["-X".into(), "TRACE".into(), "http://example.com".into()],
        )
        .unwrap_err();

        assert_eq!(err.to_string(), "unsupported HTTP method");
    }

    struct RecordingNet {
        response: Vec<u8>,
        calls: RefCell<Vec<(String, String, Vec<u8>)>>,
    }

    impl RecordingNet {
        fn new(response: Vec<u8>) -> Self {
            Self {
                response,
                calls: RefCell::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(String, String, Vec<u8>)> {
            self.calls.borrow().clone()
        }
    }

    impl Net for RecordingNet {
        fn request(&self, method: &str, url: &str, body: &[u8]) -> io::Result<Vec<u8>> {
            self.calls
                .borrow_mut()
                .push((method.to_string(), url.to_string(), body.to_vec()));
            Ok(self.response.clone())
        }
    }
}
