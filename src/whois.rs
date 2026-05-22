use std::io::{self, Write};

use crate::deps::Whois;

const DEFAULT_SERVER: &str = "whois.iana.org";

pub fn run(out: &mut impl Write, whois: &impl Whois, args: &[String]) -> io::Result<()> {
    let (server, query) = parse_args(args)?;
    let follow_referral = server == DEFAULT_SERVER;

    let response = whois.query(&server, &query)?;

    if follow_referral && let Some(referral) = find_referral(&response) {
        let referred = whois.query(&referral, &query)?;
        out.write_all(referred.as_bytes())?;
        return Ok(());
    }

    out.write_all(response.as_bytes())
}

fn parse_args(args: &[String]) -> io::Result<(String, String)> {
    match args {
        [query] => Ok((DEFAULT_SERVER.to_string(), query.clone())),
        [h, server, query] if h == "-h" => Ok((server.clone(), query.clone())),
        _ => Err(io::Error::other("usage: whois [-h server] <query>")),
    }
}

fn find_referral(response: &str) -> Option<String> {
    response.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        let rest = lower
            .strip_prefix("refer:")
            .or_else(|| lower.strip_prefix("whois:"))?;
        let server = rest.trim();
        if server.is_empty() {
            None
        } else {
            Some(server.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::Whois;

    struct FakeWhois {
        responses: Vec<(&'static str, &'static str)>,
    }

    impl Whois for FakeWhois {
        fn query(&self, server: &str, _query: &str) -> io::Result<String> {
            self.responses
                .iter()
                .find(|(s, _)| *s == server)
                .map(|(_, r)| r.to_string())
                .ok_or_else(|| io::Error::other(format!("no response for {server}")))
        }
    }

    #[test]
    fn follows_referral() {
        let whois = FakeWhois {
            responses: vec![
                (DEFAULT_SERVER, "refer: whois.verisign-grs.com\n"),
                ("whois.verisign-grs.com", "Domain Name: EXAMPLE.COM\n"),
            ],
        };
        let mut out = Vec::new();
        run(&mut out, &whois, &["example.com".into()]).unwrap();
        assert_eq!(out, b"Domain Name: EXAMPLE.COM\n");
    }

    #[test]
    fn no_referral_prints_iana_response() {
        let whois = FakeWhois {
            responses: vec![(DEFAULT_SERVER, "% No referral\nsome data\n")],
        };
        let mut out = Vec::new();
        run(&mut out, &whois, &["example".into()]).unwrap();
        assert_eq!(out, b"% No referral\nsome data\n");
    }

    #[test]
    fn explicit_server_skips_referral() {
        let whois = FakeWhois {
            responses: vec![(
                "whois.verisign-grs.com",
                "refer: should.not.follow\nDomain Name: EXAMPLE.COM\n",
            )],
        };
        let mut out = Vec::new();
        run(
            &mut out,
            &whois,
            &[
                "-h".into(),
                "whois.verisign-grs.com".into(),
                "example.com".into(),
            ],
        )
        .unwrap();
        assert_eq!(out, b"refer: should.not.follow\nDomain Name: EXAMPLE.COM\n");
    }

    #[test]
    fn wrong_args_errors() {
        let whois = FakeWhois { responses: vec![] };
        let mut out = Vec::new();
        assert!(run(&mut out, &whois, &[]).is_err());
        assert!(run(&mut out, &whois, &["-h".into()]).is_err());
    }

    #[test]
    fn parse_args_default_server() {
        let (server, query) = parse_args(&["example.com".into()]).unwrap();
        assert_eq!(server, DEFAULT_SERVER);
        assert_eq!(query, "example.com");
    }

    #[test]
    fn find_referral_matches_refer_and_whois_keys() {
        assert_eq!(
            find_referral("refer: whois.example.com\n").as_deref(),
            Some("whois.example.com")
        );
        assert_eq!(
            find_referral("whois: whois.example.com\n").as_deref(),
            Some("whois.example.com")
        );
        assert_eq!(find_referral("nothing here\n"), None);
    }
}
