use std::io::{self, Write};
use std::net::Ipv4Addr;

use crate::deps::{Dns, HopResult, Probe};

pub fn run(
    out: &mut impl Write,
    probe: &impl Probe,
    dns: &impl Dns,
    args: &[String],
) -> io::Result<()> {
    let (host, max_hops, nprobes) = parse_args(args)?;

    let host = strip_url(&host);
    let dest: Ipv4Addr = host.parse().or_else(|_| {
        dns.lookup_a(&host)?
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other("no A records found"))
    })?;

    writeln!(out, "traceroute to {host} ({dest}), {max_hops} hops max")?;

    const PAYLOAD: &[u8] = b"hakohako";

    for ttl in 1..=max_hops {
        // Collect results for this TTL before printing so we can show the hop
        // address (from the first reply) at the start of the line.
        let mut hop_addr: Option<Ipv4Addr> = None;
        let mut rtts: Vec<Option<f64>> = Vec::with_capacity(nprobes as usize);
        let mut reached = false;

        for probe_num in 0..nprobes {
            let seq = (ttl as u16).wrapping_mul(3).wrapping_add(probe_num as u16);
            match probe.probe(dest, ttl, seq, PAYLOAD)? {
                HopResult::Reply {
                    from,
                    rtt,
                    reached: r,
                } => {
                    if hop_addr.is_none() {
                        hop_addr = Some(from);
                    }
                    rtts.push(Some(rtt.as_secs_f64() * 1000.0));
                    if r {
                        reached = true;
                    }
                }
                HopResult::Timeout => rtts.push(None),
            }
        }

        // Print the hop line.
        write!(out, "{ttl:>2}  ")?;
        match hop_addr {
            Some(addr) => write!(out, "{addr}")?,
            None => write!(out, "*")?,
        }
        for rtt in &rtts {
            match rtt {
                Some(ms) => write!(out, "  {ms:.3} ms")?,
                None => write!(out, "  *")?,
            }
        }
        writeln!(out)?;

        if reached {
            break;
        }
    }

    Ok(())
}

/// Strip scheme and path from a URL-shaped argument, leaving just the host.
/// "https://example.com/path" → "example.com"
/// "example.com" → "example.com"
fn strip_url(s: &str) -> String {
    let without_scheme = s.split_once("://").map(|(_, rest)| rest).unwrap_or(s);
    without_scheme
        .split(['/', '?', '#', ':'])
        .next()
        .unwrap_or(without_scheme)
        .to_string()
}

fn parse_args(args: &[String]) -> io::Result<(String, u8, u8)> {
    const USAGE: &str = "usage: traceroute <host> [-m max_hops] [-q nprobes]";
    let mut host: Option<String> = None;
    let mut max_hops: u8 = 30;
    let mut nprobes: u8 = 3;
    let mut i = 0;

    while let Some(arg) = args.get(i) {
        match arg.as_str() {
            "-m" => {
                i += 1;
                max_hops = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .ok_or_else(|| io::Error::other(USAGE))?;
            }
            "-q" => {
                i += 1;
                nprobes = args
                    .get(i)
                    .and_then(|v| v.parse::<u8>().ok())
                    .filter(|&n| n > 0)
                    .ok_or_else(|| io::Error::other(USAGE))?;
            }
            arg if !arg.starts_with('-') && host.is_none() => {
                host = Some(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    Ok((
        host.ok_or_else(|| io::Error::other(USAGE))?,
        max_hops,
        nprobes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{FakeDns, FakeProbe};
    use std::time::Duration;

    #[test]
    fn reaches_destination_in_two_hops() {
        let dns = FakeDns(vec![]);
        let probe = FakeProbe::new(vec![
            // ttl=1: Time Exceeded from 10.0.0.1
            HopResult::Reply {
                from: Ipv4Addr::new(10, 0, 0, 1),
                rtt: Duration::from_millis(1),
                reached: false,
            },
            HopResult::Reply {
                from: Ipv4Addr::new(10, 0, 0, 1),
                rtt: Duration::from_millis(2),
                reached: false,
            },
            HopResult::Reply {
                from: Ipv4Addr::new(10, 0, 0, 1),
                rtt: Duration::from_millis(3),
                reached: false,
            },
            // ttl=2: Echo Reply from destination
            HopResult::Reply {
                from: Ipv4Addr::new(1, 2, 3, 4),
                rtt: Duration::from_millis(10),
                reached: true,
            },
            HopResult::Reply {
                from: Ipv4Addr::new(1, 2, 3, 4),
                rtt: Duration::from_millis(11),
                reached: true,
            },
            HopResult::Reply {
                from: Ipv4Addr::new(1, 2, 3, 4),
                rtt: Duration::from_millis(12),
                reached: true,
            },
        ]);

        let mut out = Vec::new();
        run(&mut out, &probe, &dns, &["1.2.3.4".into()]).unwrap();

        let body = String::from_utf8(out).unwrap();
        assert!(body.starts_with("traceroute to 1.2.3.4 (1.2.3.4), 30 hops max\n"));
        assert!(body.contains(" 1  10.0.0.1"));
        assert!(body.contains(" 2  1.2.3.4"));
        // stops after reaching destination — only 2 hop lines
        let hop_lines: Vec<&str> = body.lines().skip(1).collect();
        assert_eq!(hop_lines.len(), 2);
    }

    #[test]
    fn resolves_hostname() {
        let dns = FakeDns(vec![Ipv4Addr::new(5, 6, 7, 8)]);
        let probe = FakeProbe::new(vec![
            HopResult::Reply {
                from: Ipv4Addr::new(5, 6, 7, 8),
                rtt: Duration::from_millis(5),
                reached: true,
            },
            HopResult::Reply {
                from: Ipv4Addr::new(5, 6, 7, 8),
                rtt: Duration::from_millis(5),
                reached: true,
            },
            HopResult::Reply {
                from: Ipv4Addr::new(5, 6, 7, 8),
                rtt: Duration::from_millis(5),
                reached: true,
            },
        ]);

        let mut out = Vec::new();
        run(&mut out, &probe, &dns, &["example.com".into()]).unwrap();

        let body = String::from_utf8(out).unwrap();
        assert!(body.contains("traceroute to example.com (5.6.7.8)"));
    }

    #[test]
    fn timeouts_print_star() {
        let dns = FakeDns(vec![]);
        let probe = FakeProbe::new(vec![
            HopResult::Timeout,
            HopResult::Timeout,
            HopResult::Timeout,
            HopResult::Reply {
                from: Ipv4Addr::new(1, 2, 3, 4),
                rtt: Duration::from_millis(5),
                reached: true,
            },
            HopResult::Reply {
                from: Ipv4Addr::new(1, 2, 3, 4),
                rtt: Duration::from_millis(5),
                reached: true,
            },
            HopResult::Reply {
                from: Ipv4Addr::new(1, 2, 3, 4),
                rtt: Duration::from_millis(5),
                reached: true,
            },
        ]);

        let mut out = Vec::new();
        run(&mut out, &probe, &dns, &["1.2.3.4".into()]).unwrap();
        let body = String::from_utf8(out).unwrap();
        // First hop line should show * for the address and three * RTTs
        let first_hop = body.lines().nth(1).unwrap();
        assert!(first_hop.contains('*'));
        assert!(!first_hop.contains("ms"));
    }

    #[test]
    fn custom_max_hops_and_nprobes() {
        let dns = FakeDns(vec![]);
        let probe = FakeProbe::new(vec![HopResult::Reply {
            from: Ipv4Addr::new(1, 1, 1, 1),
            rtt: Duration::from_millis(1),
            reached: true,
        }]);

        let mut out = Vec::new();
        run(
            &mut out,
            &probe,
            &dns,
            &[
                "1.2.3.4".into(),
                "-m".into(),
                "5".into(),
                "-q".into(),
                "1".into(),
            ],
        )
        .unwrap();
        let body = String::from_utf8(out).unwrap();
        assert!(body.contains("5 hops max"));
    }

    #[test]
    fn strips_url_scheme_and_path() {
        assert_eq!(strip_url("https://example.com/foo?x=1"), "example.com");
        assert_eq!(strip_url("http://example.com"), "example.com");
        assert_eq!(strip_url("https://example.com:443/"), "example.com");
        assert_eq!(strip_url("example.com"), "example.com");
        assert_eq!(strip_url("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn no_args_errors() {
        let dns = FakeDns(vec![]);
        let probe = FakeProbe::new(vec![]);
        let mut out = Vec::new();
        assert!(run(&mut out, &probe, &dns, &[]).is_err());
    }

    #[test]
    fn parse_args_defaults() {
        let (host, max_hops, nprobes) = parse_args(&["example.com".into()]).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(max_hops, 30);
        assert_eq!(nprobes, 3);
    }

    #[test]
    fn parse_args_flags_after_host() {
        let (host, max_hops, nprobes) = parse_args(&[
            "example.com".into(),
            "-m".into(),
            "10".into(),
            "-q".into(),
            "2".into(),
        ])
        .unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(max_hops, 10);
        assert_eq!(nprobes, 2);
    }

    #[test]
    fn parse_args_flags_before_host() {
        let (host, max_hops, nprobes) = parse_args(&[
            "-m".into(),
            "10".into(),
            "-q".into(),
            "2".into(),
            "example.com".into(),
        ])
        .unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(max_hops, 10);
        assert_eq!(nprobes, 2);
    }
}
