use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::time::Duration;

use crate::deps::{Dns, Icmp};

pub fn run(
    out: &mut impl Write,
    icmp: &impl Icmp,
    dns: &impl Dns,
    args: &[String],
) -> io::Result<()> {
    let (host, count) = parse_args(args)?;

    let dest: Ipv4Addr = host.parse().or_else(|_| {
        dns.lookup_a(&host)?
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::other("no A records found"))
    })?;

    writeln!(out, "PING {host} ({dest})")?;

    const PAYLOAD: &[u8] = b"hakohakohakohako";
    let mut rtts: Vec<f64> = Vec::new();

    for seq in 1..=count {
        match icmp.send_ping(dest, seq, PAYLOAD) {
            Ok(rtt) => {
                let ms = rtt.as_secs_f64() * 1000.0;
                writeln!(
                    out,
                    "{} bytes from {dest}: icmp_seq={seq} time={ms:.3} ms",
                    8 + PAYLOAD.len()
                )?;
                rtts.push(ms);
            }
            Err(e) => writeln!(out, "Request timeout for icmp_seq={seq}: {e}")?,
        }
        if seq < count {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    let sent = count as usize;
    if sent == 0 {
        return Ok(());
    }

    let recv = rtts.len();
    let loss = (sent - recv) * 100 / sent;
    writeln!(out)?;
    writeln!(out, "--- {host} ping statistics ---")?;
    writeln!(
        out,
        "{sent} packets transmitted, {recv} received, {loss}% packet loss"
    )?;
    if !rtts.is_empty() {
        let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let avg = rtts.iter().sum::<f64>() / recv as f64;
        writeln!(
            out,
            "round-trip min/avg/max = {min:.3}/{avg:.3}/{max:.3} ms"
        )?;
    }

    Ok(())
}

fn parse_args(args: &[String]) -> io::Result<(String, u16)> {
    if args.is_empty() {
        return Err(io::Error::other("usage: ping <host> [-c count]"));
    }
    let host = args[0].clone();
    let count = args
        .windows(2)
        .find(|w| w[0] == "-c")
        .and_then(|w| w[1].parse::<u16>().ok())
        .unwrap_or(4);
    Ok((host, count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{FailIcmp, FakeDns, FakeIcmp};

    #[test]
    fn ping_ip_prints_rtt() {
        let mut out = Vec::new();
        run(
            &mut out,
            &FakeIcmp(Duration::from_millis(15)),
            &FakeDns(vec![]),
            &["1.2.3.4".into(), "-c".into(), "1".into()],
        )
        .unwrap();
        let body = String::from_utf8(out).unwrap();
        assert!(body.contains("time=15.000 ms"));
        assert!(body.contains("1 packets transmitted, 1 received, 0% packet loss"));
    }

    #[test]
    fn resolves_hostname() {
        let mut out = Vec::new();
        run(
            &mut out,
            &FakeIcmp(Duration::from_millis(5)),
            &FakeDns(vec![Ipv4Addr::new(1, 2, 3, 4)]),
            &["example.com".into(), "-c".into(), "1".into()],
        )
        .unwrap();
        let body = String::from_utf8(out).unwrap();
        assert!(body.contains("PING example.com (1.2.3.4)"));
        assert!(body.contains("from 1.2.3.4"));
    }

    #[test]
    fn timeout_counted_as_loss() {
        let mut out = Vec::new();
        run(
            &mut out,
            &FailIcmp,
            &FakeDns(vec![]),
            &["1.2.3.4".into(), "-c".into(), "1".into()],
        )
        .unwrap();
        let body = String::from_utf8(out).unwrap();
        assert!(body.contains("1 packets transmitted, 0 received, 100% packet loss"));
    }

    #[test]
    fn parse_args_defaults_count() {
        let (host, count) = parse_args(&["example.com".into()]).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(count, 4);
    }

    #[test]
    fn parse_args_custom_count() {
        let (_, count) = parse_args(&["example.com".into(), "-c".into(), "3".into()]).unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn no_args_errors() {
        assert!(parse_args(&[]).is_err());
    }
}
