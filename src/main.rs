mod ciphers;
mod deps;
mod dig;
mod dnsname;
mod env;
mod fetch;
mod hash;
mod hello;
mod hostname;
mod httpserver;
#[cfg(test)]
mod mock;
mod overwrite;
mod ping;
mod rand;
mod sleep;
mod tar;
mod time;
mod tlscheck;
mod traceroute;
mod uname;
mod which;
mod whois;

use std::io;
use std::net::Ipv4Addr;

use deps::{
    SystemClock, SystemEnv, SystemFs, SystemIcmp, SystemInfo, SystemNet, SystemProbe, SystemRng,
    TcpWhois, UdpDns,
};

fn dig_dns(args: &[String]) -> (UdpDns, Vec<String>) {
    let ns = args
        .iter()
        .find(|a| a.starts_with('@'))
        .and_then(|a| a.strip_prefix('@'))
        .and_then(|a| a.parse::<Ipv4Addr>().ok())
        .unwrap_or(Ipv4Addr::new(8, 8, 8, 8));
    let rest = args
        .iter()
        .filter(|a| !a.starts_with('@'))
        .cloned()
        .collect();
    (UdpDns { nameserver: ns }, rest)
}

fn list_commands() -> Vec<&'static str> {
    let mut cmds = vec![
        "hello",
        "time",
        "rand",
        "sleep",
        "overwrite",
        "dig",
        "dnsname",
        "httpserver",
        "tar",
        "env",
        "which",
        "whois",
        "hostname",
        "uname",
    ];
    cmds.push("fetch");
    cmds.push("ping");
    cmds.push("traceroute");
    cmds.push("tlscheck");
    cmds.push("ciphers");
    cmds.push("md5sum");
    cmds.push("sha256sum");
    cmds
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    let argv0 = args.remove(0);
    let cmd = std::path::Path::new(&argv0)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if args.first().map(String::as_str) == Some("--list-commands") {
        for c in list_commands() {
            println!("{c}");
        }
        return;
    }

    let known = list_commands();
    let (subcmd, rest): (&str, Vec<String>) = if known.contains(&cmd) {
        (cmd, args)
    } else {
        let subcmd = args.first().map(String::as_str).unwrap_or("");
        let rest = args.iter().skip(1).cloned().collect();
        (subcmd, rest)
    };

    let out = &mut io::stdout();
    let result = match subcmd {
        "hello" => hello::run(out, &rest),
        "time" => time::run(out, &SystemClock),
        "rand" => rand::run(out, &mut SystemRng::new()),
        "sleep" => sleep::run(out, &SystemClock, &rest),
        "overwrite" => overwrite::run(out, &SystemFs, &rest),
        "dig" => {
            let (dns, r) = dig_dns(&rest);
            dig::run(out, &dns, &r)
        }
        "dnsname" => {
            let (dns, _) = dig_dns(&rest);
            dnsname::run(out, &dns, &rest)
        }
        "httpserver" => httpserver::run(out, SystemFs, &rest),
        "tar" => tar::run(out, &SystemFs, &rest),
        "env" => env::run(out, &SystemEnv, &rest),
        "which" => which::run(out, &SystemEnv, &SystemFs, &rest),
        "whois" => whois::run(out, &TcpWhois, &rest),
        "hostname" => hostname::run(out, &SystemInfo),
        "uname" => uname::run(out, &SystemInfo, &rest),
        "fetch" => fetch::run(out, &SystemNet, &rest),
        "ping" => {
            let (dns, r) = dig_dns(&rest);
            ping::run(out, &SystemIcmp, &dns, &r)
        }
        "traceroute" => {
            let (dns, r) = dig_dns(&rest);
            traceroute::run(out, &SystemProbe, &dns, &r)
        }
        "tlscheck" => tlscheck::run(out, &SystemNet, &rest),
        "ciphers" => ciphers::run(out, &SystemNet, &rest),
        "md5sum" => hash::run(out, &SystemFs, hash::Algo::Md5, &rest),
        "sha256sum" => hash::run(out, &SystemFs, hash::Algo::Sha256, &rest),
        _ => {
            eprintln!("usage: {} <{}> [args...]", cmd, list_commands().join("|"));
            return;
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
