mod deps;
mod dig;
mod env;
#[cfg(feature = "fetch")]
mod fetch;
#[cfg(feature = "hash")]
mod hash;
mod hello;
mod hostname;
mod httpserver;
#[cfg(test)]
mod mock;
mod overwrite;
#[cfg(feature = "ping")]
mod ping;
mod rand;
mod sleep;
mod tar;
mod time;
mod uname;
mod which;
mod whois;

use std::io;
use std::net::Ipv4Addr;

#[cfg(feature = "ping")]
use deps::SystemIcmp;
#[cfg(feature = "fetch")]
use deps::SystemNet;
use deps::{SystemClock, SystemEnv, SystemFs, SystemInfo, SystemRng, TcpWhois, UdpDns};

fn dig_dns(args: &[String]) -> (UdpDns, Vec<String>) {
    let ns = args
        .iter()
        .find(|a| a.starts_with('@'))
        .and_then(|a| a[1..].parse::<Ipv4Addr>().ok())
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
        "httpserver",
        "tar",
        "env",
        "which",
        "whois",
        "hostname",
        "uname",
    ];
    #[cfg(feature = "fetch")]
    cmds.push("fetch");
    #[cfg(feature = "ping")]
    cmds.push("ping");
    #[cfg(feature = "hash")]
    {
        cmds.push("md5sum");
        cmds.push("sha256sum");
    }
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
        "httpserver" => httpserver::run(out, &SystemFs, &rest),
        "tar" => tar::run(out, &SystemFs, &rest),
        "env" => env::run(out, &SystemEnv, &rest),
        "which" => which::run(out, &SystemEnv, &SystemFs, &rest),
        "whois" => whois::run(out, &TcpWhois, &rest),
        "hostname" => hostname::run(out, &SystemInfo),
        "uname" => uname::run(out, &SystemInfo, &rest),
        #[cfg(feature = "fetch")]
        "fetch" => fetch::run(out, &SystemNet, &rest),
        #[cfg(feature = "ping")]
        "ping" => {
            let (dns, r) = dig_dns(&rest);
            ping::run(out, &SystemIcmp, &dns, &r)
        }
        #[cfg(feature = "hash")]
        "md5sum" => hash::run(out, &SystemFs, hash::Algo::Md5, &rest),
        #[cfg(feature = "hash")]
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
