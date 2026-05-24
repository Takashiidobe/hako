mod asn;
mod calc;
mod certwatch;
mod ciphers;
mod completions;
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
mod redirect;
mod sleep;
mod tar;
mod time;
mod tlscheck;
mod tlsping;
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

include!("../commands.rs");

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
    include!(concat!(env!("OUT_DIR"), "/command-names.rs")).to_vec()
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
    let mut result = None;
    macro_rules! dispatch_command {
        ($name:ident, $desc:expr, [$($arg:expr),* $(,)?], $run:block) => {
            if result.is_none() && subcmd == stringify!($name) {
                result = Some($run);
            }
        };
    }

    hako_commands!(dispatch_command, out, rest);

    let result = match result {
        Some(result) => result,
        None => {
            eprintln!("usage: {} <{}> [args...]", cmd, list_commands().join("|"));
            return;
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
