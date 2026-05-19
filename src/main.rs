mod deps;
mod dig;
mod hello;
mod httpserver;
mod overwrite;
mod rand;
mod tar;
mod time;
#[cfg(feature = "fetch")]
mod fetch;
#[cfg(feature = "hash")]
mod hash;
#[cfg(feature = "ping")]
mod ping;

use std::env;
use std::io;
use std::net::Ipv4Addr;

use deps::{SystemClock, SystemFs, SystemRng, UdpDns};
#[cfg(feature = "fetch")]
use deps::SystemNet;
#[cfg(feature = "ping")]
use deps::SystemIcmp;

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
    #[allow(unused_mut)]
    let mut cmds = vec!["hello", "time", "rand", "overwrite", "dig", "httpserver"];
    cmds.push("tar");
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
    let mut args: Vec<String> = env::args().collect();
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

    let out = &mut io::stdout();
    let result = match cmd {
        "hello" => hello::run(out, &args),
        "time" => time::run(out, &SystemClock),
        "rand" => rand::run(out, &mut SystemRng::new()),
        "overwrite" => overwrite::run(out, &SystemFs, &args),
        "dig" => {
            let (dns, rest) = dig_dns(&args);
            dig::run(out, &dns, &rest)
        }
        "httpserver" => httpserver::run(out, &SystemFs, &args),
        "tar" => tar::run(out, &SystemFs, &args),
        #[cfg(feature = "fetch")]
        "fetch" => fetch::run(out, &SystemNet, &args),
        #[cfg(feature = "ping")]
        "ping" => {
            let (dns, rest) = dig_dns(&args);
            ping::run(out, &SystemIcmp, &dns, &rest)
        }
        #[cfg(feature = "hash")]
        "md5sum" => hash::run(out, &SystemFs, hash::Algo::Md5, &args),
        #[cfg(feature = "hash")]
        "sha256sum" => hash::run(out, &SystemFs, hash::Algo::Sha256, &args),
        _ => {
            let subcmd = args.first().map(String::as_str).unwrap_or("");
            let rest: Vec<String> = args.iter().skip(1).cloned().collect();
            match subcmd {
                "hello" => hello::run(out, &rest),
                "time" => time::run(out, &SystemClock),
                "rand" => rand::run(out, &mut SystemRng::new()),
                "overwrite" => overwrite::run(out, &SystemFs, &rest),
                "dig" => {
                    let (dns, r) = dig_dns(&rest);
                    dig::run(out, &dns, &r)
                }
                "httpserver" => httpserver::run(out, &SystemFs, &rest),
                "tar" => tar::run(out, &SystemFs, &rest),
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
            }
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
