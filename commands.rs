macro_rules! hako_commands {
    ($command:ident, $out:ident, $rest:ident) => {
        hako_commands!(@commands $command, [], $out, $rest);
    };
    ($command:ident, $out:ident, $rest:ident, $ctx:ident) => {
        hako_commands!(@commands $command, [$ctx], $out, $rest);
    };
    (@call $command:ident, [], $name:ident, $desc:expr, [$($arg:expr),* $(,)?], $run:block) => {
        $command!($name, $desc, [$($arg),*], $run);
    };
    (@call $command:ident, [$ctx:ident], $name:ident, $desc:expr, [$($arg:expr),* $(,)?], $run:block) => {
        $command!($ctx, $name, $desc, [$($arg),*], $run);
    };
    (@commands $command:ident, [$($ctx:ident)?], $out:ident, $rest:ident) => {
        hako_commands!(@call $command, [$($ctx)?], hello, "print hello", [], { hello::run($out, &$rest) });
        hako_commands!(@call $command, [$($ctx)?], time, "print current time", [], { time::run($out, &SystemClock) });
        hako_commands!(@call $command, [$($ctx)?], rand, "print random number", [], { rand::run($out, &mut SystemRng::new()) });
        hako_commands!(@call $command, [$($ctx)?], sleep, "sleep for duration", [], { sleep::run($out, &SystemClock, &$rest) });
        hako_commands!(@call $command, [$($ctx)?], overwrite, "overwrite file contents", [arg_file("file", "file")], {
            overwrite::run($out, &SystemFs, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], asn, "look up ASN for IP", [arg_value("target", "IP or host")], {
            let (dns, r) = dig_dns(&$rest);
            asn::run($out, &dns, &TcpWhois, &r)
        });
        hako_commands!(@call $command, [$($ctx)?], calc, "evaluate math expressions", [], {
            calc::run(io::stdin().lock(), $out, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], dig, "DNS lookup", [arg_short_long_value("type", 't', "type", "type", "record type (A, AAAA, MX, TXT, NS, CNAME)"), arg_value("domain", "domain")], {
            let (dns, r) = dig_dns(&$rest);
            dig::run($out, &dns, &r)
        });
        hako_commands!(@call $command, [$($ctx)?], dnsname, "reverse DNS lookup", [arg_value("ip", "IP address")], {
            let (dns, _) = dig_dns(&$rest);
            dnsname::run($out, &dns, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], httpserver, "serve a directory over HTTP", [arg_long_flag("tls", "enable TLS"), arg_file("directory", "directory"), arg_value("port", "port")], {
            httpserver::run($out, SystemFs, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], tar, "create or extract tar archives", [arg_file("file", "file")], {
            tar::run($out, &SystemFs, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], env, "print environment variables", [], {
            env::run($out, &SystemEnv, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], which, "locate a command", [arg_value("command", "command")], {
            which::run($out, &SystemEnv, &SystemFs, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], whois, "WHOIS lookup", [arg_short_value("server", 'h', "server", "whois server"), arg_value("query", "query")], {
            whois::run($out, &TcpWhois, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], hostname, "print hostname", [], { hostname::run($out, &SystemInfo) });
        hako_commands!(@call $command, [$($ctx)?], uname, "print system info", [
            arg_short_flag("all", 'a', "all info"),
            arg_short_flag("sysname", 's', "kernel name"),
            arg_short_flag("nodename", 'n', "node name"),
            arg_short_flag("release", 'r', "kernel release"),
            arg_short_flag("version", 'v', "kernel version"),
            arg_short_flag("machine", 'm', "machine hardware")
        ], {
            uname::run($out, &SystemInfo, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], fetch, "HTTP client", [
            arg_short_long_value("request", 'X', "request", "method", "HTTP method"),
            arg_short_long_value("data", 'd', "data", "body", "request body"),
            arg_value("url", "URL")
        ], {
            fetch::run($out, &SystemNet, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], ping, "ping a host", [arg_short_value("count", 'c', "count", "packet count"), arg_value("host", "host")], {
            let (dns, r) = dig_dns(&$rest);
            ping::run($out, &SystemIcmp, &dns, &r)
        });
        hako_commands!(@call $command, [$($ctx)?], traceroute, "trace route to host", [
            arg_short_value("max-hops", 'm', "hops", "max hops"),
            arg_short_value("probes", 'q', "probes", "probes per hop"),
            arg_value("host", "host")
        ], {
            let (dns, r) = dig_dns(&$rest);
            traceroute::run($out, &SystemProbe, &dns, &r)
        });
        hako_commands!(@call $command, [$($ctx)?], tlscheck, "inspect TLS certificate", [
            arg_short_value("port", 'p', "port", "port"),
            arg_long_value("name", "name", "name", "SNI name override"),
            arg_long_flag("fingerprint", "show fingerprint"),
            arg_long_flag("cert", "show certificate"),
            arg_long_flag("chain", "show certificate chain"),
            arg_long_flag("expiry", "show expiry date"),
            arg_value("host", "host")
        ], {
            tlscheck::run($out, &SystemNet, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], ciphers, "list supported TLS ciphers", [arg_value("host", "host")], {
            ciphers::run($out, &SystemNet, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], md5sum, "compute MD5 checksum", [arg_file("file", "file")], {
            hash::run($out, &SystemFs, hash::Algo::Md5, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], sha256sum, "compute SHA-256 checksum", [arg_file("file", "file")], {
            hash::run($out, &SystemFs, hash::Algo::Sha256, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], completions, "print shell completions", [arg_value("shell", "shell")], {
            completions::run($out, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], redirect, "trace HTTP redirect chain", [arg_value("url", "URL")], {
            redirect::run($out, &SystemNet, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], certwatch, "batch TLS certificate expiry check", [arg_value("host", "host")], {
            certwatch::run($out, &SystemNet, &$rest)
        });
        hako_commands!(@call $command, [$($ctx)?], tlsping, "measure TCP + TLS handshake latency", [arg_value("host", "host")], {
            tlsping::run($out, &SystemNet, &$rest)
        });
    };
}
