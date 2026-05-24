use std::io::{self, Write};

const FISH: &str = r#"# hako fish completions
# install: hako completions fish > ~/.config/fish/completions/hako.fish

complete -c hako -f -n '__fish_use_subcommand' -a 'hello'      -d 'print hello'
complete -c hako -f -n '__fish_use_subcommand' -a 'time'       -d 'print current time'
complete -c hako -f -n '__fish_use_subcommand' -a 'rand'       -d 'print random number'
complete -c hako -f -n '__fish_use_subcommand' -a 'sleep'      -d 'sleep for duration'
complete -c hako -f -n '__fish_use_subcommand' -a 'overwrite'  -d 'overwrite file contents'
complete -c hako -f -n '__fish_use_subcommand' -a 'asn'        -d 'look up ASN for IP'
complete -c hako -f -n '__fish_use_subcommand' -a 'calc'       -d 'evaluate math expressions'
complete -c hako -f -n '__fish_use_subcommand' -a 'dig'        -d 'DNS lookup'
complete -c hako -f -n '__fish_use_subcommand' -a 'dnsname'    -d 'reverse DNS lookup'
complete -c hako -f -n '__fish_use_subcommand' -a 'httpserver' -d 'serve a directory over HTTP'
complete -c hako -f -n '__fish_use_subcommand' -a 'tar'        -d 'create or extract tar archives'
complete -c hako -f -n '__fish_use_subcommand' -a 'env'        -d 'print environment variables'
complete -c hako -f -n '__fish_use_subcommand' -a 'which'      -d 'locate a command'
complete -c hako -f -n '__fish_use_subcommand' -a 'whois'      -d 'WHOIS lookup'
complete -c hako -f -n '__fish_use_subcommand' -a 'hostname'   -d 'print hostname'
complete -c hako -f -n '__fish_use_subcommand' -a 'uname'      -d 'print system info'
complete -c hako -f -n '__fish_use_subcommand' -a 'fetch'      -d 'HTTP client'
complete -c hako -f -n '__fish_use_subcommand' -a 'ping'       -d 'ping a host'
complete -c hako -f -n '__fish_use_subcommand' -a 'traceroute' -d 'trace route to host'
complete -c hako -f -n '__fish_use_subcommand' -a 'tlscheck'   -d 'inspect TLS certificate'
complete -c hako -f -n '__fish_use_subcommand' -a 'ciphers'    -d 'list supported TLS ciphers'
complete -c hako -f -n '__fish_use_subcommand' -a 'md5sum'     -d 'compute MD5 checksum'
complete -c hako -f -n '__fish_use_subcommand' -a 'sha256sum'  -d 'compute SHA-256 checksum'
complete -c hako -f -n '__fish_use_subcommand' -a 'completions' -d 'print shell completions'
complete -c hako -f -n '__fish_use_subcommand' -a 'redirect'    -d 'trace HTTP redirect chain'
complete -c hako -f -n '__fish_use_subcommand' -a 'certwatch'   -d 'batch TLS certificate expiry check'
complete -c hako -f -n '__fish_use_subcommand' -a 'tlsping'     -d 'measure TCP + TLS handshake latency'

# fetch
complete -c hako -f -n '__fish_seen_subcommand_from fetch' -s X -l request -r -d 'HTTP method' -a 'GET POST PUT PATCH DELETE HEAD OPTIONS'
complete -c hako -f -n '__fish_seen_subcommand_from fetch' -s d -l data    -r -d 'request body'

# tlscheck
complete -c hako -f -n '__fish_seen_subcommand_from tlscheck' -s p         -r -d 'port'
complete -c hako -f -n '__fish_seen_subcommand_from tlscheck' -l name      -r -d 'SNI name override'
complete -c hako -f -n '__fish_seen_subcommand_from tlscheck' -l fingerprint  -d 'show fingerprint'
complete -c hako -f -n '__fish_seen_subcommand_from tlscheck' -l cert         -d 'show certificate'
complete -c hako -f -n '__fish_seen_subcommand_from tlscheck' -l chain        -d 'show certificate chain'
complete -c hako -f -n '__fish_seen_subcommand_from tlscheck' -l expiry       -d 'show expiry date'

# uname
complete -c hako -f -n '__fish_seen_subcommand_from uname' -s a -d 'all info'
complete -c hako -f -n '__fish_seen_subcommand_from uname' -s s -d 'kernel name'
complete -c hako -f -n '__fish_seen_subcommand_from uname' -s n -d 'node name'
complete -c hako -f -n '__fish_seen_subcommand_from uname' -s r -d 'kernel release'
complete -c hako -f -n '__fish_seen_subcommand_from uname' -s v -d 'kernel version'
complete -c hako -f -n '__fish_seen_subcommand_from uname' -s m -d 'machine hardware'

# httpserver
complete -c hako -f -n '__fish_seen_subcommand_from httpserver' -l tls -d 'enable TLS'
complete -c hako    -n '__fish_seen_subcommand_from httpserver' -F

# traceroute
complete -c hako -f -n '__fish_seen_subcommand_from traceroute' -s m -r -d 'max hops'
complete -c hako -f -n '__fish_seen_subcommand_from traceroute' -s q -r -d 'probes per hop'

# ping
complete -c hako -f -n '__fish_seen_subcommand_from ping' -s c -r -d 'packet count'

# whois
complete -c hako -f -n '__fish_seen_subcommand_from whois' -s h -r -d 'whois server'

# completions
complete -c hako -f -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish' -d 'shell'

# redirect / certwatch / tlsping — host/URL args, no special flags

# file-completing subcommands
complete -c hako -n '__fish_seen_subcommand_from md5sum sha256sum overwrite tar' -F
"#;

const BASH: &str = r#"# hako bash completions
# install: source <(hako completions bash)
#      or: hako completions bash > /etc/bash_completion.d/hako

_hako() {
    local cur prev subcmd
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    subcmd="${COMP_WORDS[1]}"

    if [[ "$COMP_CWORD" -eq 1 ]]; then
        local cmds="hello time rand sleep overwrite asn calc dig dnsname
                    httpserver tar env which whois hostname uname fetch ping
                    traceroute tlscheck ciphers md5sum sha256sum completions
                    redirect certwatch tlsping"
        COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
        return
    fi

    case "$subcmd" in
        fetch)
            case "$prev" in
                -X|--request)
                    COMPREPLY=( $(compgen -W "GET POST PUT PATCH DELETE HEAD OPTIONS" -- "$cur") )
                    return ;;
                -d|--data) return ;;
            esac
            COMPREPLY=( $(compgen -W "-X --request -d --data" -- "$cur") )
            ;;
        tlscheck)
            case "$prev" in
                -p|--name) return ;;
            esac
            COMPREPLY=( $(compgen -W "-p --name --fingerprint --cert --chain --expiry" -- "$cur") )
            ;;
        uname)
            COMPREPLY=( $(compgen -W "-a -s -n -r -v -m" -- "$cur") )
            ;;
        httpserver)
            case "$prev" in
                httpserver) COMPREPLY=( $(compgen -d -- "$cur") ); return ;;
            esac
            COMPREPLY=( $(compgen -W "--tls" -- "$cur") )
            ;;
        traceroute)
            case "$prev" in
                -m|-q) return ;;
            esac
            COMPREPLY=( $(compgen -W "-m -q" -- "$cur") )
            ;;
        ping)
            case "$prev" in
                -c) return ;;
            esac
            COMPREPLY=( $(compgen -W "-c" -- "$cur") )
            ;;
        whois)
            case "$prev" in
                -h) return ;;
            esac
            COMPREPLY=( $(compgen -W "-h" -- "$cur") )
            ;;
        completions)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") )
            ;;
        md5sum|sha256sum|overwrite|tar)
            COMPREPLY=( $(compgen -f -- "$cur") )
            ;;
    esac
}

complete -F _hako hako
"#;

const ZSH: &str = r#"#compdef hako
# hako zsh completions
# install: hako completions zsh > "${fpath[1]}/_hako"
#          then: autoload -U compinit && compinit

_hako() {
    local state

    _arguments \
        '1: :->subcmd' \
        '*: :->args'

    case "$state" in
        subcmd)
            local subcmds=(
                'hello:print hello'
                'time:print current time'
                'rand:print random number'
                'sleep:sleep for duration'
                'overwrite:overwrite file contents'
                'asn:look up ASN for IP'
                'calc:evaluate math expressions'
                'dig:DNS lookup'
                'dnsname:reverse DNS lookup'
                'httpserver:serve a directory over HTTP'
                'tar:create or extract tar archives'
                'env:print environment variables'
                'which:locate a command'
                'whois:WHOIS lookup'
                'hostname:print hostname'
                'uname:print system info'
                'fetch:HTTP client'
                'ping:ping a host'
                'traceroute:trace route to host'
                'tlscheck:inspect TLS certificate'
                'ciphers:list supported TLS ciphers'
                'md5sum:compute MD5 checksum'
                'sha256sum:compute SHA-256 checksum'
                'completions:print shell completions'
                'redirect:trace HTTP redirect chain'
                'certwatch:batch TLS certificate expiry check'
                'tlsping:measure TCP + TLS handshake latency'
            )
            _describe 'subcommand' subcmds
            ;;
        args)
            case "${words[2]}" in
                fetch)
                    _arguments \
                        '(-X --request)'{-X,--request}'[HTTP method]:method:(GET POST PUT PATCH DELETE HEAD OPTIONS)' \
                        '(-d --data)'{-d,--data}'[request body]:body:' \
                        '*:url:'
                    ;;
                tlscheck)
                    _arguments \
                        '-p[port]:port:' \
                        '--name[SNI name override]:name:' \
                        '--fingerprint[show fingerprint]' \
                        '--cert[show certificate]' \
                        '--chain[show certificate chain]' \
                        '--expiry[show expiry date]' \
                        ':host:'
                    ;;
                uname)
                    _arguments \
                        '-a[all info]' \
                        '-s[kernel name]' \
                        '-n[node name]' \
                        '-r[kernel release]' \
                        '-v[kernel version]' \
                        '-m[machine hardware]'
                    ;;
                httpserver)
                    _arguments \
                        '--tls[enable TLS]' \
                        ':directory:_files -/' \
                        '::port:'
                    ;;
                traceroute)
                    _arguments \
                        '-m[max hops]:hops:' \
                        '-q[probes per hop]:probes:' \
                        ':host:'
                    ;;
                ping)
                    _arguments \
                        '-c[packet count]:count:' \
                        ':host:'
                    ;;
                whois)
                    _arguments \
                        '-h[whois server]:server:' \
                        ':query:'
                    ;;
                completions)
                    _arguments ':shell:(bash zsh fish)'
                    ;;
                md5sum|sha256sum|overwrite|tar)
                    _arguments '*:file:_files'
                    ;;
            esac
            ;;
    esac
}

_hako "$@"
"#;

pub fn run(out: &mut impl Write, args: &[String]) -> io::Result<()> {
    let shell = args.first().map(String::as_str).unwrap_or("");
    let script = match shell {
        "bash" => BASH,
        "zsh" => ZSH,
        "fish" => FISH,
        _ => {
            return Err(io::Error::other(
                "usage: completions <bash|zsh|fish>",
            ));
        }
    };
    out.write_all(script.as_bytes())
}
