# Hako

(busybox and toybox have box in the name and hako is box in japanese)

Some CLI utils that build in 800KB (currently). The constraint for the
project is to fit every util in under 1.44MB.

```sh
du -sh target/release/hako
800K    target/release/hako
```

| Name                                         | What it does                                                                                                                                                                                                |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hello [name...]`                            | Prints `hello`, or greets the provided names joined with `and`.                                                                                                                                             |
| `time`                                       | Prints the current UTC time as `HH:MM:SS UTC`.                                                                                                                                                              |
| `rand`                                       | Prints a pseudo-random integer from 1 to 100.                                                                                                                                                               |
| `sleep <seconds>`                            | Sleeps for a non-negative integer number of seconds.                                                                                                                                                        |
| `overwrite <src> <dst>`                      | Copies `src` to `dst`, replacing `dst` if it already exists.                                                                                                                                                |
| `dig [@nameserver] <domain>`                 | Looks up IPv4 A records for a domain. The default nameserver is `8.8.8.8`.                                                                                                                                  |
| `httpserver <dir> [port] [--tls]`            | Serves static files from a directory. Defaults to port `8080`, or `8443` with `--tls`. Supports directory listings, `index.html`, redirects for directory paths, `GET`, `HEAD`, and `OPTIONS`.              |
| `tar -tf <archive.tar>`                      | Lists entries in a tar archive.                                                                                                                                                                             |
| `tar -xf <archive.tar>`                      | Extracts regular files and directories from a tar archive, rejecting paths that escape the current directory.                                                                                               |
| `env [name...]`                              | With no args, prints environment variables sorted by name. With args, prints each variable's value.                                                                                                         |
| `which <command>...`                         | Searches `PATH` and prints the first matching file for each command.                                                                                                                                        |
| `whois [-h server] <query>`                  | Queries WHOIS. By default it asks `whois.iana.org` and follows one referral from `refer:` or `whois:`.                                                                                                      |
| `hostname`                                   | Prints the system hostname.                                                                                                                                                                                 |
| `uname [-s] [-n] [-r] [-v] [-m] [-a]`        | Prints system information. With no flags, prints the system name.                                                                                                                                           |
| `fetch [-X METHOD] [-d BODY] <url> [url...]` | Fetches HTTP or HTTPS URLs and writes response bodies to stdout. `-d` sends a body and defaults the method to `POST`; supported methods are `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS`. |
| `ping <host> [-c count]`                     | Sends ICMP echo requests to an IPv4 address or hostname. Defaults to 4 packets and prints packet loss plus min/avg/max round-trip time.                                                                     |
| `tlscheck [--cert\|--chain\|--expiry\|--fingerprint] [--name name] [-p port] <host[:port]>` | Verifies a TLS service and can print certificate summaries, chain summaries, expiration time, or a leaf SHA-256 fingerprint.                                                                                |
| `ciphers <host[:port]>`                      | Probes TLS 1.3 cipher suite support, reporting `ok` or `no` for each of `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, and `TLS_CHACHA20_POLY1305_SHA256`.                                            |
| `md5sum [file...]`                           | Prints MD5 checksums. Reads stdin when no files are given or when a path is `-`.                                                                                                                            |
| `sha256sum [file...]`                        | Prints SHA-256 checksums. Reads stdin when no files are given or when a path is `-`.                                                                                                                        |

## Design

Every dependency of each util is passed in when creating the util,
allowing easy mocking for tests.

## Supporting TLS

This library supports TLS 1.3 (so you can fetch https urls). This is
done with a fork of embedded-tls, to support both AES-GCM and ChaChaPoly
(the three algorithms supported by TLS 1.3). As well, this project
builds the rust stdlib to be smaller for more size savings. It used to
be about ~1.3MB, but by building the stdlib to be panic on abort and
being more spartan, the binary size shrunk to about 800KB, so more
features can be added in.

On the server (httpserver) you can also serve https requests (with a
self-signed cert).
