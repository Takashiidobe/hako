use std::io::{self, Write};

use crate::deps::CipherProbe;

pub fn run(out: &mut impl Write, probe: &impl CipherProbe, args: &[String]) -> io::Result<()> {
    let (host, port) = parse_target(args)?;
    let r = probe.probe_ciphers(&host, port)?;

    let s = |ok: bool| if ok { "ok" } else { "no" };
    writeln!(
        out,
        "TLS_AES_128_GCM_SHA256       {}",
        s(r.aes128_gcm_sha256)
    )?;
    writeln!(
        out,
        "TLS_AES_256_GCM_SHA384       {}",
        s(r.aes256_gcm_sha384)
    )?;
    writeln!(
        out,
        "TLS_CHACHA20_POLY1305_SHA256 {}",
        s(r.chacha20_poly1305_sha256)
    )
}

fn parse_target(args: &[String]) -> io::Result<(String, u16)> {
    let raw = match args {
        [host] => host.as_str(),
        _ => return Err(usage()),
    };

    let without_scheme = raw
        .strip_prefix("https://")
        .or_else(|| raw.strip_prefix("tls://"))
        .unwrap_or(raw);
    let authority = without_scheme.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(usage());
    }

    if authority.matches(':').count() == 1
        && let Some((host, port_str)) = authority.rsplit_once(':')
    {
        if host.is_empty() {
            return Err(usage());
        }
        let port = port_str
            .parse::<u16>()
            .ok()
            .filter(|&p| p != 0)
            .ok_or_else(usage)?;
        return Ok((host.to_string(), port));
    }

    Ok((authority.to_string(), 443))
}

fn usage() -> io::Error {
    io::Error::other("usage: ciphers <host[:port]>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::CipherProbe;
    use crate::deps::net::CipherResult;

    struct AllSupported;

    impl CipherProbe for AllSupported {
        fn probe_ciphers(&self, _host: &str, _port: u16) -> io::Result<CipherResult> {
            Ok(CipherResult {
                aes128_gcm_sha256: true,
                aes256_gcm_sha384: true,
                chacha20_poly1305_sha256: true,
            })
        }
    }

    struct NoneSupported;

    impl CipherProbe for NoneSupported {
        fn probe_ciphers(&self, _host: &str, _port: u16) -> io::Result<CipherResult> {
            Ok(CipherResult {
                aes128_gcm_sha256: false,
                aes256_gcm_sha384: false,
                chacha20_poly1305_sha256: false,
            })
        }
    }

    struct CaptureCipher(std::cell::Cell<(String, u16)>);

    impl CaptureCipher {
        fn new() -> Self {
            Self(std::cell::Cell::new((String::new(), 0)))
        }
        fn captured(&self) -> (String, u16) {
            self.0.replace((String::new(), 0))
        }
    }

    impl CipherProbe for CaptureCipher {
        fn probe_ciphers(&self, host: &str, port: u16) -> io::Result<CipherResult> {
            self.0.set((host.to_string(), port));
            Ok(CipherResult {
                aes128_gcm_sha256: true,
                aes256_gcm_sha384: true,
                chacha20_poly1305_sha256: true,
            })
        }
    }

    #[test]
    fn prints_all_ok() {
        let mut out = Vec::new();
        run(&mut out, &AllSupported, &["example.com".into()]).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "TLS_AES_128_GCM_SHA256       ok\n\
             TLS_AES_256_GCM_SHA384       ok\n\
             TLS_CHACHA20_POLY1305_SHA256 ok\n"
        );
    }

    #[test]
    fn prints_all_no() {
        let mut out = Vec::new();
        run(&mut out, &NoneSupported, &["example.com".into()]).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "TLS_AES_128_GCM_SHA256       no\n\
             TLS_AES_256_GCM_SHA384       no\n\
             TLS_CHACHA20_POLY1305_SHA256 no\n"
        );
    }

    #[test]
    fn default_port_is_443() {
        let probe = CaptureCipher::new();
        let mut out = Vec::new();
        run(&mut out, &probe, &["example.com".into()]).unwrap();
        assert_eq!(probe.captured(), ("example.com".to_string(), 443));
    }

    #[test]
    fn accepts_host_colon_port() {
        let probe = CaptureCipher::new();
        let mut out = Vec::new();
        run(&mut out, &probe, &["example.com:8443".into()]).unwrap();
        assert_eq!(probe.captured(), ("example.com".to_string(), 8443));
    }

    #[test]
    fn accepts_https_url() {
        let probe = CaptureCipher::new();
        let mut out = Vec::new();
        run(&mut out, &probe, &["https://example.com/path".into()]).unwrap();
        assert_eq!(probe.captured(), ("example.com".to_string(), 443));
    }

    #[test]
    fn wrong_args_error() {
        let mut out = Vec::new();
        assert!(run(&mut out, &AllSupported, &[]).is_err());
        assert!(run(&mut out, &AllSupported, &["a".into(), "b".into()]).is_err());
    }
}
