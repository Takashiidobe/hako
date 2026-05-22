#[cfg(feature = "fetch")]
pub trait Net {
    fn get(&self, url: &str) -> std::io::Result<Vec<u8>>;
}

#[cfg(feature = "fetch")]
pub struct SystemNet;

#[cfg(all(feature = "fetch-sync", feature = "fetch-smol"))]
compile_error!("fetch-sync cannot be combined with async fetch backends");

#[cfg(all(
    feature = "fetch",
    not(any(feature = "fetch-sync", feature = "fetch-smol"))
))]
compile_error!("enable one of fetch-sync or fetch-smol");

#[cfg(feature = "fetch")]
fn parse_url(url: &str) -> std::io::Result<(bool, String, u16, String)> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(std::io::Error::other(
            "URL must start with http:// or https://",
        ));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| std::io::Error::other("invalid port"))?,
        ),
        None => (authority.to_string(), default_port),
    };
    Ok((tls, host, port, path))
}

#[cfg(feature = "fetch")]
fn parse_http_status(status_line: &str) -> std::io::Result<u16> {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other("invalid HTTP status line"))
}

#[cfg(feature = "fetch")]
fn redirect_location(
    headers: &[(String, String)],
    current_url: &str,
) -> std::io::Result<Option<String>> {
    let Some((_, value)) = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("location"))
    else {
        return Ok(None);
    };

    let location = value.trim();
    if location.starts_with("http://") || location.starts_with("https://") {
        return Ok(Some(location.to_string()));
    }

    let (tls, host, port, path) = parse_url(current_url)?;
    let scheme = if tls { "https" } else { "http" };
    let authority = if (tls && port == 443) || (!tls && port == 80) {
        host
    } else {
        format!("{host}:{port}")
    };

    if location.starts_with('/') {
        Ok(Some(format!("{scheme}://{authority}{location}")))
    } else {
        let base = path.rsplit_once('/').map(|(base, _)| base).unwrap_or("");
        Ok(Some(format!("{scheme}://{authority}{base}/{location}")))
    }
}

#[cfg(any(feature = "fetch-sync", feature = "fetch-smol"))]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[cfg(feature = "fetch-sync")]
fn write_http_request(
    mut stream: impl std::io::Write,
    host: &str,
    path: &str,
) -> std::io::Result<()> {
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )?;
    stream.flush()
}

#[cfg(feature = "fetch-sync")]
fn sync_http_response(
    mut stream: impl std::io::Read + std::io::Write,
    host: &str,
    path: &str,
) -> std::io::Result<HttpResponse> {
    use std::io::{BufRead, BufReader, Read};

    write_http_request(&mut stream, host, path)?;
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status = parse_http_status(&status_line)?;

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.trim_end_matches(['\r', '\n']).split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

#[cfg(all(feature = "fetch-sync", test))]
fn sync_http_exchange(
    stream: impl std::io::Read + std::io::Write,
    host: &str,
    path: &str,
) -> std::io::Result<Vec<u8>> {
    let response = sync_http_response(stream, host, path)?;
    if !(200..300).contains(&response.status) {
        return Err(std::io::Error::other(format!("HTTP {}", response.status)));
    }
    Ok(response.body)
}

#[cfg(feature = "fetch-smol")]
async fn async_http_response<RW>(
    stream: RW,
    host: &str,
    path: &str,
) -> std::io::Result<HttpResponse>
where
    RW: futures_lite::io::AsyncRead + futures_lite::io::AsyncWrite + Unpin,
{
    use futures_lite::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let mut stream = stream;
    stream
        .write_all(
            format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    stream.flush().await?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await?;
    let status = parse_http_status(&status_line)?;

    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.trim_end_matches(['\r', '\n']).split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    let mut body = Vec::new();
    reader.read_to_end(&mut body).await?;
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

#[cfg(all(feature = "fetch-smol", test))]
async fn async_http_exchange<RW>(stream: RW, host: &str, path: &str) -> std::io::Result<Vec<u8>>
where
    RW: futures_lite::io::AsyncRead + futures_lite::io::AsyncWrite + Unpin,
{
    let response = async_http_response(stream, host, path).await?;
    if !(200..300).contains(&response.status) {
        return Err(std::io::Error::other(format!("HTTP {}", response.status)));
    }
    Ok(response.body)
}

// ── shared embedded-tls helpers ───────────────────────────────────────────────

#[cfg(feature = "embedded-tls")]
fn load_system_ca_ders() -> Vec<Vec<u8>> {
    rustls_native_certs::load_native_certs()
        .certs
        .into_iter()
        .map(|c| c.to_vec())
        .collect()
}

// Uses rustls-webpki 0.101 to verify the server cert against the full system CA
// bundle. embedded-tls's built-in CertVerifier only accepts a single CA, so we
// implement TlsVerifier directly.
#[cfg(feature = "embedded-tls")]
struct SystemCertsVerifier<CS: embedded_tls::blocking::TlsCipherSuite> {
    ca_ders: Vec<Vec<u8>>,
    host: Option<String>,
    cert_transcript: Option<CS::Hash>,
    cert_der: Option<Vec<u8>>,
}

#[cfg(feature = "embedded-tls")]
impl<CS: embedded_tls::blocking::TlsCipherSuite> SystemCertsVerifier<CS> {
    fn new(ca_ders: Vec<Vec<u8>>) -> Self {
        Self {
            ca_ders,
            host: None,
            cert_transcript: None,
            cert_der: None,
        }
    }
}

#[cfg(feature = "embedded-tls")]
static CHAIN_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
];

#[cfg(feature = "embedded-tls")]
impl<CS: embedded_tls::blocking::TlsCipherSuite> embedded_tls::blocking::TlsVerifier<CS>
    for SystemCertsVerifier<CS>
{
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), embedded_tls::TlsError> {
        self.host = Some(hostname.to_string());
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript: &CS::Hash,
        _ca: &Option<embedded_tls::blocking::Certificate>,
        cert: embedded_tls::CertificateRef,
    ) -> Result<(), embedded_tls::TlsError> {
        use embedded_tls::CertificateEntryRef;

        let anchors: Vec<webpki::TrustAnchor> = self
            .ca_ders
            .iter()
            .filter_map(|der| webpki::TrustAnchor::try_from_cert_der(der).ok())
            .collect();
        if anchors.is_empty() {
            return Err(embedded_tls::TlsError::InvalidCertificate);
        }

        let mut entries = cert.entries.iter();
        let ee_der = match entries.next() {
            Some(CertificateEntryRef::X509(der)) => *der,
            _ => return Err(embedded_tls::TlsError::InvalidCertificate),
        };
        let intermediates: Vec<&[u8]> = entries
            .filter_map(|e| {
                if let CertificateEntryRef::X509(d) = e {
                    Some(*d)
                } else {
                    None
                }
            })
            .collect();

        let ee_cert = webpki::EndEntityCert::try_from(ee_der)
            .map_err(|_| embedded_tls::TlsError::InvalidCertificate)?;
        let now = webpki::Time::from_seconds_since_unix_epoch(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        ee_cert
            .verify_for_usage(
                CHAIN_SIGALGS,
                &anchors,
                &intermediates,
                now,
                webpki::KeyUsage::server_auth(),
                &[],
            )
            .map_err(|_| embedded_tls::TlsError::InvalidCertificate)?;

        if let Some(ref host) = self.host {
            let subject = webpki::SubjectNameRef::try_from_ascii(host.as_bytes())
                .map_err(|_| embedded_tls::TlsError::InvalidCertificate)?;
            ee_cert
                .verify_is_valid_for_subject_name(subject)
                .map_err(|_| embedded_tls::TlsError::InvalidCertificate)?;
        }

        self.cert_der = Some(ee_der.to_vec());
        self.cert_transcript = Some(transcript.clone());
        Ok(())
    }

    fn verify_signature(
        &mut self,
        verify: embedded_tls::blocking::CertificateVerifyRef,
    ) -> Result<(), embedded_tls::TlsError> {
        use digest::Digest;
        use embedded_tls::SignatureScheme;

        let transcript = self
            .cert_transcript
            .take()
            .ok_or(embedded_tls::TlsError::InvalidCertificate)?;
        let ee_der = self
            .cert_der
            .take()
            .ok_or(embedded_tls::TlsError::InvalidCertificate)?;

        let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
        let mut msg = Vec::<u8>::with_capacity(64 + ctx_str.len() + 64);
        msg.extend(std::iter::repeat_n(0x20u8, 64));
        msg.extend_from_slice(ctx_str);
        msg.extend_from_slice(&transcript.finalize());

        let ee_cert = webpki::EndEntityCert::try_from(ee_der.as_slice())
            .map_err(|_| embedded_tls::TlsError::InvalidSignature)?;
        let alg: &webpki::SignatureAlgorithm = match verify.signature_scheme {
            SignatureScheme::EcdsaSecp256r1Sha256 => &webpki::ECDSA_P256_SHA256,
            SignatureScheme::EcdsaSecp384r1Sha384 => &webpki::ECDSA_P384_SHA384,
            SignatureScheme::RsaPssRsaeSha256 => &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            SignatureScheme::RsaPssRsaeSha384 => &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            SignatureScheme::RsaPssRsaeSha512 => &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
            SignatureScheme::Ed25519 => &webpki::ED25519,
            _ => return Err(embedded_tls::TlsError::InvalidSignature),
        };
        ee_cert
            .verify_signature(alg, &msg, verify.signature)
            .map_err(|_| embedded_tls::TlsError::InvalidSignature)
    }
}

// ── sync TLS path ─────────────────────────────────────────────────────────────

#[cfg(all(feature = "fetch-sync", feature = "embedded-tls"))]
fn embedded_tls_http_response(
    stream: std::net::TcpStream,
    host: &str,
    port: u16,
    path: &str,
) -> std::io::Result<HttpResponse> {
    use embedded_io::Error as _;
    use embedded_io_adapters::std::FromStd;
    use embedded_tls::blocking::{
        Aes128GcmSha256, Aes256GcmSha384, Chacha20Poly1305Sha256, CryptoProvider, TlsConfig,
        TlsConnection, TlsContext, TlsError, TlsVerifier,
    };

    struct TlsStd<T>(T);

    impl<T> std::io::Read for TlsStd<T>
    where
        T: embedded_io::Read<Error = TlsError>,
    {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.0.read(buf) {
                Ok(n) => Ok(n),
                Err(TlsError::ConnectionClosed) => Ok(0),
                Err(TlsError::IoError) => Ok(0),
                Err(e) => Err(std::io::Error::new(
                    e.kind().into(),
                    format!("embedded-tls read: {e}"),
                )),
            }
        }
    }

    impl<T> std::io::Write for TlsStd<T>
    where
        T: embedded_io::Write<Error = TlsError>,
    {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.write(buf).map_err(|e| {
                std::io::Error::new(e.kind().into(), format!("embedded-tls write: {e}"))
            })
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush().map_err(|e| {
                std::io::Error::new(e.kind().into(), format!("embedded-tls flush: {e}"))
            })
        }
    }

    let system_ca_ders = load_system_ca_ders();

    // Attempt 1: Aes128GcmSha256
    let mut read_buf1 = [0u8; 16640];
    let mut write_buf1 = [0u8; 16640];

    let open1 = {
        let config = TlsConfig::new()
            .with_server_name(host)
            .enable_rsa_signatures();

        let mut tls = TlsConnection::<_, Aes128GcmSha256>::new(
            FromStd::new(stream),
            &mut read_buf1,
            &mut write_buf1,
        );

        #[cfg(feature = "embedded-tls")]
        {
            struct P128 {
                rng: rand_core::OsRng,
                verifier: SystemCertsVerifier<Aes128GcmSha256>,
            }
            impl CryptoProvider for P128 {
                type CipherSuite = Aes128GcmSha256;
                type Signature = &'static [u8];
                fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
                    &mut self.rng
                }
                fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
                    Ok(&mut self.verifier)
                }
            }
            tls.open(TlsContext::new(
                &config,
                P128 {
                    rng: rand_core::OsRng,
                    verifier: SystemCertsVerifier::new(system_ca_ders.clone()),
                },
            ))
            .map(|_| sync_http_response(TlsStd(tls), host, path))
        }
    };

    if let Ok(r) = open1 {
        return r;
    }

    // Attempt 2: Aes256GcmSha384
    let stream2 = {
        use std::time::Duration;
        let s = std::net::TcpStream::connect((host, port))?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s
    };

    let mut read_buf2 = [0u8; 16640];
    let mut write_buf2 = [0u8; 16640];

    let config = TlsConfig::new()
        .with_server_name(host)
        .enable_rsa_signatures();

    let mut tls2 = TlsConnection::<_, Aes256GcmSha384>::new(
        FromStd::new(stream2),
        &mut read_buf2,
        &mut write_buf2,
    );

    #[cfg(feature = "embedded-tls")]
    {
        struct P256 {
            rng: rand_core::OsRng,
            verifier: SystemCertsVerifier<Aes256GcmSha384>,
        }
        impl CryptoProvider for P256 {
            type CipherSuite = Aes256GcmSha384;
            type Signature = &'static [u8];
            fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
                &mut self.rng
            }
            fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes256GcmSha384>, TlsError> {
                Ok(&mut self.verifier)
            }
        }
        tls2.open(TlsContext::new(
            &config,
            P256 {
                rng: rand_core::OsRng,
                verifier: SystemCertsVerifier::new(system_ca_ders.clone()),
            },
        ))
        .map_err(|e| std::io::Error::other(format!("embedded-tls open: {e}")))?;
    }

    if let Ok(r) = sync_http_response(TlsStd(tls2), host, path) {
        return Ok(r);
    }

    // Attempt 3: Chacha20Poly1305Sha256
    let stream3 = {
        use std::time::Duration;
        let s = std::net::TcpStream::connect((host, port))?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s
    };

    let mut read_buf3 = [0u8; 16640];
    let mut write_buf3 = [0u8; 16640];

    let config = TlsConfig::new()
        .with_server_name(host)
        .enable_rsa_signatures();

    let mut tls3 = TlsConnection::<_, Chacha20Poly1305Sha256>::new(
        FromStd::new(stream3),
        &mut read_buf3,
        &mut write_buf3,
    );

    #[cfg(feature = "embedded-tls")]
    {
        struct P3 {
            rng: rand_core::OsRng,
            verifier: SystemCertsVerifier<Chacha20Poly1305Sha256>,
        }
        impl CryptoProvider for P3 {
            type CipherSuite = Chacha20Poly1305Sha256;
            type Signature = &'static [u8];
            fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
                &mut self.rng
            }
            fn verifier(
                &mut self,
            ) -> Result<&mut impl TlsVerifier<Chacha20Poly1305Sha256>, TlsError> {
                Ok(&mut self.verifier)
            }
        }
        tls3.open(TlsContext::new(
            &config,
            P3 {
                rng: rand_core::OsRng,
                verifier: SystemCertsVerifier::new(system_ca_ders),
            },
        ))
        .map_err(|e| std::io::Error::other(format!("embedded-tls open: {e}")))?;
    }

    sync_http_response(TlsStd(tls3), host, path)
}

// ── async TLS path ────────────────────────────────────────────────────────────

#[cfg(all(feature = "fetch-smol", feature = "embedded-tls"))]
async fn embedded_tls_async_exchange<S>(
    tls: &mut S,
    host: &str,
    path: &str,
) -> std::io::Result<HttpResponse>
where
    S: embedded_io_async::Read + embedded_io_async::Write,
{
    let req = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes())
        .await
        .map_err(|_| std::io::Error::other("embedded-tls write failed"))?;
    tls.flush()
        .await
        .map_err(|_| std::io::Error::other("embedded-tls flush failed"))?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
        }
    }

    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("no header end in response"))?;
    let header_text =
        std::str::from_utf8(&raw[..sep]).map_err(|_| std::io::Error::other("non-utf8 headers"))?;
    let mut lines = header_text.lines();
    let status = parse_http_status(lines.next().unwrap_or(""))?;
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok(HttpResponse {
        status,
        headers,
        body: raw[sep + 4..].to_vec(),
    })
}

#[cfg(all(feature = "fetch-smol", feature = "embedded-tls"))]
async fn embedded_tls_async_http_response(
    stream: smol::net::TcpStream,
    host: &str,
    port: u16,
    path: &str,
) -> std::io::Result<HttpResponse> {
    use embedded_io_adapters::futures_03::FromFutures;
    use embedded_tls::{
        Aes128GcmSha256, Aes256GcmSha384, Chacha20Poly1305Sha256, CryptoProvider, TlsConfig,
        TlsConnection, TlsContext, TlsError, TlsVerifier,
    };

    let system_ca_ders = load_system_ca_ders();

    // Attempt 1: Aes128GcmSha256
    {
        let config = TlsConfig::new()
            .with_server_name(host)
            .enable_rsa_signatures();
        let mut rb = [0u8; 16640];
        let mut wb = [0u8; 16640];
        let mut tls =
            TlsConnection::<_, Aes128GcmSha256>::new(FromFutures::new(stream), &mut rb, &mut wb);
        struct P128 {
            rng: rand_core::OsRng,
            verifier: SystemCertsVerifier<Aes128GcmSha256>,
        }
        impl CryptoProvider for P128 {
            type CipherSuite = Aes128GcmSha256;
            type Signature = &'static [u8];
            fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
                &mut self.rng
            }
            fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, TlsError> {
                Ok(&mut self.verifier)
            }
        }
        if tls
            .open(TlsContext::new(
                &config,
                P128 {
                    rng: rand_core::OsRng,
                    verifier: SystemCertsVerifier::new(system_ca_ders.clone()),
                },
            ))
            .await
            .is_ok()
        {
            return embedded_tls_async_exchange(&mut tls, host, path).await;
        }
    }

    // Attempt 2: Aes256GcmSha384
    let stream2 = smol::net::TcpStream::connect((host, port)).await?;
    {
        let config = TlsConfig::new()
            .with_server_name(host)
            .enable_rsa_signatures();
        let mut rb = [0u8; 16640];
        let mut wb = [0u8; 16640];
        let mut tls =
            TlsConnection::<_, Aes256GcmSha384>::new(FromFutures::new(stream2), &mut rb, &mut wb);
        struct P256 {
            rng: rand_core::OsRng,
            verifier: SystemCertsVerifier<Aes256GcmSha384>,
        }
        impl CryptoProvider for P256 {
            type CipherSuite = Aes256GcmSha384;
            type Signature = &'static [u8];
            fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
                &mut self.rng
            }
            fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Aes256GcmSha384>, TlsError> {
                Ok(&mut self.verifier)
            }
        }
        if tls
            .open(TlsContext::new(
                &config,
                P256 {
                    rng: rand_core::OsRng,
                    verifier: SystemCertsVerifier::new(system_ca_ders.clone()),
                },
            ))
            .await
            .is_ok()
        {
            return embedded_tls_async_exchange(&mut tls, host, path).await;
        }
    }

    // Attempt 3: Chacha20Poly1305Sha256
    let stream3 = smol::net::TcpStream::connect((host, port)).await?;
    let config = TlsConfig::new()
        .with_server_name(host)
        .enable_rsa_signatures();
    let mut rb = [0u8; 16640];
    let mut wb = [0u8; 16640];
    let mut tls = TlsConnection::<_, Chacha20Poly1305Sha256>::new(
        FromFutures::new(stream3),
        &mut rb,
        &mut wb,
    );
    struct P3 {
        rng: rand_core::OsRng,
        verifier: SystemCertsVerifier<Chacha20Poly1305Sha256>,
    }
    impl CryptoProvider for P3 {
        type CipherSuite = Chacha20Poly1305Sha256;
        type Signature = &'static [u8];
        fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
            &mut self.rng
        }
        fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Chacha20Poly1305Sha256>, TlsError> {
            Ok(&mut self.verifier)
        }
    }
    tls.open(TlsContext::new(
        &config,
        P3 {
            rng: rand_core::OsRng,
            verifier: SystemCertsVerifier::new(system_ca_ders),
        },
    ))
    .await
    .map_err(|e| std::io::Error::other(format!("embedded-tls: {e}")))?;
    embedded_tls_async_exchange(&mut tls, host, path).await
}

// ── sync Net impl ─────────────────────────────────────────────────────────────

#[cfg(feature = "fetch-sync")]
fn sync_get(url: &str) -> std::io::Result<Vec<u8>> {
    sync_get_inner(url, 0)
}

#[cfg(feature = "fetch-sync")]
fn sync_get_inner(url: &str, redirects: usize) -> std::io::Result<Vec<u8>> {
    use std::net::TcpStream;
    use std::time::Duration;

    if redirects > 5 {
        return Err(std::io::Error::other("too many redirects"));
    }

    let (tls, host, port, path) = parse_url(url)?;
    let stream = TcpStream::connect((&*host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    if tls {
        #[cfg(feature = "tls-dynamic")]
        {
            let connector = native_tls::TlsConnector::new()
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let tls_stream = connector
                .connect(&host, stream)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            return handle_sync_response(
                sync_http_response(tls_stream, &host, &path)?,
                url,
                redirects,
            );
        }

        #[cfg(all(feature = "rustls", not(feature = "tls-dynamic")))]
        {
            use rustls::pki_types::ServerName;
            use std::sync::Arc;

            let mut root_store = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                root_store.add(cert).ok();
            }
            let config = Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            );
            let server_name = ServerName::try_from(host.as_str())
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .to_owned();
            let conn = rustls::ClientConnection::new(config, server_name)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            return handle_sync_response(
                sync_http_response(rustls::StreamOwned::new(conn, stream), &host, &path)?,
                url,
                redirects,
            );
        }

        #[cfg(all(
            feature = "embedded-tls",
            not(any(feature = "tls-dynamic", feature = "rustls"))
        ))]
        return handle_sync_response(
            embedded_tls_http_response(stream, &host, port, &path)?,
            url,
            redirects,
        );

        #[cfg(not(any(feature = "tls-dynamic", feature = "rustls", feature = "embedded-tls")))]
        return Err(std::io::Error::other(
            "https:// requires the native-tls, rustls, or embedded-tls feature",
        ));
    }

    handle_sync_response(sync_http_response(stream, &host, &path)?, url, redirects)
}

#[cfg(feature = "fetch-sync")]
fn handle_sync_response(
    response: HttpResponse,
    url: &str,
    redirects: usize,
) -> std::io::Result<Vec<u8>> {
    if (300..400).contains(&response.status) {
        if let Some(next) = redirect_location(&response.headers, url)? {
            return sync_get_inner(&next, redirects + 1);
        }
    }

    if !(200..300).contains(&response.status) {
        return Err(std::io::Error::other(format!("HTTP {}", response.status)));
    }
    Ok(response.body)
}

#[cfg(feature = "fetch-sync")]
impl Net for SystemNet {
    fn get(&self, url: &str) -> std::io::Result<Vec<u8>> {
        sync_get(url)
    }
}

// ── async Net impl ────────────────────────────────────────────────────────────

#[cfg(feature = "fetch-smol")]
pub(crate) async fn async_get(url: &str) -> std::io::Result<Vec<u8>> {
    let mut current = url.to_string();
    let mut redirects = 0;

    loop {
        if redirects > 5 {
            return Err(std::io::Error::other("too many redirects"));
        }

        let response = async_get_once(&current).await?;
        if (300..400).contains(&response.status)
            && let Some(next) = redirect_location(&response.headers, &current)?
        {
            current = next;
            redirects += 1;
            continue;
        }

        if !(200..300).contains(&response.status) {
            return Err(std::io::Error::other(format!("HTTP {}", response.status)));
        }
        return Ok(response.body);
    }
}

#[cfg(feature = "fetch-smol")]
async fn async_get_once(url: &str) -> std::io::Result<HttpResponse> {
    let (tls, host, port, path) = parse_url(url)?;
    let stream = smol::net::TcpStream::connect((host.as_str(), port)).await?;
    if tls {
        #[cfg(feature = "tls-dynamic")]
        {
            let tls_stream = async_native_tls::connect(host.as_str(), stream)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            return async_http_response(tls_stream, &host, &path).await;
        }

        #[cfg(all(feature = "rustls", not(feature = "tls-dynamic")))]
        {
            use futures_rustls::TlsConnector;
            use rustls::pki_types::ServerName;
            use std::sync::Arc;

            let mut root_store = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                root_store.add(cert).ok();
            }
            let config = Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            );
            let server_name = ServerName::try_from(host.as_str())
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .to_owned();
            let connector = TlsConnector::from(config);
            let tls_stream = connector.connect(server_name, stream).await?;
            return async_http_response(tls_stream, &host, &path).await;
        }

        #[cfg(all(
            feature = "embedded-tls",
            not(any(feature = "tls-dynamic", feature = "rustls"))
        ))]
        return embedded_tls_async_http_response(stream, &host, port, &path).await;

        #[cfg(not(any(feature = "tls-dynamic", feature = "rustls", feature = "embedded-tls")))]
        return Err(std::io::Error::other(
            "https:// requires tls-dynamic, rustls, or embedded-tls",
        ));
    }

    async_http_response(stream, &host, &path).await
}

#[cfg(feature = "fetch-smol")]
impl Net for SystemNet {
    fn get(&self, url: &str) -> std::io::Result<Vec<u8>> {
        smol::block_on(async_get(url))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(any(feature = "fetch-sync", feature = "fetch-smol"))]
    use std::io::Cursor;
    #[cfg(feature = "fetch-smol")]
    use std::io::Read;
    #[cfg(feature = "fetch-sync")]
    use std::io::{Read, Write};
    #[cfg(feature = "fetch-smol")]
    use std::pin::Pin;
    #[cfg(feature = "fetch-smol")]
    use std::task::{Context, Poll};

    #[cfg(feature = "fetch-sync")]
    struct SyncTestStream {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    #[cfg(feature = "fetch-sync")]
    impl SyncTestStream {
        fn new(read: &[u8]) -> Self {
            Self {
                read: Cursor::new(read.to_vec()),
                written: Vec::new(),
            }
        }
    }

    #[cfg(feature = "fetch-sync")]
    impl Read for SyncTestStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buf)
        }
    }

    #[cfg(feature = "fetch-sync")]
    impl Write for SyncTestStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[cfg(feature = "fetch-smol")]
    struct AsyncTestStream {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    #[cfg(feature = "fetch-smol")]
    impl AsyncTestStream {
        fn new(read: &[u8]) -> Self {
            Self {
                read: Cursor::new(read.to_vec()),
                written: Vec::new(),
            }
        }
    }

    #[cfg(feature = "fetch-smol")]
    impl futures_lite::io::AsyncRead for AsyncTestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(self.read.read(buf))
        }
    }

    #[cfg(feature = "fetch-smol")]
    impl futures_lite::io::AsyncWrite for AsyncTestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn parse_url_defaults_path_and_port() {
        let (tls, host, port, path) = parse_url("http://example.com").unwrap();
        assert!(!tls);
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn parse_url_preserves_https_path_and_port() {
        let (tls, host, port, path) = parse_url("https://example.com:8443/a/b").unwrap();
        assert!(tls);
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/a/b");
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn parse_http_status_rejects_malformed_line() {
        let err = parse_http_status("nonsense").unwrap_err();
        assert_eq!(err.to_string(), "invalid HTTP status line");
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn redirect_location_accepts_absolute_url() {
        let headers = vec![(
            "Location".to_string(),
            "https://example.org/new".to_string(),
        )];
        let next = redirect_location(&headers, "https://example.com/old").unwrap();
        assert_eq!(next.as_deref(), Some("https://example.org/new"));
    }

    #[cfg(feature = "fetch")]
    #[test]
    fn redirect_location_resolves_absolute_path() {
        let headers = vec![("location".to_string(), "/new".to_string())];
        let next = redirect_location(&headers, "https://example.com/old").unwrap();
        assert_eq!(next.as_deref(), Some("https://example.com/new"));
    }

    #[cfg(feature = "fetch-sync")]
    #[test]
    fn sync_http_exchange_writes_request_and_reads_body() {
        let response = b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut stream = SyncTestStream::new(response);

        let body = sync_http_exchange(&mut stream, "example.com", "/hello").unwrap();

        assert_eq!(
            stream.written,
            b"GET /hello HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(body, b"hello");
    }

    #[cfg(feature = "fetch-sync")]
    #[test]
    fn sync_http_exchange_rejects_non_success_status() {
        let response = b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let mut stream = SyncTestStream::new(response);

        let err = sync_http_exchange(&mut stream, "example.com", "/missing").unwrap_err();

        assert_eq!(err.to_string(), "HTTP 404");
    }

    #[cfg(feature = "fetch-smol")]
    #[test]
    fn async_http_exchange_writes_request_and_reads_body() {
        let response = b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut stream = AsyncTestStream::new(response);

        let body =
            smol::block_on(async_http_exchange(&mut stream, "example.com", "/hello")).unwrap();

        assert_eq!(
            stream.written,
            b"GET /hello HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(body, b"hello");
    }

    #[cfg(feature = "fetch-smol")]
    #[test]
    fn async_http_exchange_rejects_non_success_status() {
        let response = b"HTTP/1.0 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
        let mut stream = AsyncTestStream::new(response);

        let err =
            smol::block_on(async_http_exchange(&mut stream, "example.com", "/broken")).unwrap_err();

        assert_eq!(err.to_string(), "HTTP 500");
    }

    #[cfg(feature = "fetch-smol")]
    #[test]
    fn async_get_follows_redirect() {
        smol::block_on(async {
            use futures_lite::io::{AsyncReadExt, AsyncWriteExt};

            let listener = smol::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = smol::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buf = [0u8; 256];
                let n = stream.read(&mut buf).await.unwrap();
                assert!(
                    std::str::from_utf8(&buf[..n])
                        .unwrap()
                        .starts_with("GET /old ")
                );
                stream
                    .write_all(b"HTTP/1.0 302 Found\r\nLocation: /new\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
                drop(stream);

                let (mut stream, _) = listener.accept().await.unwrap();
                let n = stream.read(&mut buf).await.unwrap();
                assert!(
                    std::str::from_utf8(&buf[..n])
                        .unwrap()
                        .starts_with("GET /new ")
                );
                stream
                    .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\ndone")
                    .await
                    .unwrap();
                stream.flush().await.unwrap();
            });

            let body = async_get(&format!("http://127.0.0.1:{port}/old"))
                .await
                .unwrap();

            assert_eq!(body, b"done");
            server.await;
        });
    }
}
