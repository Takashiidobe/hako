pub trait Net {
    fn request(&self, method: &str, url: &str, body: &[u8]) -> std::io::Result<Vec<u8>>;
}

pub struct TlsOptions<'a> {
    pub server_name: &'a str,
}

pub struct TlsInfo {
    pub certs: Vec<Vec<u8>>,
    pub verified: bool,
}

pub trait TlsCheck {
    fn check_tls(
        &self,
        host: &str,
        port: u16,
        options: &TlsOptions<'_>,
    ) -> std::io::Result<TlsInfo>;
}

pub struct CipherResult {
    pub aes128_gcm_sha256: bool,
    pub aes256_gcm_sha384: bool,
    pub chacha20_poly1305_sha256: bool,
}

pub trait CipherProbe {
    fn probe_ciphers(&self, host: &str, port: u16) -> std::io::Result<CipherResult>;
}

pub struct SystemNet;

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
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
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

fn parse_http_status(status_line: &str) -> std::io::Result<u16> {
    status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other("invalid HTTP status line"))
}

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

struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[cfg(not(feature = "fetch-smol"))]
fn write_http_request(
    mut stream: impl std::io::Write,
    method: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write!(
        stream,
        "{method} {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n"
    )?;
    if !body.is_empty() {
        write!(stream, "Content-Length: {}\r\n", body.len())?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(body)?;
    stream.flush()
}

#[cfg(not(feature = "fetch-smol"))]
fn sync_http_response(
    mut stream: impl std::io::Read + std::io::Write,
    method: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> std::io::Result<HttpResponse> {
    use std::io::{BufRead, BufReader, Read};

    write_http_request(&mut stream, method, host, path, body)?;
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

#[cfg(all(not(feature = "fetch-smol"), test))]
fn sync_http_exchange(
    stream: impl std::io::Read + std::io::Write,
    method: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let response = sync_http_response(stream, method, host, path, body)?;
    if !(200..300).contains(&response.status) {
        return Err(std::io::Error::other(format!("HTTP {}", response.status)));
    }
    Ok(response.body)
}

#[cfg(feature = "fetch-smol")]
async fn async_http_response<RW>(
    stream: RW,
    method: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> std::io::Result<HttpResponse>
where
    RW: futures_lite::io::AsyncRead + futures_lite::io::AsyncWrite + Unpin,
{
    use futures_lite::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let mut stream = stream;
    let mut request = format!("{method} {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n");
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;
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
    let response = async_http_response(stream, "GET", host, path, &[]).await?;
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
struct SystemCertsVerifier {
    ca_ders: Vec<Vec<u8>>,
    host: Option<String>,
    cert_transcript_hash: Option<Vec<u8>>,
    signing_cert_der: Option<Vec<u8>>,
    cert_ders: Vec<Vec<u8>>,
}

#[cfg(feature = "embedded-tls")]
impl SystemCertsVerifier {
    fn new(ca_ders: Vec<Vec<u8>>) -> Self {
        Self {
            ca_ders,
            host: None,
            cert_transcript_hash: None,
            signing_cert_der: None,
            cert_ders: Vec::new(),
        }
    }
}

#[cfg(feature = "embedded-tls")]
struct SystemTlsProvider<CS: embedded_tls::blocking::TlsCipherSuite> {
    rng: rand_core::OsRng,
    verifier: SystemCertsVerifier,
    _suite: std::marker::PhantomData<CS>,
}

#[cfg(feature = "embedded-tls")]
impl<CS: embedded_tls::blocking::TlsCipherSuite> SystemTlsProvider<CS> {
    fn new(ca_ders: Vec<Vec<u8>>) -> Self {
        Self {
            rng: rand_core::OsRng,
            verifier: SystemCertsVerifier::new(ca_ders),
            _suite: std::marker::PhantomData,
        }
    }
}

#[cfg(feature = "embedded-tls")]
impl<CS: embedded_tls::blocking::TlsCipherSuite> embedded_tls::blocking::CryptoProvider
    for SystemTlsProvider<CS>
{
    type CipherSuite = CS;
    type Signature = &'static [u8];

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut self.rng
    }

    fn verifier(
        &mut self,
    ) -> Result<&mut impl embedded_tls::blocking::TlsVerifier, embedded_tls::TlsError> {
        Ok(&mut self.verifier)
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
impl embedded_tls::blocking::TlsVerifier for SystemCertsVerifier {
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), embedded_tls::TlsError> {
        self.host = Some(hostname.to_string());
        Ok(())
    }

    fn verify_certificate(
        &mut self,
        transcript_hash: &[u8],
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
        self.cert_ders.clear();
        self.cert_ders.push(ee_der.to_vec());
        let intermediates: Vec<&[u8]> = entries
            .filter_map(|e| {
                if let CertificateEntryRef::X509(d) = e {
                    self.cert_ders.push((*d).to_vec());
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

        self.signing_cert_der = Some(ee_der.to_vec());
        self.cert_transcript_hash = Some(transcript_hash.to_vec());
        Ok(())
    }

    fn verify_signature(
        &mut self,
        verify: embedded_tls::blocking::CertificateVerifyRef,
    ) -> Result<(), embedded_tls::TlsError> {
        use embedded_tls::SignatureScheme;

        let transcript_hash = self
            .cert_transcript_hash
            .take()
            .ok_or(embedded_tls::TlsError::InvalidCertificate)?;
        let ee_der = self
            .signing_cert_der
            .take()
            .ok_or(embedded_tls::TlsError::InvalidCertificate)?;

        let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
        let mut msg = Vec::<u8>::with_capacity(64 + ctx_str.len() + 64);
        msg.extend(std::iter::repeat_n(0x20u8, 64));
        msg.extend_from_slice(ctx_str);
        msg.extend_from_slice(&transcript_hash);

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

#[cfg(all(not(feature = "fetch-smol"), feature = "embedded-tls"))]
fn embedded_tls_http_response(
    stream: std::net::TcpStream,
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    body: &[u8],
) -> std::io::Result<HttpResponse> {
    use embedded_io::Error as _;
    use embedded_io_adapters::std::FromStd;
    use embedded_tls::blocking::{
        Aes128GcmSha256, Aes256GcmSha384, Chacha20Poly1305Sha256, TlsConfig, TlsConnection,
        TlsContext, TlsError,
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

        tls.open(TlsContext::new(
            &config,
            SystemTlsProvider::<Aes128GcmSha256>::new(system_ca_ders.clone()),
        ))
        .map(|_| sync_http_response(TlsStd(tls), method, host, path, body))
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

    tls2.open(TlsContext::new(
        &config,
        SystemTlsProvider::<Aes256GcmSha384>::new(system_ca_ders.clone()),
    ))
    .map_err(|e| std::io::Error::other(format!("embedded-tls open: {e}")))?;

    if let Ok(r) = sync_http_response(TlsStd(tls2), method, host, path, body) {
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

    tls3.open(TlsContext::new(
        &config,
        SystemTlsProvider::<Chacha20Poly1305Sha256>::new(system_ca_ders),
    ))
    .map_err(|e| std::io::Error::other(format!("embedded-tls open: {e}")))?;

    sync_http_response(TlsStd(tls3), method, host, path, body)
}

// ── async TLS path ────────────────────────────────────────────────────────────

#[cfg(all(feature = "fetch-smol", feature = "embedded-tls"))]
async fn embedded_tls_async_exchange<S>(
    tls: &mut S,
    method: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> std::io::Result<HttpResponse>
where
    S: embedded_io_async::Read + embedded_io_async::Write,
{
    let mut req = format!("{method} {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n");
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes())
        .await
        .map_err(|_| std::io::Error::other("embedded-tls write failed"))?;
    tls.write_all(body)
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
            Ok(n) => raw.extend_from_slice(
                buf.get(..n)
                    .ok_or_else(|| std::io::Error::other("invalid read length"))?,
            ),
        }
    }

    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| std::io::Error::other("no header end in response"))?;
    let header_bytes = raw
        .get(..sep)
        .ok_or_else(|| std::io::Error::other("no header end in response"))?;
    let header_text =
        std::str::from_utf8(header_bytes).map_err(|_| std::io::Error::other("non-utf8 headers"))?;
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
        body: raw
            .get(sep + 4..)
            .ok_or_else(|| std::io::Error::other("no response body"))?
            .to_vec(),
    })
}

#[cfg(all(feature = "fetch-smol", feature = "embedded-tls"))]
enum AnyAsyncTls<'a> {
    Aes128(
        Box<
            embedded_tls::TlsConnection<
                'a,
                embedded_io_adapters::futures_03::FromFutures<smol::net::TcpStream>,
                embedded_tls::Aes128GcmSha256,
            >,
        >,
    ),
    Aes256(
        Box<
            embedded_tls::TlsConnection<
                'a,
                embedded_io_adapters::futures_03::FromFutures<smol::net::TcpStream>,
                embedded_tls::Aes256GcmSha384,
            >,
        >,
    ),
    Chacha(
        Box<
            embedded_tls::TlsConnection<
                'a,
                embedded_io_adapters::futures_03::FromFutures<smol::net::TcpStream>,
                embedded_tls::Chacha20Poly1305Sha256,
            >,
        >,
    ),
}

#[cfg(all(feature = "fetch-smol", feature = "embedded-tls"))]
impl embedded_io_async::ErrorType for AnyAsyncTls<'_> {
    type Error = embedded_tls::TlsError;
}

#[cfg(all(feature = "fetch-smol", feature = "embedded-tls"))]
impl embedded_io_async::Read for AnyAsyncTls<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self {
            AnyAsyncTls::Aes128(tls) => tls.read(buf).await,
            AnyAsyncTls::Aes256(tls) => tls.read(buf).await,
            AnyAsyncTls::Chacha(tls) => tls.read(buf).await,
        }
    }
}

#[cfg(all(feature = "fetch-smol", feature = "embedded-tls"))]
impl embedded_io_async::Write for AnyAsyncTls<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        match self {
            AnyAsyncTls::Aes128(tls) => tls.write(buf).await,
            AnyAsyncTls::Aes256(tls) => tls.write(buf).await,
            AnyAsyncTls::Chacha(tls) => tls.write(buf).await,
        }
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        match self {
            AnyAsyncTls::Aes128(tls) => tls.flush().await,
            AnyAsyncTls::Aes256(tls) => tls.flush().await,
            AnyAsyncTls::Chacha(tls) => tls.flush().await,
        }
    }
}

#[cfg(all(feature = "fetch-smol", feature = "embedded-tls"))]
async fn embedded_tls_async_http_response(
    stream: smol::net::TcpStream,
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    body: &[u8],
) -> std::io::Result<HttpResponse> {
    use embedded_io_adapters::futures_03::FromFutures;
    use embedded_tls::{
        Aes128GcmSha256, Aes256GcmSha384, Chacha20Poly1305Sha256, TlsConfig, TlsConnection,
        TlsContext,
    };

    let system_ca_ders = load_system_ca_ders();

    {
        let config = TlsConfig::new()
            .with_server_name(host)
            .enable_rsa_signatures();
        let mut rb = [0u8; 16640];
        let mut wb = [0u8; 16640];
        let mut tls =
            TlsConnection::<_, Aes128GcmSha256>::new(FromFutures::new(stream), &mut rb, &mut wb);
        if tls
            .open(TlsContext::new(
                &config,
                SystemTlsProvider::<Aes128GcmSha256>::new(system_ca_ders.clone()),
            ))
            .await
            .is_ok()
        {
            return embedded_tls_async_exchange(
                &mut AnyAsyncTls::Aes128(Box::new(tls)),
                method,
                host,
                path,
                body,
            )
            .await;
        }
    }

    let stream2 = smol::net::TcpStream::connect((host, port)).await?;
    {
        let config = TlsConfig::new()
            .with_server_name(host)
            .enable_rsa_signatures();
        let mut rb = [0u8; 16640];
        let mut wb = [0u8; 16640];
        let mut tls =
            TlsConnection::<_, Aes256GcmSha384>::new(FromFutures::new(stream2), &mut rb, &mut wb);
        if tls
            .open(TlsContext::new(
                &config,
                SystemTlsProvider::<Aes256GcmSha384>::new(system_ca_ders.clone()),
            ))
            .await
            .is_ok()
        {
            return embedded_tls_async_exchange(
                &mut AnyAsyncTls::Aes256(Box::new(tls)),
                method,
                host,
                path,
                body,
            )
            .await;
        }
    }

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
    tls.open(TlsContext::new(
        &config,
        SystemTlsProvider::<Chacha20Poly1305Sha256>::new(system_ca_ders),
    ))
    .await
    .map_err(|e| std::io::Error::other(format!("embedded-tls: {e}")))?;
    embedded_tls_async_exchange(
        &mut AnyAsyncTls::Chacha(Box::new(tls)),
        method,
        host,
        path,
        body,
    )
    .await
}

// ── sync Net impl ─────────────────────────────────────────────────────────────

#[cfg(not(feature = "fetch-smol"))]
fn sync_request(url: &str, method: &str, body: &[u8]) -> std::io::Result<Vec<u8>> {
    sync_request_inner(url, method, body, 0)
}

#[cfg(not(feature = "fetch-smol"))]
fn sync_request_inner(
    url: &str,
    method: &str,
    body: &[u8],
    redirects: usize,
) -> std::io::Result<Vec<u8>> {
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
                sync_http_response(tls_stream, method, &host, &path, body)?,
                url,
                method,
                body,
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
                sync_http_response(
                    rustls::StreamOwned::new(conn, stream),
                    method,
                    &host,
                    &path,
                    body,
                )?,
                url,
                method,
                body,
                redirects,
            );
        }

        #[cfg(all(
            feature = "embedded-tls",
            not(any(feature = "tls-dynamic", feature = "rustls"))
        ))]
        return handle_sync_response(
            embedded_tls_http_response(stream, method, &host, port, &path, body)?,
            url,
            method,
            body,
            redirects,
        );

        #[cfg(not(any(feature = "tls-dynamic", feature = "rustls", feature = "embedded-tls")))]
        return Err(std::io::Error::other(
            "https:// requires the native-tls, rustls, or embedded-tls feature",
        ));
    }

    handle_sync_response(
        sync_http_response(stream, method, &host, &path, body)?,
        url,
        method,
        body,
        redirects,
    )
}

#[cfg(not(feature = "fetch-smol"))]
fn handle_sync_response(
    response: HttpResponse,
    url: &str,
    method: &str,
    body: &[u8],
    redirects: usize,
) -> std::io::Result<Vec<u8>> {
    if (300..400).contains(&response.status) {
        if let Some(next) = redirect_location(&response.headers, url)? {
            return sync_request_inner(&next, method, body, redirects + 1);
        }
    }

    if !(200..300).contains(&response.status) {
        return Err(std::io::Error::other(format!("HTTP {}", response.status)));
    }
    Ok(response.body)
}

#[cfg(not(feature = "fetch-smol"))]
impl Net for SystemNet {
    fn request(&self, method: &str, url: &str, body: &[u8]) -> std::io::Result<Vec<u8>> {
        sync_request(url, method, body)
    }
}

// ── async Net impl ────────────────────────────────────────────────────────────

#[cfg(all(feature = "fetch-smol", test))]
pub(crate) async fn async_get(url: &str) -> std::io::Result<Vec<u8>> {
    async_request(url, "GET", &[]).await
}

#[cfg(feature = "fetch-smol")]
pub(crate) async fn async_request(
    url: &str,
    method: &str,
    body: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut current = url.to_string();
    let mut redirects = 0;

    loop {
        if redirects > 5 {
            return Err(std::io::Error::other("too many redirects"));
        }

        let response = async_request_once(&current, method, body).await?;
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
async fn async_request_once(url: &str, method: &str, body: &[u8]) -> std::io::Result<HttpResponse> {
    let (tls, host, port, path) = parse_url(url)?;
    let stream = smol::net::TcpStream::connect((host.as_str(), port)).await?;
    if tls {
        #[cfg(feature = "tls-dynamic")]
        {
            let tls_stream = async_native_tls::connect(host.as_str(), stream)
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            return async_http_response(tls_stream, method, &host, &path, body).await;
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
            return async_http_response(tls_stream, method, &host, &path, body).await;
        }

        #[cfg(all(
            feature = "embedded-tls",
            not(any(feature = "tls-dynamic", feature = "rustls"))
        ))]
        return embedded_tls_async_http_response(stream, method, &host, port, &path, body).await;

        #[cfg(not(any(feature = "tls-dynamic", feature = "rustls", feature = "embedded-tls")))]
        return Err(std::io::Error::other(
            "https:// requires tls-dynamic, rustls, or embedded-tls",
        ));
    }

    async_http_response(stream, method, &host, &path, body).await
}

#[cfg(feature = "fetch-smol")]
impl Net for SystemNet {
    fn request(&self, method: &str, url: &str, body: &[u8]) -> std::io::Result<Vec<u8>> {
        smol::block_on(async_request(url, method, body))
    }
}

fn connect_tls_socket(
    host: &str,
    port: u16,
    timeout: std::time::Duration,
) -> std::io::Result<std::net::TcpStream> {
    let stream = std::net::TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

#[cfg(feature = "embedded-tls")]
fn embedded_tls_open_suite<CS>(
    stream: std::net::TcpStream,
    host: &str,
    ca_ders: Vec<Vec<u8>>,
) -> std::io::Result<TlsInfo>
where
    CS: embedded_tls::blocking::TlsCipherSuite + 'static,
{
    use embedded_io_adapters::std::FromStd;
    use embedded_tls::blocking::{TlsConfig, TlsConnection, TlsContext};

    let mut read_buf = [0u8; 16640];
    let mut write_buf = [0u8; 16640];
    let config = TlsConfig::new()
        .with_server_name(host)
        .enable_rsa_signatures();
    let mut tls = TlsConnection::<_, CS>::new(FromStd::new(stream), &mut read_buf, &mut write_buf);
    let mut provider = SystemTlsProvider::<CS>::new(ca_ders);

    tls.open(TlsContext::new(&config, &mut provider))
        .map_err(|e| std::io::Error::other(format!("embedded-tls open: {e}")))?;
    Ok(TlsInfo {
        certs: provider.verifier.cert_ders,
        verified: true,
    })
}

#[cfg(feature = "embedded-tls")]
fn embedded_tls_open(
    connect_host: &str,
    server_name: &str,
    port: u16,
    stream: std::net::TcpStream,
) -> std::io::Result<TlsInfo> {
    use embedded_tls::blocking::{Aes128GcmSha256, Aes256GcmSha384, Chacha20Poly1305Sha256};

    let ca_ders = load_system_ca_ders();

    if let Ok(info) =
        embedded_tls_open_suite::<Aes128GcmSha256>(stream, server_name, ca_ders.clone())
    {
        return Ok(info);
    }

    if let Ok(info) = embedded_tls_open_suite::<Aes256GcmSha384>(
        connect_tls_socket(connect_host, port, std::time::Duration::from_secs(10))?,
        server_name,
        ca_ders.clone(),
    ) {
        return Ok(info);
    }

    embedded_tls_open_suite::<Chacha20Poly1305Sha256>(
        connect_tls_socket(connect_host, port, std::time::Duration::from_secs(10))?,
        server_name,
        ca_ders,
    )
}

impl TlsCheck for SystemNet {
    fn check_tls(
        &self,
        host: &str,
        port: u16,
        options: &TlsOptions<'_>,
    ) -> std::io::Result<TlsInfo> {
        #[cfg(feature = "tls-dynamic")]
        {
            let stream = connect_tls_socket(host, port, std::time::Duration::from_secs(1))?;
            let connector = native_tls::TlsConnector::new()
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let tls = connector
                .connect(options.server_name, stream)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            let certs = tls
                .peer_certificate()
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .map(|cert| cert.to_der())
                .transpose()
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .into_iter()
                .collect();
            return Ok(TlsInfo {
                certs,
                verified: true,
            });
        }

        #[cfg(all(feature = "rustls", not(feature = "tls-dynamic")))]
        {
            use rustls::pki_types::ServerName;
            use std::sync::Arc;

            let stream = connect_tls_socket(host, port, std::time::Duration::from_secs(1))?;
            let mut stream = stream;
            let mut root_store = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().certs {
                root_store.add(cert).ok();
            }
            let config = Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
            );
            let server_name = ServerName::try_from(options.server_name)
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .to_owned();
            let mut conn = rustls::ClientConnection::new(config, server_name)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
            while conn.is_handshaking() {
                conn.complete_io(&mut stream)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            let certs = conn
                .peer_certificates()
                .map(|certs| certs.iter().map(|cert| cert.to_vec()).collect())
                .unwrap_or_default();
            return Ok(TlsInfo {
                certs,
                verified: true,
            });
        }

        #[cfg(all(
            feature = "embedded-tls",
            not(any(feature = "tls-dynamic", feature = "rustls"))
        ))]
        let stream = connect_tls_socket(host, port, std::time::Duration::from_secs(1))?;
        #[cfg(all(
            feature = "embedded-tls",
            not(any(feature = "tls-dynamic", feature = "rustls"))
        ))]
        return embedded_tls_open(host, options.server_name, port, stream);

        #[cfg(not(any(feature = "tls-dynamic", feature = "rustls", feature = "embedded-tls")))]
        let _ = (host, port, options);
        #[cfg(not(any(feature = "tls-dynamic", feature = "rustls", feature = "embedded-tls")))]
        Err(std::io::Error::other(
            "tlscheck requires the native-tls, rustls, or embedded-tls feature",
        ))
    }
}

// ── Redirect trait ────────────────────────────────────────────────────────────

pub struct RedirectStep {
    pub status: u16,
    pub url: String,
}

pub trait Redirect {
    fn follow(&self, url: &str) -> std::io::Result<Vec<RedirectStep>>;
}

#[cfg(not(feature = "fetch-smol"))]
fn sync_follow_redirects(start: &str) -> std::io::Result<Vec<RedirectStep>> {
    use std::net::TcpStream;
    use std::time::Duration;

    let mut url = start.to_string();
    let mut steps = Vec::new();

    for _ in 0..=10 {
        let (tls, host, port, path) = parse_url(&url)?;
        let stream = TcpStream::connect((&*host, port))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;

        let response = if tls {
            #[cfg(feature = "embedded-tls")]
            {
                embedded_tls_http_response(stream, "GET", &host, port, &path, &[])?
            }
            #[cfg(not(feature = "embedded-tls"))]
            return Err(std::io::Error::other("https requires embedded-tls"));
        } else {
            sync_http_response(stream, "GET", &host, &path, &[])?
        };

        steps.push(RedirectStep { status: response.status, url: url.clone() });

        if !(300..400).contains(&response.status) {
            return Ok(steps);
        }

        match redirect_location(&response.headers, &url)? {
            Some(next) => url = next,
            None => return Ok(steps),
        }
    }

    Err(std::io::Error::other("too many redirects"))
}

#[cfg(not(feature = "fetch-smol"))]
impl Redirect for SystemNet {
    fn follow(&self, url: &str) -> std::io::Result<Vec<RedirectStep>> {
        sync_follow_redirects(url)
    }
}

#[cfg(feature = "fetch-smol")]
async fn async_follow_redirects(start: &str) -> std::io::Result<Vec<RedirectStep>> {
    let mut url = start.to_string();
    let mut steps = Vec::new();

    for _ in 0..=10 {
        let response = async_request_once(&url, "GET", &[]).await?;
        steps.push(RedirectStep { status: response.status, url: url.clone() });

        if !(300..400).contains(&response.status) {
            return Ok(steps);
        }

        match redirect_location(&response.headers, &url)? {
            Some(next) => url = next,
            None => return Ok(steps),
        }
    }

    Err(std::io::Error::other("too many redirects"))
}

#[cfg(feature = "fetch-smol")]
impl Redirect for SystemNet {
    fn follow(&self, url: &str) -> std::io::Result<Vec<RedirectStep>> {
        smol::block_on(async_follow_redirects(url))
    }
}

// ── TlsPing trait ─────────────────────────────────────────────────────────────

pub struct TlsPingResult {
    pub tcp_ms: u128,
    pub tls_ms: u128,
}

pub trait TlsPing {
    fn ping(&self, host: &str, port: u16) -> std::io::Result<TlsPingResult>;
}

impl TlsPing for SystemNet {
    fn ping(&self, host: &str, port: u16) -> std::io::Result<TlsPingResult> {
        use std::time::Instant;

        let t0 = Instant::now();
        let stream = connect_tls_socket(host, port, std::time::Duration::from_secs(10))?;
        let tcp_ms = t0.elapsed().as_millis();

        #[cfg(feature = "embedded-tls")]
        {
            let t1 = Instant::now();
            embedded_tls_open(host, host, port, stream)?;
            let tls_ms = t1.elapsed().as_millis();
            return Ok(TlsPingResult { tcp_ms, tls_ms });
        }

        #[cfg(not(feature = "embedded-tls"))]
        {
            let _ = stream;
            Err(std::io::Error::other("tlsping requires the embedded-tls feature"))
        }
    }
}

// ── CipherProbe impl ──────────────────────────────────────────────────────────

impl CipherProbe for SystemNet {
    fn probe_ciphers(&self, host: &str, port: u16) -> std::io::Result<CipherResult> {
        #[cfg(feature = "embedded-tls")]
        {
            use embedded_tls::blocking::{
                Aes128GcmSha256, Aes256GcmSha384, Chacha20Poly1305Sha256,
            };

            let timeout = std::time::Duration::from_secs(1);
            let ca_ders = load_system_ca_ders();
            let aes128 = connect_tls_socket(host, port, timeout)
                .and_then(|s| embedded_tls_open_suite::<Aes128GcmSha256>(s, host, ca_ders.clone()))
                .is_ok();
            let aes256 = connect_tls_socket(host, port, timeout)
                .and_then(|s| embedded_tls_open_suite::<Aes256GcmSha384>(s, host, ca_ders.clone()))
                .is_ok();
            let chacha = connect_tls_socket(host, port, timeout)
                .and_then(|s| embedded_tls_open_suite::<Chacha20Poly1305Sha256>(s, host, ca_ders))
                .is_ok();
            Ok(CipherResult {
                aes128_gcm_sha256: aes128,
                aes256_gcm_sha384: aes256,
                chacha20_poly1305_sha256: chacha,
            })
        }

        #[cfg(not(feature = "embedded-tls"))]
        {
            let _ = (host, port);
            Err(std::io::Error::other(
                "ciphers requires the embedded-tls feature",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "fetch-smol"))]
    use std::io::Write;
    use std::io::{Cursor, Read};
    #[cfg(feature = "fetch-smol")]
    use std::pin::Pin;
    #[cfg(feature = "fetch-smol")]
    use std::task::{Context, Poll};

    #[cfg(not(feature = "fetch-smol"))]
    struct SyncTestStream {
        read: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    #[cfg(not(feature = "fetch-smol"))]
    impl SyncTestStream {
        fn new(read: &[u8]) -> Self {
            Self {
                read: Cursor::new(read.to_vec()),
                written: Vec::new(),
            }
        }
    }

    #[cfg(not(feature = "fetch-smol"))]
    impl Read for SyncTestStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buf)
        }
    }

    #[cfg(not(feature = "fetch-smol"))]
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

    #[test]
    fn parse_url_defaults_path_and_port() {
        let (tls, host, port, path) = parse_url("http://example.com").unwrap();
        assert!(!tls);
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_url_preserves_https_path_and_port() {
        let (tls, host, port, path) = parse_url("https://example.com:8443/a/b").unwrap();
        assert!(tls);
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/a/b");
    }

    #[test]
    fn parse_http_status_rejects_malformed_line() {
        let err = parse_http_status("nonsense").unwrap_err();
        assert_eq!(err.to_string(), "invalid HTTP status line");
    }

    #[test]
    fn redirect_location_accepts_absolute_url() {
        let headers = vec![(
            "Location".to_string(),
            "https://example.org/new".to_string(),
        )];
        let next = redirect_location(&headers, "https://example.com/old").unwrap();
        assert_eq!(next.as_deref(), Some("https://example.org/new"));
    }

    #[test]
    fn redirect_location_resolves_absolute_path() {
        let headers = vec![("location".to_string(), "/new".to_string())];
        let next = redirect_location(&headers, "https://example.com/old").unwrap();
        assert_eq!(next.as_deref(), Some("https://example.com/new"));
    }

    #[cfg(not(feature = "fetch-smol"))]
    #[test]
    fn sync_http_exchange_writes_request_and_reads_body() {
        let response = b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut stream = SyncTestStream::new(response);

        let body = sync_http_exchange(&mut stream, "GET", "example.com", "/hello", &[]).unwrap();

        assert_eq!(
            stream.written,
            b"GET /hello HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(body, b"hello");
    }

    #[cfg(not(feature = "fetch-smol"))]
    #[test]
    fn sync_http_exchange_writes_method_and_body() {
        let response = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut stream = SyncTestStream::new(response);

        let body =
            sync_http_exchange(&mut stream, "PUT", "example.com", "/item", b"name=hako").unwrap();

        assert_eq!(
            stream.written,
            b"PUT /item HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 9\r\n\r\nname=hako"
        );
        assert_eq!(body, b"ok");
    }

    #[cfg(not(feature = "fetch-smol"))]
    #[test]
    fn sync_http_exchange_rejects_non_success_status() {
        let response = b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let mut stream = SyncTestStream::new(response);

        let err =
            sync_http_exchange(&mut stream, "GET", "example.com", "/missing", &[]).unwrap_err();

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
    fn async_http_response_writes_method_and_body() {
        let response = b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let mut stream = AsyncTestStream::new(response);

        let body = smol::block_on(async_http_response(
            &mut stream,
            "PATCH",
            "example.com",
            "/item",
            b"name=hako",
        ))
        .unwrap()
        .body;

        assert_eq!(
            stream.written,
            b"PATCH /item HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\nContent-Length: 9\r\n\r\nname=hako"
        );
        assert_eq!(body, b"ok");
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
