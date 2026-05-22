use embedded_io::Error as _;
use embedded_io::{ErrorType, Read as BlockingRead, Write as BlockingWrite};
use embedded_io_async::{Read as AsyncRead, Write as AsyncWrite};
use portable_atomic::AtomicBool;

use aes_gcm::aead::AeadCore;
use digest::Digest;
use digest::generic_array::typenum::Unsigned;
use p256::EncodedPoint;
use p256::ecdh::EphemeralSecret;
use signature::SignerMut;

use crate::CryptoProvider;
use crate::TlsError;
use crate::alert::{Alert, AlertDescription, AlertLevel};
use crate::application_data::ApplicationData;
use crate::buffer::CryptoBuffer;
use crate::common::decrypted_buffer_info::DecryptedBufferInfo;
use crate::common::decrypted_read_handler::DecryptedReadHandler;
use crate::config::{TLS_RECORD_OVERHEAD, TlsCipherSuite, TlsConfig};
use crate::connection::{decrypt_application_data, encrypt_application_data};
use crate::content_types::ContentType;
use crate::flush_policy::FlushPolicy;
use crate::handshake::HandshakeType;
use crate::handshake::certificate::{CertificateEntryRef, CertificateRef};
use crate::handshake::client_hello::ParsedClientHello;
use crate::handshake::encrypted_extensions::encode_empty as encode_empty_extensions;
use crate::handshake::server_hello::encode_server_hello;
use crate::key_schedule::{KeySchedule, ReadKeySchedule, WriteKeySchedule};
use crate::parse_buffer::ParseBuffer;
use crate::read_buffer::ReadBuffer;
use crate::record::{RecordHeader, ServerRecord};
use crate::record_reader::RecordReader;
use crate::write_buffer::WriteBuffer;

// ----- Server-side AEAD helpers ---------------------------------------------

/// Encrypt the contents of `buf` in place using the server write-traffic keys.
/// Mirrors `encrypt()` but pulls keys from `ReadKeySchedule` (which holds the
/// server traffic state from the server's perspective).
pub(crate) fn encrypt_server<CipherSuite>(
    key_schedule: &ReadKeySchedule<CipherSuite>,
    buf: &mut CryptoBuffer<'_>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let server_key = key_schedule.get_key()?;
    let nonce = key_schedule.get_nonce()?;
    encrypt_application_data(CipherSuite::CODE_POINT, server_key, &nonce, buf)
}

/// Decrypt an in-place application data record using the **client** traffic keys.
/// Used by the server to read encrypted handshake messages and application data.
fn decrypt_client_application_data<'a, CipherSuite>(
    key_schedule: &mut WriteKeySchedule<CipherSuite>,
    header: &RecordHeader,
    app_data: &mut CryptoBuffer<'a>,
) -> Result<ContentType, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let client_key = key_schedule.get_key()?;
    let nonce = key_schedule.get_nonce()?;
    decrypt_application_data(
        CipherSuite::CODE_POINT,
        client_key,
        &nonce,
        header.data(),
        app_data,
    )?;

    // strip zero padding
    let padding = app_data
        .as_slice()
        .iter()
        .enumerate()
        .rfind(|(_, b)| **b != 0);
    if let Some((index, _)) = padding {
        app_data.truncate(index + 1);
    }

    let inner_type =
        ContentType::of(*app_data.as_slice().last().ok_or(TlsError::InvalidRecord)?)
            .ok_or(TlsError::InvalidRecord)?;
    app_data.truncate(app_data.len() - 1);

    key_schedule.increment_counter();
    Ok(inner_type)
}

// ----- ClientHello reading --------------------------------------------------

/// Read exactly `len` bytes into `buf` from a blocking transport.
fn read_exact_blocking(transport: &mut impl BlockingRead, buf: &mut [u8]) -> Result<(), TlsError> {
    let mut total = 0;
    while total < buf.len() {
        let n = transport
            .read(&mut buf[total..])
            .map_err(|e| TlsError::Io(e.kind()))?;
        if n == 0 {
            return Err(TlsError::IoError);
        }
        total += n;
    }
    Ok(())
}

async fn read_exact_async(
    transport: &mut impl AsyncRead,
    buf: &mut [u8],
) -> Result<(), TlsError> {
    let mut total = 0;
    while total < buf.len() {
        let n = transport
            .read(&mut buf[total..])
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;
        if n == 0 {
            return Err(TlsError::IoError);
        }
        total += n;
    }
    Ok(())
}

/// Read a raw TLS record (header + body) into `buffer`, returning
/// `(content_type, body_len)`. The body bytes occupy `buffer[5..5+body_len]`.
fn read_record_blocking(
    buffer: &mut [u8],
    transport: &mut impl BlockingRead,
) -> Result<(ContentType, usize), TlsError> {
    if buffer.len() < RecordHeader::LEN {
        return Err(TlsError::InsufficientSpace);
    }
    read_exact_blocking(transport, &mut buffer[..RecordHeader::LEN])?;
    let mut hdr = [0u8; RecordHeader::LEN];
    hdr.copy_from_slice(&buffer[..RecordHeader::LEN]);
    let header = RecordHeader::decode(hdr)?;
    let body_len = header.content_length();
    if RecordHeader::LEN + body_len > buffer.len() {
        return Err(TlsError::InsufficientSpace);
    }
    read_exact_blocking(
        transport,
        &mut buffer[RecordHeader::LEN..RecordHeader::LEN + body_len],
    )?;
    Ok((header.content_type(), body_len))
}

async fn read_record_async(
    buffer: &mut [u8],
    transport: &mut impl AsyncRead,
) -> Result<(ContentType, usize), TlsError> {
    if buffer.len() < RecordHeader::LEN {
        return Err(TlsError::InsufficientSpace);
    }
    read_exact_async(transport, &mut buffer[..RecordHeader::LEN]).await?;
    let mut hdr = [0u8; RecordHeader::LEN];
    hdr.copy_from_slice(&buffer[..RecordHeader::LEN]);
    let header = RecordHeader::decode(hdr)?;
    let body_len = header.content_length();
    if RecordHeader::LEN + body_len > buffer.len() {
        return Err(TlsError::InsufficientSpace);
    }
    read_exact_async(
        transport,
        &mut buffer[RecordHeader::LEN..RecordHeader::LEN + body_len],
    )
    .await?;
    Ok((header.content_type(), body_len))
}

// ----- Server flight encoding ----------------------------------------------

/// Build a TLS record containing a single (possibly multiple) encrypted handshake
/// message(s). Returns the slice ready to send and the encrypted payload range
/// for any further processing.
fn build_encrypted_handshake_record<CipherSuite>(
    buffer: &mut [u8],
    handshake_type: HandshakeType,
    body_writer: impl FnOnce(&mut CryptoBuffer<'_>) -> Result<(), TlsError>,
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<usize, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    const HEADER_SIZE: usize = 5;

    if buffer.len() <= HEADER_SIZE + TLS_RECORD_OVERHEAD {
        return Err(TlsError::InsufficientSpace);
    }

    // outer record header placeholder: ApplicationData / TLS1.2 / len(2)
    buffer[0] = ContentType::ApplicationData as u8;
    buffer[1] = 0x03;
    buffer[2] = 0x03;
    buffer[3] = 0;
    buffer[4] = 0;

    // Build inner plaintext (handshake header + body + inner content type).
    let inner_start = HEADER_SIZE;
    let mut inner_pos = inner_start;

    // Write handshake type and 3-byte length placeholder
    buffer[inner_pos] = handshake_type as u8;
    buffer[inner_pos + 1] = 0;
    buffer[inner_pos + 2] = 0;
    buffer[inner_pos + 3] = 0;
    inner_pos += 4;

    // Write body via CryptoBuffer over remaining space.
    let body_start = inner_pos;
    {
        let mut body_buf = CryptoBuffer::wrap(&mut buffer[body_start..]);
        body_writer(&mut body_buf)?;
        inner_pos = body_start + body_buf.len();
    }

    // Patch in 24-bit length of handshake body
    let body_len = (inner_pos - body_start) as u32;
    let body_len_bytes = body_len.to_be_bytes();
    buffer[inner_start + 1] = body_len_bytes[1];
    buffer[inner_start + 2] = body_len_bytes[2];
    buffer[inner_start + 3] = body_len_bytes[3];

    // Update transcript with the unencrypted handshake message bytes (incl. header).
    key_schedule
        .transcript_hash()
        .update(&buffer[inner_start..inner_pos]);

    // Append inner content type = Handshake.
    if inner_pos >= buffer.len() {
        return Err(TlsError::InsufficientSpace);
    }
    buffer[inner_pos] = ContentType::Handshake as u8;
    inner_pos += 1;

    // Encrypt in place over [inner_start..inner_pos]. We need space for the AEAD tag.
    let inner_plaintext_len = inner_pos - inner_start;
    let tail_space = buffer.len() - inner_pos;
    let tag_size = <<CipherSuite::Cipher as AeadCore>::TagSize as Unsigned>::to_usize();
    if tail_space < tag_size {
        return Err(TlsError::InsufficientSpace);
    }

    // Use CryptoBuffer that owns the entire remaining buffer starting at inner_start.
    let mut enc_buf = CryptoBuffer::wrap(&mut buffer[inner_start..]);
    enc_buf.extend_from_slice(&[]).ok();
    // We need to grow CryptoBuffer's len to inner_plaintext_len without copying.
    // The easiest way is to push bytes that are already present using extend_from_slice
    // — but that copies. Instead, drop the buffer wrap and rebuild via wrap_with_pos.
    drop(enc_buf);
    let mut enc_buf = CryptoBuffer::wrap_with_pos(&mut buffer[inner_start..], inner_plaintext_len);

    // Mirror connection::encrypt() but with server keys.
    let (_, read_state) = key_schedule.as_split();
    encrypt_server(read_state, &mut enc_buf)?;

    let ciphertext_len = enc_buf.len();
    let total_record = HEADER_SIZE + ciphertext_len;

    // Patch outer length field.
    let len_bytes = (ciphertext_len as u16).to_be_bytes();
    buffer[3] = len_bytes[0];
    buffer[4] = len_bytes[1];

    Ok(total_record)
}

/// Write a plaintext ChangeCipherSpec record. Length must be 6 (header+body).
fn write_change_cipher_spec(buffer: &mut [u8]) -> Result<usize, TlsError> {
    let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    if buffer.len() < ccs.len() {
        return Err(TlsError::InsufficientSpace);
    }
    buffer[..ccs.len()].copy_from_slice(&ccs);
    Ok(ccs.len())
}

/// Build a plaintext ServerHello record. Updates transcript with the handshake
/// message body (not the record header). Returns the byte length to send.
fn build_server_hello_record<CipherSuite, Provider>(
    buffer: &mut [u8],
    key_schedule: &mut KeySchedule<CipherSuite>,
    session_id: &[u8],
    server_public_key: &[u8],
    provider: &mut Provider,
) -> Result<usize, TlsError>
where
    CipherSuite: TlsCipherSuite,
    Provider: CryptoProvider,
{
    const HEADER_SIZE: usize = 5;
    if buffer.len() < HEADER_SIZE + 4 {
        return Err(TlsError::InsufficientSpace);
    }

    buffer[0] = ContentType::Handshake as u8;
    buffer[1] = 0x03;
    buffer[2] = 0x03;
    // outer length filled later

    let inner_start = HEADER_SIZE;
    buffer[inner_start] = HandshakeType::ServerHello as u8;
    // 24-bit length placeholder
    buffer[inner_start + 1] = 0;
    buffer[inner_start + 2] = 0;
    buffer[inner_start + 3] = 0;

    let body_start = inner_start + 4;
    let mut body_buf = CryptoBuffer::wrap(&mut buffer[body_start..]);
    encode_server_hello::<CipherSuite>(
        &mut body_buf,
        &mut provider.rng(),
        session_id,
        server_public_key,
    )?;
    let body_len = body_buf.len();
    let body_len_bytes = (body_len as u32).to_be_bytes();
    buffer[inner_start + 1] = body_len_bytes[1];
    buffer[inner_start + 2] = body_len_bytes[2];
    buffer[inner_start + 3] = body_len_bytes[3];

    let hs_total = 4 + body_len;
    let record_len_bytes = (hs_total as u16).to_be_bytes();
    buffer[3] = record_len_bytes[0];
    buffer[4] = record_len_bytes[1];

    // Update transcript with the handshake message bytes (handshake header + body).
    key_schedule
        .transcript_hash()
        .update(&buffer[inner_start..inner_start + hs_total]);

    Ok(HEADER_SIZE + hs_total)
}

// ----- Server handshake -----------------------------------------------------

fn ensure_handshake_buf_room(buf: &[u8]) -> Result<(), TlsError> {
    if buf.len() < TLS_RECORD_OVERHEAD + 256 {
        return Err(TlsError::InsufficientSpace);
    }
    Ok(())
}

/// Run the full server-side TLS 1.3 handshake on a blocking transport. Leaves
/// the key schedule in the application-data state.
fn server_handshake_blocking<'a, Transport, Provider>(
    transport: &mut Transport,
    rx_buf: &mut [u8],
    tx_buf: &mut [u8],
    key_schedule: &mut KeySchedule<Provider::CipherSuite>,
    config: &TlsConfig<'a>,
    provider: &mut Provider,
) -> Result<(), TlsError>
where
    Transport: BlockingRead + BlockingWrite + 'a,
    Provider: CryptoProvider,
{
    ensure_handshake_buf_room(rx_buf)?;
    ensure_handshake_buf_room(tx_buf)?;

    // 1) Read ClientHello
    let (ct, body_len) = read_record_blocking(rx_buf, transport)?;
    if !matches!(ct, ContentType::Handshake) {
        return Err(TlsError::InvalidRecord);
    }
    let client_secret = process_client_hello_and_init(
        &rx_buf[RecordHeader::LEN..RecordHeader::LEN + body_len],
        key_schedule,
        provider,
    )?;

    // 2) Send ServerHello
    let server_public_key = EncodedPoint::from(&client_secret.server_secret.public_key());
    let session_id_owned = client_secret.session_id;
    let session_id = &session_id_owned[..client_secret.session_id_len];

    // Compute ECDH shared secret first before borrowing transcript via build_server_hello.
    let shared = client_secret
        .server_secret
        .diffie_hellman(&client_secret.client_public_key);

    let sh_len = build_server_hello_record(
        tx_buf,
        key_schedule,
        session_id,
        server_public_key.as_ref(),
        provider,
    )?;
    transport
        .write_all(&tx_buf[..sh_len])
        .map_err(|e| TlsError::Io(e.kind()))?;

    // 3) Initialize handshake secrets
    key_schedule.initialize_handshake_secret(shared.raw_secret_bytes())?;

    // 4) Send ChangeCipherSpec
    let ccs_len = write_change_cipher_spec(tx_buf)?;
    transport
        .write_all(&tx_buf[..ccs_len])
        .map_err(|e| TlsError::Io(e.kind()))?;

    // 5) Send EncryptedExtensions (empty)
    let ee_len = build_encrypted_handshake_record(
        tx_buf,
        HandshakeType::EncryptedExtensions,
        |buf| encode_empty_extensions(buf),
        key_schedule,
    )?;
    transport
        .write_all(&tx_buf[..ee_len])
        .map_err(|e| TlsError::Io(e.kind()))?;
    key_schedule.read_state().increment_counter();

    // 6) Send Certificate (from config.cert)
    let cert = config.cert.as_ref().ok_or(TlsError::InvalidCertificate)?;
    let cert_entry = CertificateEntryRef::from(cert);
    let mut cert_msg = CertificateRef::with_context(&[]);
    cert_msg.add(cert_entry)?;
    let cert_len = build_encrypted_handshake_record(
        tx_buf,
        HandshakeType::Certificate,
        |buf| cert_msg.encode(buf),
        key_schedule,
    )?;
    transport
        .write_all(&tx_buf[..cert_len])
        .map_err(|e| TlsError::Io(e.kind()))?;
    key_schedule.read_state().increment_counter();

    // 7) Send CertificateVerify (sign with server private key)
    let (mut signing_key, signature_scheme) = provider
        .signer(config.priv_key)
        .map_err(|_| TlsError::InvalidPrivateKey)?;
    let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
    let mut msg: heapless::Vec<u8, 146> = heapless::Vec::new();
    msg.resize(64, 0x20).map_err(|_| TlsError::EncodeError)?;
    msg.extend_from_slice(ctx_str)
        .map_err(|_| TlsError::EncodeError)?;
    msg.extend_from_slice(&key_schedule.transcript_hash().clone().finalize())
        .map_err(|_| TlsError::EncodeError)?;
    let signature = signing_key.sign(&msg);
    let signature_bytes: heapless::Vec<u8, 512> =
        heapless::Vec::from_slice(signature.as_ref()).map_err(|_| TlsError::EncodeError)?;
    let cv_len = build_encrypted_handshake_record(
        tx_buf,
        HandshakeType::CertificateVerify,
        |buf| {
            buf.push_u16(signature_scheme.as_u16())?;
            buf.with_u16_length(|buf| buf.extend_from_slice(&signature_bytes))?;
            Ok(())
        },
        key_schedule,
    )?;
    transport
        .write_all(&tx_buf[..cv_len])
        .map_err(|e| TlsError::Io(e.kind()))?;
    key_schedule.read_state().increment_counter();

    // 8) Send server Finished
    let server_finished = key_schedule.create_server_finished()?;
    let verify_bytes: heapless::Vec<u8, 64> =
        heapless::Vec::from_slice(server_finished.verify.as_slice())
            .map_err(|_| TlsError::EncodeError)?;
    let fin_len = build_encrypted_handshake_record(
        tx_buf,
        HandshakeType::Finished,
        |buf| {
            buf.extend_from_slice(&verify_bytes)
                .map_err(|_| TlsError::EncodeError)
        },
        key_schedule,
    )?;
    transport
        .write_all(&tx_buf[..fin_len])
        .map_err(|e| TlsError::Io(e.kind()))?;
    key_schedule.read_state().increment_counter();
    transport.flush().map_err(|e| TlsError::Io(e.kind()))?;

    // 9) Read client's ChangeCipherSpec (optional) and Finished
    loop {
        let (ct, body_len) = read_record_blocking(rx_buf, transport)?;
        match ct {
            ContentType::ChangeCipherSpec => continue,
            ContentType::ApplicationData => {
                let mut hdr_arr = [0u8; RecordHeader::LEN];
                hdr_arr.copy_from_slice(&rx_buf[..RecordHeader::LEN]);
                let header = RecordHeader::decode(hdr_arr)?;
                let inner_type = {
                    let mut payload =
                        CryptoBuffer::wrap_with_pos(&mut rx_buf[RecordHeader::LEN..], body_len);
                    let inner_type = decrypt_client_application_data::<Provider::CipherSuite>(
                        key_schedule.write_state(),
                        &header,
                        &mut payload,
                    )?;
                    let plaintext = payload.as_slice();
                    if !matches!(inner_type, ContentType::Handshake) {
                        return Err(TlsError::InvalidHandshake);
                    }
                    if plaintext.len() < 4 || plaintext[0] != HandshakeType::Finished as u8 {
                        return Err(TlsError::InvalidHandshake);
                    }
                    let hs_body_len =
                        u32::from_be_bytes([0, plaintext[1], plaintext[2], plaintext[3]]) as usize;
                    if plaintext.len() < 4 + hs_body_len {
                        return Err(TlsError::InvalidHandshake);
                    }
                    let verify_data = &plaintext[4..4 + hs_body_len];
                    if !key_schedule.verify_client_finished_data(verify_data)? {
                        return Err(TlsError::InvalidSignature);
                    }
                    // app traffic secrets are derived from the transcript through
                    // ServerFinished only, so do this before updating with ClientFinished.
                    key_schedule.initialize_master_secret()?;
                    key_schedule
                        .transcript_hash()
                        .update(&plaintext[..4 + hs_body_len]);
                    inner_type
                };
                let _ = inner_type;
                break;
            }
            _ => return Err(TlsError::InvalidRecord),
        }
    }

    Ok(())
}

async fn server_handshake_async<'a, Transport, Provider>(
    transport: &mut Transport,
    rx_buf: &mut [u8],
    tx_buf: &mut [u8],
    key_schedule: &mut KeySchedule<Provider::CipherSuite>,
    config: &TlsConfig<'a>,
    provider: &mut Provider,
) -> Result<(), TlsError>
where
    Transport: AsyncRead + AsyncWrite + 'a,
    Provider: CryptoProvider,
{
    ensure_handshake_buf_room(rx_buf)?;
    ensure_handshake_buf_room(tx_buf)?;

    let (ct, body_len) = read_record_async(rx_buf, transport).await?;
    if !matches!(ct, ContentType::Handshake) {
        return Err(TlsError::InvalidRecord);
    }
    let client_secret = process_client_hello_and_init(
        &rx_buf[RecordHeader::LEN..RecordHeader::LEN + body_len],
        key_schedule,
        provider,
    )?;

    let server_public_key = EncodedPoint::from(&client_secret.server_secret.public_key());
    let session_id_owned = client_secret.session_id;
    let session_id = &session_id_owned[..client_secret.session_id_len];
    let shared = client_secret
        .server_secret
        .diffie_hellman(&client_secret.client_public_key);

    let sh_len = build_server_hello_record(
        tx_buf,
        key_schedule,
        session_id,
        server_public_key.as_ref(),
        provider,
    )?;
    transport
        .write_all(&tx_buf[..sh_len])
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;

    key_schedule.initialize_handshake_secret(shared.raw_secret_bytes())?;

    let ccs_len = write_change_cipher_spec(tx_buf)?;
    transport
        .write_all(&tx_buf[..ccs_len])
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;

    let ee_len = build_encrypted_handshake_record(
        tx_buf,
        HandshakeType::EncryptedExtensions,
        |buf| encode_empty_extensions(buf),
        key_schedule,
    )?;
    transport
        .write_all(&tx_buf[..ee_len])
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;
    key_schedule.read_state().increment_counter();

    let cert = config.cert.as_ref().ok_or(TlsError::InvalidCertificate)?;
    let cert_entry = CertificateEntryRef::from(cert);
    let mut cert_msg = CertificateRef::with_context(&[]);
    cert_msg.add(cert_entry)?;
    let cert_len = build_encrypted_handshake_record(
        tx_buf,
        HandshakeType::Certificate,
        |buf| cert_msg.encode(buf),
        key_schedule,
    )?;
    transport
        .write_all(&tx_buf[..cert_len])
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;
    key_schedule.read_state().increment_counter();

    let (mut signing_key, signature_scheme) = provider
        .signer(config.priv_key)
        .map_err(|_| TlsError::InvalidPrivateKey)?;
    let ctx_str = b"TLS 1.3, server CertificateVerify\x00";
    let mut msg: heapless::Vec<u8, 146> = heapless::Vec::new();
    msg.resize(64, 0x20).map_err(|_| TlsError::EncodeError)?;
    msg.extend_from_slice(ctx_str)
        .map_err(|_| TlsError::EncodeError)?;
    msg.extend_from_slice(&key_schedule.transcript_hash().clone().finalize())
        .map_err(|_| TlsError::EncodeError)?;
    let signature = signing_key.sign(&msg);
    let signature_bytes: heapless::Vec<u8, 512> =
        heapless::Vec::from_slice(signature.as_ref()).map_err(|_| TlsError::EncodeError)?;
    let cv_len = build_encrypted_handshake_record(
        tx_buf,
        HandshakeType::CertificateVerify,
        |buf| {
            buf.push_u16(signature_scheme.as_u16())?;
            buf.with_u16_length(|buf| buf.extend_from_slice(&signature_bytes))?;
            Ok(())
        },
        key_schedule,
    )?;
    transport
        .write_all(&tx_buf[..cv_len])
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;
    key_schedule.read_state().increment_counter();

    let server_finished = key_schedule.create_server_finished()?;
    let verify_bytes: heapless::Vec<u8, 64> =
        heapless::Vec::from_slice(server_finished.verify.as_slice())
            .map_err(|_| TlsError::EncodeError)?;
    let fin_len = build_encrypted_handshake_record(
        tx_buf,
        HandshakeType::Finished,
        |buf| {
            buf.extend_from_slice(&verify_bytes)
                .map_err(|_| TlsError::EncodeError)
        },
        key_schedule,
    )?;
    transport
        .write_all(&tx_buf[..fin_len])
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;
    key_schedule.read_state().increment_counter();
    transport
        .flush()
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;

    loop {
        let (ct, body_len) = read_record_async(rx_buf, transport).await?;
        match ct {
            ContentType::ChangeCipherSpec => continue,
            ContentType::ApplicationData => {
                let mut hdr_arr = [0u8; RecordHeader::LEN];
                hdr_arr.copy_from_slice(&rx_buf[..RecordHeader::LEN]);
                let header = RecordHeader::decode(hdr_arr)?;
                let mut payload =
                    CryptoBuffer::wrap_with_pos(&mut rx_buf[RecordHeader::LEN..], body_len);
                let inner_type = decrypt_client_application_data::<Provider::CipherSuite>(
                    key_schedule.write_state(),
                    &header,
                    &mut payload,
                )?;
                let plaintext = payload.as_slice();
                if !matches!(inner_type, ContentType::Handshake) {
                    return Err(TlsError::InvalidHandshake);
                }
                if plaintext.len() < 4 || plaintext[0] != HandshakeType::Finished as u8 {
                    return Err(TlsError::InvalidHandshake);
                }
                let hs_body_len =
                    u32::from_be_bytes([0, plaintext[1], plaintext[2], plaintext[3]]) as usize;
                if plaintext.len() < 4 + hs_body_len {
                    return Err(TlsError::InvalidHandshake);
                }
                let verify_data = &plaintext[4..4 + hs_body_len];
                if !key_schedule.verify_client_finished_data(verify_data)? {
                    return Err(TlsError::InvalidSignature);
                }
                // app traffic secrets are derived from the transcript through
                // ServerFinished only, so do this before updating with ClientFinished.
                key_schedule.initialize_master_secret()?;
                key_schedule
                    .transcript_hash()
                    .update(&plaintext[..4 + hs_body_len]);
                break;
            }
            _ => return Err(TlsError::InvalidRecord),
        }
    }

    Ok(())
}

struct ClientHelloOutcome {
    server_secret: EphemeralSecret,
    client_public_key: p256::PublicKey,
    session_id: [u8; 32],
    session_id_len: usize,
}

/// Parse the ClientHello body, update the transcript with it, and prepare for
/// the server's ECDH key share. Does NOT touch the key schedule beyond the
/// transcript update (the caller invokes `initialize_handshake_secret` after
/// sending its ServerHello).
fn process_client_hello_and_init<CipherSuite, Provider>(
    ch_body: &[u8],
    key_schedule: &mut KeySchedule<CipherSuite>,
    provider: &mut Provider,
) -> Result<ClientHelloOutcome, TlsError>
where
    CipherSuite: TlsCipherSuite,
    Provider: CryptoProvider,
{
    // ch_body is the TLS-handshake payload (record content), which begins with
    // the 4-byte handshake header.
    if ch_body.len() < 4 || ch_body[0] != HandshakeType::ClientHello as u8 {
        return Err(TlsError::InvalidHandshake);
    }
    let inner_len = u32::from_be_bytes([0, ch_body[1], ch_body[2], ch_body[3]]) as usize;
    if ch_body.len() < 4 + inner_len {
        return Err(TlsError::InvalidHandshake);
    }
    let body = &ch_body[4..4 + inner_len];

    let mut pb = ParseBuffer::new(body);
    let parsed = ParsedClientHello::parse(&mut pb)?;

    // Initialize early secrets (no PSK).
    key_schedule.initialize_early_secret(None)?;
    // Update transcript with the ClientHello handshake message (header + body).
    key_schedule
        .transcript_hash()
        .update(&ch_body[..4 + inner_len]);

    // Build server ECDH secret + parse client public key.
    let client_public_key = p256::PublicKey::from_sec1_bytes(parsed.client_key_share)
        .map_err(|_| TlsError::InvalidKeyShare)?;
    let server_secret = EphemeralSecret::random(&mut provider.rng());

    let mut session_id = [0u8; 32];
    let session_id_len = parsed.session_id.len().min(32);
    session_id[..session_id_len].copy_from_slice(&parsed.session_id[..session_id_len]);

    Ok(ClientHelloOutcome {
        server_secret,
        client_public_key,
        session_id,
        session_id_len,
    })
}

// ----- Public blocking acceptor & server connection -------------------------

/// Blocking server-side TLS 1.3 connection.
pub struct TlsServerConnection<'a, Socket, CipherSuite>
where
    Socket: BlockingRead + BlockingWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    opened: AtomicBool,
    key_schedule: KeySchedule<CipherSuite>,
    record_reader: RecordReader<'a>,
    record_write_buf: WriteBuffer<'a>,
    decrypted: DecryptedBufferInfo,
    flush_policy: FlushPolicy,
}

impl<'a, Socket, CipherSuite> TlsServerConnection<'a, Socket, CipherSuite>
where
    Socket: BlockingRead + BlockingWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    /// Allocate a new server-side TLS connection wrapper. The buffers are used
    /// during handshake and reused for application data.
    pub fn new(
        delegate: Socket,
        record_read_buf: &'a mut [u8],
        record_write_buf: &'a mut [u8],
    ) -> Self {
        Self {
            delegate,
            opened: AtomicBool::new(false),
            key_schedule: KeySchedule::new(),
            record_reader: RecordReader::new(record_read_buf),
            record_write_buf: WriteBuffer::new(record_write_buf),
            decrypted: DecryptedBufferInfo::default(),
            flush_policy: FlushPolicy::default(),
        }
    }

    fn is_opened(&mut self) -> bool {
        *self.opened.get_mut()
    }

    pub fn flush_policy(&self) -> FlushPolicy {
        self.flush_policy
    }

    pub fn set_flush_policy(&mut self, policy: FlushPolicy) {
        self.flush_policy = policy;
    }

    /// Drive the server-side TLS 1.3 handshake.
    pub fn accept<Provider>(
        &mut self,
        config: &TlsConfig<'_>,
        mut provider: Provider,
    ) -> Result<(), TlsError>
    where
        Provider: CryptoProvider<CipherSuite = CipherSuite>,
    {
        server_handshake_blocking::<_, Provider>(
            &mut self.delegate,
            self.record_reader.buf,
            self.record_write_buf.as_raw_slice(),
            &mut self.key_schedule,
            config,
            &mut provider,
        )?;
        *self.opened.get_mut() = true;
        Ok(())
    }

    /// Read decrypted application data.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut buffer = self.read_buffered()?;
        Ok(buffer.pop_into(buf))
    }

    pub fn read_buffered(&mut self) -> Result<ReadBuffer<'_>, TlsError> {
        if self.is_opened() {
            while self.decrypted.is_empty() {
                self.read_application_data()?;
            }
            Ok(self.decrypted.create_read_buffer(self.record_reader.buf))
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    fn read_application_data(&mut self) -> Result<(), TlsError> {
        let buf_ptr_range = self.record_reader.buf.as_ptr_range();
        // For the server the *read* keys are the client traffic keys, which
        // live in `write_state`. But the standard `RecordReader` expects a
        // `ReadKeySchedule` (which for the server holds *write* keys). So we
        // read the record manually and decrypt against `write_state`.
        let mut hdr_buf = [0u8; RecordHeader::LEN];
        read_exact_blocking(&mut self.delegate, &mut hdr_buf)?;
        let header = RecordHeader::decode(hdr_buf)?;
        let body_len = header.content_length();
        let buf = &mut self.record_reader.buf[..body_len];
        read_exact_blocking(&mut self.delegate, buf)?;

        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: &mut self.decrypted,
            is_open: self.opened.get_mut(),
        };
        match header.content_type() {
            ContentType::ApplicationData => {
                let mut payload = CryptoBuffer::wrap_with_pos(buf, body_len);
                let inner_type = decrypt_client_application_data::<CipherSuite>(
                    self.key_schedule.write_state(),
                    &header,
                    &mut payload,
                )?;
                match inner_type {
                    ContentType::ApplicationData => {
                        let app = ApplicationData::new(payload, header);
                        handler.handle(ServerRecord::ApplicationData(app))?;
                    }
                    ContentType::Alert => {
                        let mut pb = ParseBuffer::new(payload.as_slice());
                        let alert = Alert::parse(&mut pb)?;
                        handler.handle(ServerRecord::Alert(alert))?;
                    }
                    ContentType::Handshake => {
                        // post-handshake messages ignored
                    }
                    _ => return Err(TlsError::InvalidRecord),
                }
            }
            ContentType::Alert => {
                let mut pb = ParseBuffer::new(buf);
                let alert = Alert::parse(&mut pb)?;
                handler.handle(ServerRecord::Alert(alert))?;
            }
            ContentType::ChangeCipherSpec => {
                // middlebox-compat CCS ignored
            }
            _ => return Err(TlsError::InvalidRecord),
        }
        Ok(())
    }

    /// Encrypt and write application data.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if !self.is_opened() {
            return Err(TlsError::MissingHandshake);
        }
        // Build an ApplicationData record using the same write buffer used
        // during handshake. We mirror the client logic but with server keys.
        let tx_buf = self.record_write_buf.as_raw_slice();
        const HEADER_SIZE: usize = 5;
        if tx_buf.len() < HEADER_SIZE + TLS_RECORD_OVERHEAD {
            return Err(TlsError::InsufficientSpace);
        }
        let max_payload =
            tx_buf.len() - HEADER_SIZE - TLS_RECORD_OVERHEAD;
        let to_write = buf.len().min(max_payload);

        tx_buf[0] = ContentType::ApplicationData as u8;
        tx_buf[1] = 0x03;
        tx_buf[2] = 0x03;
        tx_buf[3] = 0;
        tx_buf[4] = 0;
        tx_buf[HEADER_SIZE..HEADER_SIZE + to_write].copy_from_slice(&buf[..to_write]);
        tx_buf[HEADER_SIZE + to_write] = ContentType::ApplicationData as u8;
        let plaintext_len = to_write + 1;

        let mut enc_buf =
            CryptoBuffer::wrap_with_pos(&mut tx_buf[HEADER_SIZE..], plaintext_len);
        let (_, read_state) = self.key_schedule.as_split();
        encrypt_server(read_state, &mut enc_buf)?;
        let ciphertext_len = enc_buf.len();
        let total = HEADER_SIZE + ciphertext_len;
        let lb = (ciphertext_len as u16).to_be_bytes();
        tx_buf[3] = lb[0];
        tx_buf[4] = lb[1];

        self.delegate
            .write_all(&tx_buf[..total])
            .map_err(|e| TlsError::Io(e.kind()))?;
        self.key_schedule.read_state().increment_counter();
        if self.flush_policy.flush_transport() {
            self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))?;
        }
        Ok(to_write)
    }

    pub fn flush(&mut self) -> Result<(), TlsError> {
        self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))
    }

    /// Close the connection, sending close_notify. Returns the underlying socket.
    pub fn close(mut self) -> Result<Socket, (Socket, TlsError)> {
        // Send an encrypted close_notify alert.
        match self.send_alert(AlertLevel::Warning, AlertDescription::CloseNotify) {
            Ok(()) => Ok(self.delegate),
            Err(e) => Err((self.delegate, e)),
        }
    }

    fn send_alert(
        &mut self,
        level: AlertLevel,
        description: AlertDescription,
    ) -> Result<(), TlsError> {
        let tx_buf = self.record_write_buf.as_raw_slice();
        const HEADER_SIZE: usize = 5;
        tx_buf[0] = ContentType::ApplicationData as u8;
        tx_buf[1] = 0x03;
        tx_buf[2] = 0x03;
        tx_buf[3] = 0;
        tx_buf[4] = 0;
        // alert (2 bytes) + content type byte
        let alert = Alert::new(level, description);
        let mut body_buf = CryptoBuffer::wrap(&mut tx_buf[HEADER_SIZE..]);
        alert.encode(&mut body_buf)?;
        let body_len = body_buf.len();
        drop(body_buf);
        tx_buf[HEADER_SIZE + body_len] = ContentType::Alert as u8;
        let plaintext_len = body_len + 1;

        let mut enc_buf =
            CryptoBuffer::wrap_with_pos(&mut tx_buf[HEADER_SIZE..], plaintext_len);
        let (_, read_state) = self.key_schedule.as_split();
        encrypt_server(read_state, &mut enc_buf)?;
        let ciphertext_len = enc_buf.len();
        let total = HEADER_SIZE + ciphertext_len;
        let lb = (ciphertext_len as u16).to_be_bytes();
        tx_buf[3] = lb[0];
        tx_buf[4] = lb[1];

        self.delegate
            .write_all(&tx_buf[..total])
            .map_err(|e| TlsError::Io(e.kind()))?;
        self.key_schedule.read_state().increment_counter();
        self.delegate.flush().map_err(|e| TlsError::Io(e.kind()))?;
        Ok(())
    }
}

impl<'a, Socket, CipherSuite> ErrorType for TlsServerConnection<'a, Socket, CipherSuite>
where
    Socket: BlockingRead + BlockingWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<'a, Socket, CipherSuite> embedded_io::Read for TlsServerConnection<'a, Socket, CipherSuite>
where
    Socket: BlockingRead + BlockingWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        TlsServerConnection::read(self, buf)
    }
}

impl<'a, Socket, CipherSuite> embedded_io::Write for TlsServerConnection<'a, Socket, CipherSuite>
where
    Socket: BlockingRead + BlockingWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        TlsServerConnection::write(self, buf)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        TlsServerConnection::flush(self)
    }
}

// ----- Async server connection ---------------------------------------------

/// Async server-side TLS 1.3 connection.
pub struct AsyncTlsServerConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    delegate: Socket,
    opened: core::sync::atomic::AtomicBool,
    key_schedule: KeySchedule<CipherSuite>,
    record_reader: RecordReader<'a>,
    record_write_buf: WriteBuffer<'a>,
    decrypted: DecryptedBufferInfo,
    flush_policy: FlushPolicy,
}

impl<'a, Socket, CipherSuite> AsyncTlsServerConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    pub fn new(
        delegate: Socket,
        record_read_buf: &'a mut [u8],
        record_write_buf: &'a mut [u8],
    ) -> Self {
        Self {
            delegate,
            opened: core::sync::atomic::AtomicBool::new(false),
            key_schedule: KeySchedule::new(),
            record_reader: RecordReader::new(record_read_buf),
            record_write_buf: WriteBuffer::new(record_write_buf),
            decrypted: DecryptedBufferInfo::default(),
            flush_policy: FlushPolicy::default(),
        }
    }

    fn is_opened(&mut self) -> bool {
        *self.opened.get_mut()
    }

    pub fn set_flush_policy(&mut self, policy: FlushPolicy) {
        self.flush_policy = policy;
    }

    pub async fn accept<Provider>(
        &mut self,
        config: &TlsConfig<'_>,
        mut provider: Provider,
    ) -> Result<(), TlsError>
    where
        Provider: CryptoProvider<CipherSuite = CipherSuite>,
    {
        server_handshake_async::<_, Provider>(
            &mut self.delegate,
            self.record_reader.buf,
            self.record_write_buf.as_raw_slice(),
            &mut self.key_schedule,
            config,
            &mut provider,
        )
        .await?;
        *self.opened.get_mut() = true;
        Ok(())
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut buffer = self.read_buffered().await?;
        Ok(buffer.pop_into(buf))
    }

    pub async fn read_buffered(&mut self) -> Result<ReadBuffer<'_>, TlsError> {
        if self.is_opened() {
            while self.decrypted.is_empty() {
                self.read_application_data().await?;
            }
            Ok(self.decrypted.create_read_buffer(self.record_reader.buf))
        } else {
            Err(TlsError::MissingHandshake)
        }
    }

    async fn read_application_data(&mut self) -> Result<(), TlsError> {
        let buf_ptr_range = self.record_reader.buf.as_ptr_range();
        let mut hdr_buf = [0u8; RecordHeader::LEN];
        read_exact_async(&mut self.delegate, &mut hdr_buf).await?;
        let header = RecordHeader::decode(hdr_buf)?;
        let body_len = header.content_length();
        let buf = &mut self.record_reader.buf[..body_len];
        read_exact_async(&mut self.delegate, buf).await?;

        let mut handler = DecryptedReadHandler {
            source_buffer: buf_ptr_range,
            buffer_info: &mut self.decrypted,
            is_open: self.opened.get_mut(),
        };
        match header.content_type() {
            ContentType::ApplicationData => {
                let mut payload = CryptoBuffer::wrap_with_pos(buf, body_len);
                let inner_type = decrypt_client_application_data::<CipherSuite>(
                    self.key_schedule.write_state(),
                    &header,
                    &mut payload,
                )?;
                match inner_type {
                    ContentType::ApplicationData => {
                        let app = ApplicationData::new(payload, header);
                        handler.handle(ServerRecord::ApplicationData(app))?;
                    }
                    ContentType::Alert => {
                        let mut pb = ParseBuffer::new(payload.as_slice());
                        let alert = Alert::parse(&mut pb)?;
                        handler.handle(ServerRecord::Alert(alert))?;
                    }
                    ContentType::Handshake => {}
                    _ => return Err(TlsError::InvalidRecord),
                }
            }
            ContentType::Alert => {
                let mut pb = ParseBuffer::new(buf);
                let alert = Alert::parse(&mut pb)?;
                handler.handle(ServerRecord::Alert(alert))?;
            }
            ContentType::ChangeCipherSpec => {}
            _ => return Err(TlsError::InvalidRecord),
        }
        Ok(())
    }

    pub async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsError> {
        if !self.is_opened() {
            return Err(TlsError::MissingHandshake);
        }
        let tx_buf = self.record_write_buf.as_raw_slice();
        const HEADER_SIZE: usize = 5;
        if tx_buf.len() < HEADER_SIZE + TLS_RECORD_OVERHEAD {
            return Err(TlsError::InsufficientSpace);
        }
        let max_payload = tx_buf.len() - HEADER_SIZE - TLS_RECORD_OVERHEAD;
        let to_write = buf.len().min(max_payload);

        tx_buf[0] = ContentType::ApplicationData as u8;
        tx_buf[1] = 0x03;
        tx_buf[2] = 0x03;
        tx_buf[3] = 0;
        tx_buf[4] = 0;
        tx_buf[HEADER_SIZE..HEADER_SIZE + to_write].copy_from_slice(&buf[..to_write]);
        tx_buf[HEADER_SIZE + to_write] = ContentType::ApplicationData as u8;
        let plaintext_len = to_write + 1;

        let mut enc_buf =
            CryptoBuffer::wrap_with_pos(&mut tx_buf[HEADER_SIZE..], plaintext_len);
        let (_, read_state) = self.key_schedule.as_split();
        encrypt_server(read_state, &mut enc_buf)?;
        let ciphertext_len = enc_buf.len();
        let total = HEADER_SIZE + ciphertext_len;
        let lb = (ciphertext_len as u16).to_be_bytes();
        tx_buf[3] = lb[0];
        tx_buf[4] = lb[1];

        self.delegate
            .write_all(&tx_buf[..total])
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;
        self.key_schedule.read_state().increment_counter();
        if self.flush_policy.flush_transport() {
            self.delegate
                .flush()
                .await
                .map_err(|e| TlsError::Io(e.kind()))?;
        }
        Ok(to_write)
    }

    pub async fn flush(&mut self) -> Result<(), TlsError> {
        self.delegate
            .flush()
            .await
            .map_err(|e| TlsError::Io(e.kind()))
    }

    pub async fn close(mut self) -> Result<Socket, (Socket, TlsError)> {
        match self.send_alert(AlertLevel::Warning, AlertDescription::CloseNotify).await {
            Ok(()) => Ok(self.delegate),
            Err(e) => Err((self.delegate, e)),
        }
    }

    async fn send_alert(
        &mut self,
        level: AlertLevel,
        description: AlertDescription,
    ) -> Result<(), TlsError> {
        let tx_buf = self.record_write_buf.as_raw_slice();
        const HEADER_SIZE: usize = 5;
        tx_buf[0] = ContentType::ApplicationData as u8;
        tx_buf[1] = 0x03;
        tx_buf[2] = 0x03;
        tx_buf[3] = 0;
        tx_buf[4] = 0;
        let alert = Alert::new(level, description);
        let mut body_buf = CryptoBuffer::wrap(&mut tx_buf[HEADER_SIZE..]);
        alert.encode(&mut body_buf)?;
        let body_len = body_buf.len();
        drop(body_buf);
        tx_buf[HEADER_SIZE + body_len] = ContentType::Alert as u8;
        let plaintext_len = body_len + 1;

        let mut enc_buf =
            CryptoBuffer::wrap_with_pos(&mut tx_buf[HEADER_SIZE..], plaintext_len);
        let (_, read_state) = self.key_schedule.as_split();
        encrypt_server(read_state, &mut enc_buf)?;
        let ciphertext_len = enc_buf.len();
        let total = HEADER_SIZE + ciphertext_len;
        let lb = (ciphertext_len as u16).to_be_bytes();
        tx_buf[3] = lb[0];
        tx_buf[4] = lb[1];

        self.delegate
            .write_all(&tx_buf[..total])
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;
        self.key_schedule.read_state().increment_counter();
        self.delegate
            .flush()
            .await
            .map_err(|e| TlsError::Io(e.kind()))?;
        Ok(())
    }
}

impl<'a, Socket, CipherSuite> ErrorType for AsyncTlsServerConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    type Error = TlsError;
}

impl<'a, Socket, CipherSuite> AsyncRead for AsyncTlsServerConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        AsyncTlsServerConnection::read(self, buf).await
    }
}

impl<'a, Socket, CipherSuite> AsyncWrite for AsyncTlsServerConnection<'a, Socket, CipherSuite>
where
    Socket: AsyncRead + AsyncWrite + 'a,
    CipherSuite: TlsCipherSuite + 'static,
{
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        AsyncTlsServerConnection::write(self, buf).await
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        AsyncTlsServerConnection::flush(self).await
    }
}
