use heapless::Vec;

use crate::buffer::CryptoBuffer;
use crate::cipher_suites::CipherSuite;
use crate::config::TlsCipherSuite;
use crate::crypto_engine::CryptoEngine;
use crate::extensions::extension_data::key_share::{
    KeyShareEntry, KeyShareServerHello,
};
use crate::extensions::extension_data::supported_groups::NamedGroup;
use crate::extensions::extension_data::supported_versions::{
    SupportedVersionsServerHello, TLS13,
};
use crate::extensions::messages::ServerHelloExtension;
use crate::handshake::LEGACY_VERSION;
use crate::parse_buffer::ParseBuffer;
use crate::{TlsError, unused};
use p256::PublicKey;
use p256::ecdh::{EphemeralSecret, SharedSecret};
use rand_core::CryptoRngCore;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerHello<'a> {
    extensions: Vec<ServerHelloExtension<'a>, 4>,
}

impl<'a> ServerHello<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<ServerHello<'a>, TlsError> {
        //let mut buf = ParseBuffer::new(&buf[0..content_length]);
        //let mut buf = ParseBuffer::new(&buf);

        let _version = buf.read_u16().map_err(|_| TlsError::InvalidHandshake)?;

        let mut random = [0; 32];
        buf.fill(&mut random)?;

        let session_id_length = buf
            .read_u8()
            .map_err(|_| TlsError::InvalidSessionIdLength)?;

        //info!("sh 1");

        let session_id = buf
            .slice(session_id_length as usize)
            .map_err(|_| TlsError::InvalidSessionIdLength)?;
        //info!("sh 2");

        let cipher_suite = CipherSuite::parse(buf).map_err(|_| TlsError::InvalidCipherSuite)?;

        ////info!("sh 3");
        // skip compression method, it's 0.
        buf.read_u8()?;

        let extensions = ServerHelloExtension::parse_vector(buf)?;

        // debug!("server random {:x}", random);
        // debug!("server session-id {:x}", session_id.as_slice());
        debug!("server cipher_suite {:?}", cipher_suite);
        debug!("server extensions {:?}", extensions);

        unused(session_id);
        Ok(Self { extensions })
    }

    pub fn key_share(&self) -> Option<&KeyShareEntry<'_>> {
        self.extensions.iter().find_map(|e| {
            if let ServerHelloExtension::KeyShare(entry) = e {
                Some(&entry.0)
            } else {
                None
            }
        })
    }

    pub fn calculate_shared_secret(&self, secret: &EphemeralSecret) -> Option<SharedSecret> {
        let server_key_share = self.key_share()?;
        let server_public_key = PublicKey::from_sec1_bytes(server_key_share.opaque).ok()?;
        Some(secret.diffie_hellman(&server_public_key))
    }

    #[allow(dead_code)]
    pub fn initialize_crypto_engine(&self, secret: &EphemeralSecret) -> Option<CryptoEngine> {
        let server_key_share = self.key_share()?;

        let group = server_key_share.group;

        let server_public_key = PublicKey::from_sec1_bytes(server_key_share.opaque).ok()?;
        let shared = secret.diffie_hellman(&server_public_key);

        Some(CryptoEngine::new(group, shared))
    }
}

/// Encode a ServerHello body (after the handshake type+length header).
#[allow(dead_code)]
pub fn encode_server_hello<CS: TlsCipherSuite>(
    buf: &mut CryptoBuffer<'_>,
    rng: &mut impl CryptoRngCore,
    session_id: &[u8],
    server_public_key: &[u8],
) -> Result<(), TlsError> {
    buf.push_u16(LEGACY_VERSION)
        .map_err(|_| TlsError::EncodeError)?;

    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    buf.extend_from_slice(&random)
        .map_err(|_| TlsError::EncodeError)?;

    buf.push(session_id.len() as u8)
        .map_err(|_| TlsError::EncodeError)?;
    buf.extend_from_slice(session_id)
        .map_err(|_| TlsError::EncodeError)?;

    buf.push_u16(CS::CODE_POINT)
        .map_err(|_| TlsError::EncodeError)?;

    // null compression method
    buf.push(0).map_err(|_| TlsError::EncodeError)?;

    buf.with_u16_length(|buf| {
        ServerHelloExtension::SupportedVersions(SupportedVersionsServerHello {
            selected_version: TLS13,
        })
        .encode(buf)?;

        ServerHelloExtension::KeyShare(KeyShareServerHello(KeyShareEntry {
            group: NamedGroup::Secp256r1,
            opaque: server_public_key,
        }))
        .encode(buf)?;

        Ok(())
    })?;

    Ok(())
}
