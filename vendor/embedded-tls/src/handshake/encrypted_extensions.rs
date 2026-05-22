use core::marker::PhantomData;

use crate::buffer::CryptoBuffer;
use crate::extensions::messages::EncryptedExtensionsExtension;

use crate::TlsError;
use crate::parse_buffer::ParseBuffer;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncryptedExtensions<'a> {
    _todo: PhantomData<&'a ()>,
}

impl<'a> EncryptedExtensions<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<EncryptedExtensions<'a>, TlsError> {
        EncryptedExtensionsExtension::parse_vector::<16>(buf)?;
        Ok(EncryptedExtensions { _todo: PhantomData })
    }
}

/// Encode an empty EncryptedExtensions body (after the handshake header).
#[allow(dead_code)]
pub fn encode_empty(buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
    // empty extension list
    buf.push_u16(0).map_err(|_| TlsError::EncodeError)
}
