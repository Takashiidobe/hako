use crate::TlsError;
use crate::buffer::CryptoBuffer;
use crate::parse_buffer::ParseBuffer;
use core::fmt::{Debug, Formatter};
use generic_array::{ArrayLength, GenericArray};
use heapless::Vec;

pub struct Finished<N: ArrayLength<u8>> {
    pub verify: GenericArray<u8, N>,
    pub hash: Option<GenericArray<u8, N>>,
}

pub struct ServerFinished {
    pub verify: Vec<u8, 48>,
    pub hash: Option<Vec<u8, 48>>,
}

#[cfg(feature = "defmt")]
impl defmt::Format for ServerFinished {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "verify length:{}", &self.verify.len());
    }
}

impl Debug for ServerFinished {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerFinished")
            .field("verify", &self.hash)
            .finish()
    }
}

impl ServerFinished {
    pub fn parse(buf: &mut ParseBuffer, len: u32) -> Result<Self, TlsError> {
        let verify = buf
            .slice(len as usize)
            .map_err(|_| TlsError::InvalidHandshake)?;
        Ok(Self {
            verify: Vec::from_slice(verify.as_slice()).map_err(|_| TlsError::InvalidHandshake)?,
            hash: None,
        })
    }
}

#[cfg(feature = "defmt")]
impl<N: ArrayLength<u8>> defmt::Format for Finished<N> {
    fn format(&self, f: defmt::Formatter<'_>) {
        defmt::write!(f, "verify length:{}", &self.verify.len());
    }
}

impl<N: ArrayLength<u8>> Debug for Finished<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Finished")
            .field("verify", &self.hash)
            .finish()
    }
}

impl<N: ArrayLength<u8>> Finished<N> {
    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.extend_from_slice(&self.verify[..self.verify.len()])
            .map_err(|_| TlsError::EncodeError)?;
        Ok(())
    }
}
