use crate::{Algorithm, Error, EscapeAscii, YubiKey};
use std::fmt;

pub struct Response<'a> {
    pub version: &'a [u8],
    pub name: &'a [u8],
    pub inner: Option<Inner<'a>>,
}

impl fmt::Debug for Response<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("version", &self.version)
            .field("name", &EscapeAscii(self.name))
            .field("inner", &self.inner)
            .finish()
    }
}

#[derive(Debug)]
pub struct Inner<'a> {
    pub challenge: &'a [u8],
    pub algorithm: Algorithm,
}

impl YubiKey {
    #[tracing::instrument(skip(self, buf))]
    pub fn select<'a>(&self, buf: &'a mut Vec<u8>) -> Result<Response<'a>, Error> {
        buf.clear();
        buf.extend_from_slice(&[0x00, 0xa4, 0x04, 0x00]);
        buf.push(0x00);
        buf.extend_from_slice(&[0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01]);
        let mut response = self.transmit(buf)?;
        let (_, version) = Self::pop(&mut response, &[0x79])?;
        let (_, name) = Self::pop(&mut response, &[0x71])?;
        let inner = if response.is_empty() {
            None
        } else {
            let (_, challenge) = Self::pop(&mut response, &[0x74])?;
            let (_, algorithm) = Self::pop(&mut response, &[0x7b])?;
            let algorithm = match algorithm {
                [0x01] => Ok(Algorithm::HmacSha1),
                [0x02] => Ok(Algorithm::HmacSha256),
                [0x03] => Ok(Algorithm::HmacSha512),
                [v] => Err(Error::UnexpectedValue(*v)),
                _ => Err(Error::UnexpectedValue(algorithm.len() as _)),
            }?;
            Some(Inner {
                challenge,
                algorithm,
            })
        };
        let response = Response {
            version,
            name,
            inner,
        };
        tracing::debug!(response = ?response);
        Ok(response)
    }
}
