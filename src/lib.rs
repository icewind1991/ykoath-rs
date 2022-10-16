//! https://developers.yubico.com/OATH/YKOATH_Protocol.html

pub use pcsc;
use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};
use std::iter;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Pcsc(#[from] pcsc::Error),
    #[error("No YubiKey found")]
    NoDevice,
    #[error("Response does not have enough length")]
    InsufficientData,
    #[error("Unknown response code (0x{0:04x})")]
    UnknownCode(u16),
    #[error("Unexpected value (0x{0:02x}")]
    UnexpectedValue(u8),
    #[error("No space")]
    NoSpace,
    #[error("No such object")]
    NoSuchObject,
    #[error("Auth required")]
    AuthRequired,
    #[error("Wrong syntax")]
    WrongSyntax,
    #[error("Generic error")]
    GenericError,
}

pub struct YubiKey(Card);

impl YubiKey {
    #[tracing::instrument(skip_all)]
    pub fn connect(buf: &mut Vec<u8>) -> Result<Self, Error> {
        let context = Context::establish(Scope::User)?;
        Self::connect_with(&context, buf)
    }

    #[tracing::instrument(skip_all)]
    pub fn connect_with(context: &Context, buf: &mut Vec<u8>) -> Result<Self, Error> {
        // https://github.com/Yubico/yubikey-manager/blob/4.0.9/ykman/pcsc/__init__.py#L46
        const READER_NAME: &[u8] = b"yubico yubikey";

        buf.resize(context.list_readers_len()?, 0);
        let reader_name = context
            .list_readers(buf)?
            .find(|reader_name| {
                // https://github.com/Yubico/yubikey-manager/blob/4.0.9/ykman/pcsc/__init__.py#L165
                reader_name
                    .to_bytes()
                    .to_ascii_lowercase()
                    .windows(READER_NAME.len())
                    .any(|window| window == READER_NAME)
            })
            .ok_or(Error::NoDevice)?;
        tracing::debug!(reader_name = ?reader_name);
        Ok(Self(context.connect(
            reader_name,
            ShareMode::Shared,
            Protocols::ANY,
        )?))
    }

    #[tracing::instrument(skip_all)]
    fn transmit<'a>(&self, buf: &'a mut Vec<u8>) -> Result<&'a [u8], Error> {
        if buf.len() >= 5 {
            // Lc
            buf[4] = (buf.len() - 5) as _;
        }
        tracing::trace!(command = ?buf);
        let mid = buf.len();
        loop {
            let len = buf.len();
            buf.resize(len + MAX_BUFFER_SIZE, 0);
            let (occupied, vacant) = buf.split_at_mut(len);
            let command = if mid == len {
                &occupied[..mid]
            } else {
                // SEND REMAINING INSTRUCTION
                &[0x00, 0xa5, 0x00, 0x00]
            };
            tracing::trace!(pcsc_command = ?command);
            let response = self.0.transmit(command, vacant)?;
            tracing::trace!(pcsc_response = ?response);
            let len = len + response.len();
            buf.truncate(len);
            let code = u16::from_le_bytes([
                buf.pop().ok_or(Error::InsufficientData)?,
                buf.pop().ok_or(Error::InsufficientData)?,
            ]);
            match code {
                0x9000 => {
                    let response = &buf[mid..];
                    tracing::trace!(response = ?response);
                    break Ok(response);
                }
                0x6100..=0x61ff => Ok(()),
                0x6a84 => Err(Error::NoSpace),
                0x6984 => Err(Error::NoSuchObject),
                0x6982 => Err(Error::AuthRequired),
                0x6a80 => Err(Error::WrongSyntax),
                0x6581 => Err(Error::GenericError),
                _ => Err(Error::UnknownCode(code)),
            }?
        }
    }

    fn push(buf: &mut Vec<u8>, tag: u8, data: &[u8]) {
        buf.push(tag);
        buf.push(data.len() as _);
        buf.extend_from_slice(data);
    }

    fn pop<'a>(buf: &mut &'a [u8], tags: &[u8]) -> Result<(u8, &'a [u8]), Error> {
        let tag = *buf.first().ok_or(Error::InsufficientData)?;
        if tags.contains(&tag) {
            let len = *buf.get(1).ok_or(Error::InsufficientData)? as usize;
            let data = buf.get(2..2 + len).ok_or(Error::InsufficientData)?;
            *buf = &buf[2 + len..];
            Ok((tag, data))
        } else {
            Err(Error::UnexpectedValue(tag))
        }
    }

    // SELECT INSTRUCTION
    #[tracing::instrument(skip(self, buf))]
    pub fn select<'a>(&self, buf: &'a mut Vec<u8>) -> Result<select::Response<'a>, Error> {
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
            let algorithm = if algorithm.len() == 1 {
                match algorithm[0] {
                    0x01 => Ok(Algorithm::HmacSha1),
                    0x02 => Ok(Algorithm::HmacSha256),
                    0x03 => Ok(Algorithm::HmacSha512),
                    _ => Err(Error::UnexpectedValue(algorithm[0])),
                }
            } else {
                Err(Error::UnexpectedValue(algorithm.len() as _))
            }?;
            Some(select::Inner {
                challenge,
                algorithm,
            })
        };
        let response = select::Response {
            version,
            name,
            inner,
        };
        tracing::debug!(response = ?response);
        Ok(response)
    }

    // CALCULATE INSTRUCTION
    #[tracing::instrument(skip(self, buf))]
    pub fn calculate<'a>(
        &self,
        truncate: bool,
        name: &[u8],
        challenge: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<calculate::Response<'a>, Error> {
        buf.clear();
        buf.extend_from_slice(&[0x00, 0xa2, 0x00, if truncate { 0x01 } else { 0x00 }]);
        buf.push(0x00);
        Self::push(buf, 0x71, name);
        Self::push(buf, 0x74, challenge);
        let mut response = self.transmit(buf)?;
        let (_, response) = Self::pop(&mut response, &[if truncate { 0x76 } else { 0x75 }])?;
        let response = calculate::Response {
            digits: *response.first().ok_or(Error::InsufficientData)?,
            response: &response[1..],
        };
        tracing::debug!(response = ?response);
        Ok(response)
    }

    // CALCULATE ALL INSTRUCTION
    #[tracing::instrument(skip(self, buf))]
    pub fn calculate_all<'a>(
        &self,
        truncate: bool,
        challenge: &[u8],
        buf: &'a mut Vec<u8>,
    ) -> Result<impl Iterator<Item = Result<calculate_all::Response<'a>, Error>> + 'a, Error> {
        let span = tracing::Span::current();
        buf.clear();
        buf.extend_from_slice(&[0x00, 0xa4, 0x00, if truncate { 0x01 } else { 0x00 }]);
        buf.push(0x00);
        Self::push(buf, 0x74, challenge);
        let mut response = self.transmit(buf)?;
        Ok(iter::from_fn(move || {
            let _enter = span.enter();
            if response.is_empty() {
                None
            } else {
                Some(Self::pop(&mut response, &[0x71]).and_then(|(_, name)| {
                    let (tag, response) = Self::pop(
                        &mut response,
                        &[if truncate { 0x76 } else { 0x75 }, 0x77, 0x7c],
                    )?;
                    let inner = match tag {
                        0x75 | 0x76 => {
                            let digits = *response.first().ok_or(Error::InsufficientData)?;
                            let response = &response[1..];
                            Ok(calculate_all::Inner::Response(calculate::Response {
                                digits,
                                response,
                            }))
                        }
                        0x77 => Ok(calculate_all::Inner::Hotp),
                        0x7c => Ok(calculate_all::Inner::Touch),
                        _ => Err(Error::UnexpectedValue(tag)),
                    }?;
                    let response = calculate_all::Response { name, inner };
                    tracing::debug!(response = ?response);
                    Ok(response)
                }))
            }
        }))
    }
}

// ALGORITHMS
#[derive(Debug)]
pub enum Algorithm {
    HmacSha1,
    HmacSha256,
    HmacSha512,
}

pub mod select {
    #[derive(Debug)]
    pub struct Response<'a> {
        pub version: &'a [u8],
        pub name: &'a [u8],
        pub inner: Option<Inner<'a>>,
    }

    #[derive(Debug)]
    pub struct Inner<'a> {
        pub challenge: &'a [u8],
        pub algorithm: super::Algorithm,
    }
}

pub mod calculate {
    #[derive(Debug)]
    pub struct Response<'a> {
        pub digits: u8,
        pub response: &'a [u8],
    }
}

pub mod calculate_all {
    #[derive(Debug)]
    pub struct Response<'a> {
        pub name: &'a [u8],
        pub inner: Inner<'a>,
    }

    #[derive(Debug)]
    pub enum Inner<'a> {
        Response(super::calculate::Response<'a>),
        Hotp,
        Touch,
    }
}
