//! https://developers.yubico.com/OATH/YKOATH_Protocol.html

pub mod calculate;
pub mod calculate_all;
mod error;
pub mod select;

pub use crate::calculate::Response;
pub use crate::calculate_all::{BulkResponse, BulkResponseData};
pub use error::Error;
use pcsc::{Card, Context, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};
use std::fmt::{self, Debug, Write};
use std::mem::size_of;

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

    fn push<Data: Payload>(buf: &mut Vec<u8>, tag: u8, data: Data) {
        buf.push(tag);
        buf.push(data.len());
        data.push_into(buf);
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
}

#[derive(Debug)]
pub enum Algorithm {
    HmacSha1,
    HmacSha256,
    HmacSha512,
}

struct EscapeAscii<'a>(&'a [u8]);

impl fmt::Debug for EscapeAscii<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("b\"")?;
        for b in self.0.escape_ascii() {
            f.write_char(b as char)?;
        }
        f.write_char('"')
    }
}

pub trait Payload: Debug {
    fn push_into(&self, buf: &mut Vec<u8>);
    fn len(&self) -> u8;
}

impl Payload for &'_ [u8] {
    fn push_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self)
    }

    fn len(&self) -> u8 {
        <[u8]>::len(self) as _
    }
}

impl Payload for i64 {
    fn push_into(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.to_be_bytes())
    }

    fn len(&self) -> u8 {
        size_of::<Self>() as _
    }
}
