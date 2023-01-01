use crate::{Error, EscapeAscii, Payload, YubiKey};
use std::fmt;
use std::iter;

#[derive(Clone)]
pub struct BulkResponse<'a> {
    pub name: &'a str,
    pub data: BulkResponseData,
}

impl fmt::Debug for BulkResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("name", &EscapeAscii(self.name.as_bytes()))
            .field("inner", &self.data)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub enum BulkResponseData {
    Totp(crate::calculate::Response),
    Hotp,
    Touch,
}

impl YubiKey {
    #[tracing::instrument(skip(self, buf))]
    pub fn calculate_all<'a, C: Payload>(
        &self,
        truncate: bool,
        challenge: C,
        buf: &'a mut Vec<u8>,
    ) -> Result<impl Iterator<Item = Result<BulkResponse<'a>, Error>> + 'a, Error> {
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
                        0x75 | 0x76 => response.try_into().map(BulkResponseData::Totp),
                        0x77 => Ok(BulkResponseData::Hotp),
                        0x7c => Ok(BulkResponseData::Touch),
                        _ => Err(Error::UnexpectedValue(tag)),
                    }?;
                    let name = std::str::from_utf8(name)?;
                    let response = BulkResponse { name, data: inner };
                    tracing::debug!(response = ?response);
                    Ok(response)
                }))
            }
        }))
    }
}
