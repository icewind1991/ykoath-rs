use crate::{Error, Payload, YubiKey};
use std::fmt::{Display, Formatter};
use std::mem::size_of;

#[derive(Debug, Clone)]
pub struct Response {
    pub digits: u8,
    pub response: u32,
}

impl TryFrom<&'_ [u8]> for Response {
    type Error = Error;

    fn try_from(value: &'_ [u8]) -> Result<Self, Self::Error> {
        Ok(Response {
            digits: *value.first().ok_or(Error::InsufficientData)?,
            response: u32::from_be_bytes(
                value
                    .get(1..(1 + size_of::<u32>()))
                    .ok_or(Error::InsufficientData)?
                    .try_into()
                    .unwrap(),
            ),
        })
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let code = self.response % 10_u32.pow(u32::from(self.digits));

        write!(f, "{:01$}", code, self.digits as usize)
    }
}

impl YubiKey {
    #[tracing::instrument(skip(self, buf))]
    pub fn calculate<C: Payload>(
        &self,
        truncate: bool,
        name: &[u8],
        challenge: C,
        buf: &mut Vec<u8>,
    ) -> Result<Response, Error> {
        buf.clear();
        buf.extend_from_slice(&[0x00, 0xa2, 0x00, if truncate { 0x01 } else { 0x00 }]);
        buf.push(0x00);
        Self::push(buf, 0x71, name);
        Self::push(buf, 0x74, challenge);
        let mut response = self.transmit(buf)?;
        let (_, response) = Self::pop(&mut response, &[if truncate { 0x76 } else { 0x75 }])?;
        let response = response.try_into()?;
        tracing::debug!(response = ?response);
        Ok(response)
    }
}
