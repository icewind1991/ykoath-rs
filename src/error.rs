use std::str::Utf8Error;

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
    #[error("Non utf8 key name")]
    Utf8(#[from] Utf8Error),
}
