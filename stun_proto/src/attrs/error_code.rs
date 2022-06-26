use std::str;
use std::str::Utf8Error;

use super::super::enums::{ComplianceError, ErrorCode, RfcSpec};
use super::base::GenericAttrReader;

pub struct ErrorCodeAttributeReader<'a> {
    bytes: &'a [u8],
}

impl<'a> ErrorCodeAttributeReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn get_error(&self) -> Result<ErrorCode, u16> {
        let error_code = self.get_error_code_raw();
        match error_code {
            300 => Ok(ErrorCode::TryAlternate),
            400 => Ok(ErrorCode::BadRequest),
            401 => Ok(ErrorCode::Unauthorized),
            420 => Ok(ErrorCode::UnknownAttribute),
            438 => Ok(ErrorCode::StaleNonce),
            500 => Ok(ErrorCode::InternalServerError),
            _ => Err(error_code)
        }
    }

    pub fn get_reason(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.bytes[4..(4 + self.get_value_length() - 2) as usize])
    }

    pub fn get_error_code_raw(&self) -> u16 {
        self.get_class() as u16 * 100 + self.get_number() as u16
    }

    pub fn get_class(&self) -> u8 {
        self.bytes[5] >> 5
    }

    pub fn get_number(&self) -> u8 {
        self.bytes[6]
    }
}

impl GenericAttrReader for ErrorCodeAttributeReader<'_> {
    fn get_bytes(&self) -> &[u8] {
        self.bytes
    }

    fn get_rfc_spec(&self) -> RfcSpec {
        RfcSpec::Rfc5389
    }

    fn check_compliance(&self) -> Vec<ComplianceError> {
        todo!()
    }

    fn is_deprecated(&self) -> bool {
        true
    }
}
