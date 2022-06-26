use std::str;
use std::str::Utf8Error;

use super::super::enums::{ComplianceError, RfcSpec};
use super::base::GenericAttrReader;

pub struct PasswordAttributeReader<'a> {
    bytes: &'a [u8],
}

impl<'a> PasswordAttributeReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn get_password(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.bytes[2..2 + self.get_value_length() as usize])
    }
}

impl GenericAttrReader for PasswordAttributeReader<'_> {
    fn get_bytes(&self) -> &[u8] {
        self.bytes
    }

    fn get_rfc_spec(&self) -> RfcSpec {
        RfcSpec::Rfc3489
    }

    fn check_compliance(&self) -> Vec<ComplianceError> {
        todo!()
    }

    fn is_deprecated(&self) -> bool {
        true
    }
}
