use std::convert::TryInto;
use super::super::enums::{ComplianceError, RfcSpec};
use super::base::GenericAttrReader;

pub struct MessageIntegrityAttributeReader<'a> {
    bytes: &'a [u8],
}

impl<'a> MessageIntegrityAttributeReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn get_digest(&self) -> &[u8; 20] {
        self.bytes[2..2 + self.get_value_length() as usize].try_into().unwrap()
    }
}

impl GenericAttrReader for MessageIntegrityAttributeReader<'_> {
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
