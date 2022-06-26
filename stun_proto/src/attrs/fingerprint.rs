use std::convert::TryInto;
use super::super::enums::{ComplianceError, RfcSpec};
use super::base::GenericAttrReader;

pub struct FingerprintAttributeReader<'a> {
    bytes: &'a [u8],
}

impl<'a> FingerprintAttributeReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn get_checksum(&self) -> u32 {
        u32::from_be_bytes(self.bytes[2..2 + self.get_value_length() as usize].try_into().unwrap()) ^ 0x5354554E
    }
}

impl GenericAttrReader for FingerprintAttributeReader<'_> {
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
