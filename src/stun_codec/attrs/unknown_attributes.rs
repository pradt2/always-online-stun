use std::convert::TryInto;

use super::base::GenericAttrReader;
use super::super::enums::{ComplianceError, RfcSpec};

pub struct UnknownAttributesAttributeReader<'a> {
    bytes: &'a [u8],
}

pub struct UnknownAttrIter<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Iterator for UnknownAttrIter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            None
        } else {
            let attr = u16::from_be_bytes(self.bytes[self.offset..self.offset + 2].try_into().unwrap());
            self.offset += 2;
            Some(attr)
        }
    }
}

impl<'a> UnknownAttributesAttributeReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn get_attr_codes(&self) -> UnknownAttrIter {
        UnknownAttrIter {
            bytes: &self.bytes[2..2+self.get_value_length() as usize],
            offset: 0
        }
    }
}

impl GenericAttrReader for UnknownAttributesAttributeReader<'_> {
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
        false
    }
}
