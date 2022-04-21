use std::convert::TryInto;
use super::super::super::enums::ComprehensionCategory;

pub struct UnknownAttrReader<'a> {
    bytes: &'a [u8],
}

impl<'a> UnknownAttrReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn get_value_raw(&self) -> &[u8] {
        &self.bytes[4..(self.get_value_length() as usize)]
    }

    pub fn get_type_raw(&self) -> u16 {
        u16::from_be_bytes(self.bytes[0..2].try_into().unwrap())
    }

    pub fn get_comprehension_category(&self) -> ComprehensionCategory {
        let typ = self.get_type_raw();
        if typ <= 0x7FFF { ComprehensionCategory::Required } else { ComprehensionCategory::Optional }
    }

    pub fn get_value_length(&self) -> u16 {
        u16::from_be_bytes(self.bytes[2..4].try_into().unwrap())
    }

    pub fn get_total_length(&self) -> u16 { 4 + ((self.get_value_length() + 4 - 1) & (-4i16 as u16)) }
}
