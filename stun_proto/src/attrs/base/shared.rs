use std::convert::TryInto;
use super::malformed::MalformedAttrReader;
use super::unknown::UnknownAttrReader;
use super::super::super::enums::{ComplianceError, ComprehensionCategory, RfcSpec};

pub enum NonParsableAttribute<'a> {
    Unknown(UnknownAttrReader<'a>),
    Malformed(MalformedAttrReader<'a>),
}

pub trait GenericAttrReader {
    fn get_bytes(&self) -> &[u8];

    fn get_value_raw(&self) -> &[u8] {
        &self.get_bytes()[4..(self.get_value_length() as usize)]
    }

    fn get_type_raw(&self) -> u16 {
        u16::from_be_bytes(self.get_bytes()[0..2].try_into().unwrap())
    }

    fn get_value_length(&self) -> u16 {
        u16::from_be_bytes(self.get_bytes()[2..4].try_into().unwrap())
    }

    fn get_total_length(&self) -> u16 {
        4 + ((self.get_value_length() + 4 - 1) & (-4i16 as u16))
    }

    fn get_rfc_spec(&self) -> RfcSpec;

    fn get_comprehension_category(&self) -> ComprehensionCategory {
        let typ = self.get_type_raw();
        if typ <= 0x7FFF { ComprehensionCategory::Required } else { ComprehensionCategory::Optional }
    }

    fn check_compliance(&self) -> Vec<ComplianceError>;

    fn is_deprecated(&self) -> bool;
}
