use std::net::IpAddr;
use super::mapped_address::MappedAddressAttributeReader;
use super::super::enums::{AddressFamily, ComplianceError, RfcSpec};
use super::base::GenericAttrReader;

pub struct SourceAddressAttributeReader<'a> {
    mapped_address_reader: MappedAddressAttributeReader<'a>,
}

impl<'a> SourceAddressAttributeReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            mapped_address_reader: MappedAddressAttributeReader::new(bytes)
        }
    }

    pub fn get_address_family(&self) -> Result<AddressFamily, u8> {
        self.mapped_address_reader.get_address_family()
    }

    pub fn get_address_family_raw(&self) -> u8 {
        self.mapped_address_reader.get_address_family_raw()
    }

    pub fn get_port(&self) -> u16 {
        self.mapped_address_reader.get_port()
    }

    pub fn get_address(&self) -> Result<IpAddr, u8> {
        self.mapped_address_reader.get_address()
    }
}

impl GenericAttrReader for SourceAddressAttributeReader<'_> {
    fn get_bytes(&self) -> &[u8] {
        self.mapped_address_reader.get_bytes()
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
