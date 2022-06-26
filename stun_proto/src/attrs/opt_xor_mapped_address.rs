use std::net::IpAddr;
use super::xor_mapped_address::XorMappedAddressAttributeReader;
use super::super::enums::{AddressFamily, ComplianceError, RfcSpec};
use super::base::GenericAttrReader;

pub struct OptXorMappedAddressAttributeReader<'a> {
    xor_mapped_address_reader: XorMappedAddressAttributeReader<'a>,
}

impl<'a> OptXorMappedAddressAttributeReader<'a> {
    pub fn new(bytes: &'a [u8], transaction_id: &'a [u8; 12]) -> Self {
        Self {
            xor_mapped_address_reader: XorMappedAddressAttributeReader::new(bytes, transaction_id)
        }
    }

    pub fn get_address_family(&self) -> Result<AddressFamily, u8> {
        self.xor_mapped_address_reader.get_address_family()
    }

    pub fn get_address_family_raw(&self) -> u8 {
        self.xor_mapped_address_reader.get_address_family_raw()
    }

    pub fn get_port(&self) -> u16 {
        self.xor_mapped_address_reader.get_port()
    }

    pub fn get_address(&self) -> Result<IpAddr, u8> {
        self.xor_mapped_address_reader.get_address()
    }
}

impl GenericAttrReader for OptXorMappedAddressAttributeReader<'_> {
    fn get_bytes(&self) -> &[u8] {
        self.xor_mapped_address_reader.get_bytes()
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
