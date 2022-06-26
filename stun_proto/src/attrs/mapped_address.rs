use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use super::super::enums::{AddressFamily, ComplianceError, RfcSpec};
use super::base::GenericAttrReader;

pub struct MappedAddressAttributeReader<'a> {
    bytes: &'a [u8],
}

impl<'a> MappedAddressAttributeReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn get_address_family(&self) -> Result<AddressFamily, u8> {
        let family_code = self.get_address_family_raw();
        match family_code {
            1 => Ok(AddressFamily::V4),
            2 => Ok(AddressFamily::V6),
            _ => Err(family_code)
        }
    }

    pub fn get_address_family_raw(&self) -> u8 {
        self.bytes[5]
    }

    pub fn get_port(&self) -> u16 {
        u16::from_be_bytes(self.bytes[6..8].try_into().unwrap())
    }

    pub fn get_address(&self) -> Result<IpAddr, u8> {
        match self.get_address_family()? {
            AddressFamily::V4 => {
                let ip_num = u32::from_be_bytes(self.bytes[8..12].try_into().unwrap());
                Ok(IpAddr::V4(Ipv4Addr::from(ip_num)))
            }
            AddressFamily::V6 => {
                let ip_num = u128::from_be_bytes(self.bytes[8..24].try_into().unwrap());
                Ok(IpAddr::V6(Ipv6Addr::from(ip_num)))
            }
        }
    }
}

impl GenericAttrReader for MappedAddressAttributeReader<'_> {
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
