use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use super::super::enums::{AddressFamily, ComplianceError, RfcSpec};
use super::base::GenericAttrReader;

pub struct XorMappedAddressAttributeReader<'a> {
    bytes: &'a [u8],
    transaction_id: &'a [u8; 12],
}

impl<'a> XorMappedAddressAttributeReader<'a> {
    pub fn new(bytes: &'a [u8], transaction_id: &'a [u8; 12]) -> Self {
        Self { bytes, transaction_id }
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
        u16::from_be_bytes(self.bytes[6..8].try_into().unwrap()) ^ 0x2112 // xor with top half of magic cookie
    }

    pub fn get_address(&self) -> Result<IpAddr, u8> {
        match self.get_address_family()? {
            AddressFamily::V4 => {
                let ip_num = u32::from_be_bytes(self.bytes[8..12].try_into().unwrap()) ^ 0x2112A442; // xor with magic cookie
                Ok(IpAddr::V4(Ipv4Addr::from(ip_num)))
            }
            AddressFamily::V6 => {
                let t_id = self.transaction_id;
                let xor_mask = 0x2112A442_u128 << 92 | u128::from(u64::from_ne_bytes(t_id[4..12].try_into().unwrap())) << 64 | u32::from_ne_bytes(t_id[0..4].try_into().unwrap()) as u128;
                let ip_num = u128::from_be_bytes(self.bytes[8..24].try_into().unwrap()) ^ xor_mask;
                Ok(IpAddr::V6(Ipv6Addr::from(ip_num)))
            }
        }
    }
}

impl GenericAttrReader for XorMappedAddressAttributeReader<'_> {
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
        false
    }
}
