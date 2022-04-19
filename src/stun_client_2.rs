use std::cmp::min;
use std::convert::TryInto;
use std::io::ErrorKind::Other;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub enum MessageClass {
    Request,
    Indirection,
    SuccessResponse,
    ErrorResponse,
}

#[derive(Debug)]
pub enum Method {
    Binding
}

pub enum ComprehensionCategory {
    Mandatory,
    Optional,
}

pub struct MalformedAttrReader<'a> {
    bytes: &'a [u8],
}

impl MalformedAttrReader<'_> {
    pub fn get_type_raw(&self) -> u16 {
        match self.bytes.len() {
            0 => 0,
            1 => u8::from_be(self.bytes[0]) as u16,
            _ => u16::from_be_bytes(self.bytes[0..2].try_into().unwrap()),
        }
    }

    pub fn get_value_length_raw(&self) -> u16 {
        match self.bytes.len() {
            0 | 1 | 2 => 0,
            3 => u8::from_be(self.bytes[2]) as u16,
            _ => u16::from_be_bytes(self.bytes[2..4].try_into().unwrap()),
        }
    }

    pub fn get_value_raw(&self) -> &[u8] {
        match self.bytes.len() {
            0 | 1 | 2 | 3 | 4 => self.bytes[0..0].as_ref(),
            _ => {
                let length_raw = self.get_value_length_raw() as usize;
                let target_value_size = min(length_raw, self.bytes.len() - 4) / 4;
                self.bytes[5..target_value_size].as_ref()
            }
        }
    }
}

pub struct UnknownAttrReader<'a> {
    bytes: &'a [u8],
}

impl UnknownAttrReader<'_> {
    pub fn get_value_raw(&self) -> &[u8] {
        self.bytes[4..(self.get_value_length() as usize)].as_ref()
    }

    pub fn get_type_raw(&self) -> u16 {
        u16::from_be_bytes(self.bytes[0..2].try_into().unwrap())
    }

    pub fn get_comprehension_category(&self) -> ComprehensionCategory {
        let typ = self.get_type_raw();
        if typ <= 0x07FF { ComprehensionCategory::Mandatory } else { ComprehensionCategory::Optional }
    }

    pub fn get_value_length(&self) -> u16 {
        u16::from_be_bytes(self.bytes[2..4].try_into().unwrap())
    }

    pub fn get_total_length(&self) -> u16 { 4 + ((self.get_value_length() + 4 - 1) & (-4i16 as u16)) }
}

pub enum RfcSpec {
    Rfc3489,
    Rfc5245,
    Rfc5389,
    Rfc5766,
    Rfc5780,
}

#[derive(PartialEq)]
pub enum AddressFamily {
    V4,
    V6,
}

pub trait GenericAttrReader {
    fn get_bytes(&self) -> &[u8];

    fn get_value_raw(&self) -> &[u8] {
        self.get_bytes()[4..(self.get_value_length() as usize)].as_ref()
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
        if typ <= 0x07FF { ComprehensionCategory::Mandatory } else { ComprehensionCategory::Optional }
    }

    fn check_compliance(&self) -> Vec<ComplianceError>;

    fn is_deprecated(&self) -> bool;
}

pub struct MappedAddressAttributeReader<'a> {
    bytes: &'a [u8],
}

impl MappedAddressAttributeReader<'_> {
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

pub struct ResponseOriginAttributeReader<'a> {
    bytes: &'a [u8],
}

impl ResponseOriginAttributeReader<'_> {
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

impl GenericAttrReader for ResponseOriginAttributeReader<'_> {
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

pub struct OtherAddressAttributeReader<'a> {
    bytes: &'a [u8],
}

impl OtherAddressAttributeReader<'_> {
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

impl GenericAttrReader for OtherAddressAttributeReader<'_> {
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

pub struct XorMappedAddressAttributeReader<'a> {
    bytes: &'a [u8],
    transaction_id: &'a [u8; 12],
}

impl XorMappedAddressAttributeReader<'_> {
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

pub struct OptXorMappedAddressAttributeReader<'a> {
    bytes: &'a [u8],
    transaction_id: &'a [u8; 12],
}

impl OptXorMappedAddressAttributeReader<'_> {
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

impl GenericAttrReader for OptXorMappedAddressAttributeReader<'_> {
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

pub enum Attribute<'a> {
    MappedAddress(MappedAddressAttributeReader<'a>),
    XorMappedAddress(XorMappedAddressAttributeReader<'a>),
    OptXorMappedAddress(OptXorMappedAddressAttributeReader<'a>),
    OtherAddress(OtherAddressAttributeReader<'a>),
    ResponseOrigin(ResponseOriginAttributeReader<'a>),
}

impl GenericAttrReader for Attribute<'_> {
    fn get_bytes(&self) -> &[u8] {
        match self {
            Attribute::MappedAddress(r) => r.get_bytes(),
            Attribute::XorMappedAddress(r) => r.get_bytes(),
            Attribute::OptXorMappedAddress(r) => r.get_bytes(),
            Attribute::OtherAddress(r) => r.get_bytes(),
            Attribute::ResponseOrigin(r) => r.get_bytes(),
        }
    }

    fn get_value_raw(&self) -> &[u8] {
        match self {
            Attribute::MappedAddress(r) => r.get_value_raw(),
            Attribute::XorMappedAddress(r) => r.get_value_raw(),
            Attribute::OptXorMappedAddress(r) => r.get_value_raw(),
            Attribute::OtherAddress(r) => r.get_value_raw(),
            Attribute::ResponseOrigin(r) => r.get_value_raw(),
        }
    }

    fn get_type_raw(&self) -> u16 {
        match self {
            Attribute::MappedAddress(r) => r.get_type_raw(),
            Attribute::XorMappedAddress(r) => r.get_type_raw(),
            Attribute::OptXorMappedAddress(r) => r.get_type_raw(),
            Attribute::OtherAddress(r) => r.get_type_raw(),
            Attribute::ResponseOrigin(r) => r.get_type_raw(),
        }
    }

    fn get_value_length(&self) -> u16 {
        match self {
            Attribute::MappedAddress(r) => r.get_value_length(),
            Attribute::XorMappedAddress(r) => r.get_value_length(),
            Attribute::OptXorMappedAddress(r) => r.get_value_length(),
            Attribute::OtherAddress(r) => r.get_value_length(),
            Attribute::ResponseOrigin(r) => r.get_value_length(),
        }
    }

    fn get_total_length(&self) -> u16 {
        match self {
            Attribute::MappedAddress(r) => r.get_total_length(),
            Attribute::XorMappedAddress(r) => r.get_total_length(),
            Attribute::OptXorMappedAddress(r) => r.get_total_length(),
            Attribute::OtherAddress(r) => r.get_total_length(),
            Attribute::ResponseOrigin(r) => r.get_total_length(),
        }
    }

    fn get_rfc_spec(&self) -> RfcSpec {
        match self {
            Attribute::MappedAddress(r) => r.get_rfc_spec(),
            Attribute::XorMappedAddress(r) => r.get_rfc_spec(),
            Attribute::OptXorMappedAddress(r) => r.get_rfc_spec(),
            Attribute::OtherAddress(r) => r.get_rfc_spec(),
            Attribute::ResponseOrigin(r) => r.get_rfc_spec(),
        }
    }

    fn check_compliance(&self) -> Vec<ComplianceError> {
        match self {
            Attribute::MappedAddress(r) => r.check_compliance(),
            Attribute::XorMappedAddress(r) => r.check_compliance(),
            Attribute::OptXorMappedAddress(r) => r.check_compliance(),
            Attribute::OtherAddress(r) => r.check_compliance(),
            Attribute::ResponseOrigin(r) => r.check_compliance(),
        }
    }

    fn is_deprecated(&self) -> bool {
        match self {
            Attribute::MappedAddress(r) => r.is_deprecated(),
            Attribute::XorMappedAddress(r) => r.is_deprecated(),
            Attribute::OptXorMappedAddress(r) => r.is_deprecated(),
            Attribute::OtherAddress(r) => r.is_deprecated(),
            Attribute::ResponseOrigin(r) => r.is_deprecated(),
        }
    }
}

pub enum NonParsableAttribute<'a> {
    Unknown(UnknownAttrReader<'a>),
    Malformed(MalformedAttrReader<'a>),
}

pub struct Iter<'a> {
    attr_bytes: &'a [u8],
    curr_offset: usize,
    transaction_id: &'a [u8; 12],
}

impl<'a> Iterator for Iter<'a> {
    type Item = Result<Attribute<'a>, NonParsableAttribute<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.attr_bytes.len() - self.curr_offset == 0 { return None; }

        let bytes = self.attr_bytes[self.curr_offset..self.attr_bytes.len()].as_ref();

        if self.attr_bytes.len() - self.curr_offset <= 4 {
            let item = Some(
                Err(
                    NonParsableAttribute::Malformed(
                        MalformedAttrReader {
                            bytes
                        }
                    )
                )
            );
            self.curr_offset = self.attr_bytes.len();
            return item;
        }

        let typ = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        let transaction_id = self.transaction_id;

        let res = match typ {
            0x0001 => Ok(Attribute::MappedAddress(MappedAddressAttributeReader { bytes })),
            0x0020 => Ok(Attribute::XorMappedAddress(XorMappedAddressAttributeReader { bytes, transaction_id })),
            0x8020 => Ok(Attribute::OptXorMappedAddress(OptXorMappedAddressAttributeReader { bytes, transaction_id })),
            0x802b => Ok(Attribute::ResponseOrigin(ResponseOriginAttributeReader { bytes })),
            0x802c => Ok(Attribute::OtherAddress(OtherAddressAttributeReader { bytes })),
            _ => Err(NonParsableAttribute::Unknown(UnknownAttrReader { bytes }))
        };

        let offset_delta = match &res {
            Ok(attr) => attr.get_total_length() as usize,
            Err(NonParsableAttribute::Unknown(reader)) => reader.get_total_length() as usize,
            Err(NonParsableAttribute::Malformed(_)) => self.attr_bytes.len() - self.curr_offset,
        };

        self.curr_offset += offset_delta;

        Some(res)
    }
}

pub struct StunMessageReader<'a> {
    pub(crate) bytes: &'a [u8],
}

pub enum ComplianceError {}

impl StunMessageReader<'_> {
    pub fn get_message_type(&self) -> u16 {
        u16::from_be_bytes(self.bytes[0..2].try_into().unwrap())
    }

    pub fn get_method(&self) -> Result<Method, u16> {
        let method_code = self.get_method_raw();
        match method_code {
            1 => Ok(Method::Binding),
            _ => Err(method_code)
        }
    }

    pub fn get_method_raw(&self) -> u16 {
        let msg_type = self.get_message_type();
        let method_code: u16 = msg_type & 0b11111011101111;
        method_code
    }

    pub fn get_class(&self) -> MessageClass {
        let class = self.get_class_raw();
        match class {
            0b000000000 => MessageClass::Request,
            0b000010000 => MessageClass::Indirection,
            0b100000000 => MessageClass::SuccessResponse,
            0b100010000 => MessageClass::ErrorResponse,
            _ => panic!("Impossible message class")
        }
    }

    pub fn get_class_raw(&self) -> u16 {
        let msg_type = self.get_message_type();
        let class = msg_type & !0b11111011101111;
        class
    }

    pub fn get_length(&self) -> u16 {
        u16::from_be_bytes(self.bytes[2..4].try_into().unwrap())
    }

    pub fn get_attrs(&self) -> Iter {
        Iter {
            attr_bytes: self.bytes[20..(self.bytes.len())].as_ref(),
            curr_offset: 0,
            transaction_id: self.bytes[8..20].try_into().unwrap(),
        }
    }

    pub fn check_header_spec_compliance(&self) -> Vec<ComplianceError> { todo!() }

    pub fn is_compliant(&self) -> bool {
        if !self.check_header_spec_compliance().is_empty() { return false; }

        for attr in self.get_attrs() {
            match attr {
                Ok(attr) => if !attr.check_compliance().is_empty() { return false; }
                Err(_) => return false,
            }
        }

        true
    }
}
