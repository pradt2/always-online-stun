use std::cmp::min;
use std::convert::TryInto;
use std::io::ErrorKind::Other;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;
use std::str::Utf8Error;

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
    Required,
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
            0 | 1 | 2 | 3 | 4 => 0,
            _ => u16::from_be_bytes(self.bytes[2..4].try_into().unwrap()),
        }
    }

    pub fn get_value_raw(&self) -> &[u8] {
        match self.bytes.len() {
            0 | 1 | 2 | 3 | 4 => &self.bytes[0..0],
            _ => {
                let length_raw = self.get_value_length_raw() as usize;
                let target_value_size = min(length_raw, self.bytes.len() - 4) / 4;
                &self.bytes[5..target_value_size]
            }
        }
    }
}

pub struct UnknownAttrReader<'a> {
    bytes: &'a [u8],
}

impl UnknownAttrReader<'_> {
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
    mapped_address_reader: MappedAddressAttributeReader<'a>,
}

impl ResponseOriginAttributeReader<'_> {
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

impl GenericAttrReader for ResponseOriginAttributeReader<'_> {
    fn get_bytes(&self) -> &[u8] {
        self.mapped_address_reader.get_bytes()
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

pub struct AlternateServerAttributeReader<'a> {
    mapped_address_reader: MappedAddressAttributeReader<'a>,
}

impl AlternateServerAttributeReader<'_> {
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

impl GenericAttrReader for AlternateServerAttributeReader<'_> {
    fn get_bytes(&self) -> &[u8] {
        self.mapped_address_reader.get_bytes()
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
    mapped_address_reader: MappedAddressAttributeReader<'a>,
}

impl OtherAddressAttributeReader<'_> {
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

impl GenericAttrReader for OtherAddressAttributeReader<'_> {
    fn get_bytes(&self) -> &[u8] {
        self.mapped_address_reader.get_bytes()
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
    xor_mapped_address_reader: XorMappedAddressAttributeReader<'a>,
}

impl OptXorMappedAddressAttributeReader<'_> {
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

pub struct ResponseAddressAttributeReader<'a> {
    mapped_address_reader: MappedAddressAttributeReader<'a>,
}

impl ResponseAddressAttributeReader<'_> {
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

impl GenericAttrReader for ResponseAddressAttributeReader<'_> {
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

pub struct ChangeAddressAttributeReader<'a> {
    mapped_address_reader: MappedAddressAttributeReader<'a>,
}

impl ChangeAddressAttributeReader<'_> {
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

impl GenericAttrReader for ChangeAddressAttributeReader<'_> {
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

pub struct SourceAddressAttributeReader<'a> {
    mapped_address_reader: MappedAddressAttributeReader<'a>,
}

impl SourceAddressAttributeReader<'_> {
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

pub struct ChangedAddressAttributeReader<'a> {
    mapped_address_reader: MappedAddressAttributeReader<'a>,
}

impl ChangedAddressAttributeReader<'_> {
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

impl GenericAttrReader for ChangedAddressAttributeReader<'_> {
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

pub struct ReflectedFromAttributeReader<'a> {
    mapped_address_reader: MappedAddressAttributeReader<'a>,
}

impl ReflectedFromAttributeReader<'_> {
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

impl GenericAttrReader for ReflectedFromAttributeReader<'_> {
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

pub struct UsernameAttributeReader<'a> {
    bytes: &'a [u8],
}

impl UsernameAttributeReader<'_> {
    pub fn get_username(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.bytes[2..2 + self.get_value_length() as usize])
    }
}

impl GenericAttrReader for UsernameAttributeReader<'_> {
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

pub struct PasswordAttributeReader<'a> {
    bytes: &'a [u8],
}

impl PasswordAttributeReader<'_> {
    pub fn get_password(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.bytes[2..2 + self.get_value_length() as usize])
    }
}

impl GenericAttrReader for PasswordAttributeReader<'_> {
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

pub struct RealmAttributeReader<'a> {
    bytes: &'a [u8],
}

impl RealmAttributeReader<'_> {
    pub fn get_realm(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.bytes[2..2 + self.get_value_length() as usize])
    }
}

impl GenericAttrReader for RealmAttributeReader<'_> {
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

pub struct NonceAttributeReader<'a> {
    bytes: &'a [u8],
}

impl NonceAttributeReader<'_> {
    pub fn get_nonce(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.bytes[2..2 + self.get_value_length() as usize])
    }
}

impl GenericAttrReader for NonceAttributeReader<'_> {
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

impl UnknownAttributesAttributeReader<'_> {
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

pub struct MessageIntegrityAttributeReader<'a> {
    bytes: &'a [u8],
}

impl MessageIntegrityAttributeReader<'_> {
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

pub struct FingerprintAttributeReader<'a> {
    bytes: &'a [u8],
}

impl FingerprintAttributeReader<'_> {
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

pub struct ErrorCodeAttributeReader<'a> {
    bytes: &'a [u8],
}

#[derive(Debug)]
pub enum ErrorCode {
    TryAlternate,
    BadRequest,
    Unauthorized,
    UnknownAttribute,
    StaleNonce,
    InternalServerError,
}

impl ErrorCodeAttributeReader<'_> {
    pub fn get_error(&self) -> Result<ErrorCode, u16> {
        let error_code = self.get_error_code_raw();
        match error_code {
            300 => Ok(ErrorCode::TryAlternate),
            400 => Ok(ErrorCode::BadRequest),
            401 => Ok(ErrorCode::Unauthorized),
            420 => Ok(ErrorCode::UnknownAttribute),
            438 => Ok(ErrorCode::StaleNonce),
            500 => Ok(ErrorCode::InternalServerError),
            _ => Err(error_code)
        }
    }

    pub fn get_reason(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.bytes[4..(4 + self.get_value_length() - 2) as usize])
    }

    pub fn get_error_code_raw(&self) -> u16 {
        self.get_class() as u16 * 100 + self.get_number() as u16
    }

    pub fn get_class(&self) -> u8 {
        self.bytes[5] >> 5
    }

    pub fn get_number(&self) -> u8 {
        self.bytes[6]
    }
}

impl GenericAttrReader for ErrorCodeAttributeReader<'_> {
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

pub struct SoftwareAttributeReader<'a> {
    bytes: &'a [u8],
}

impl SoftwareAttributeReader<'_> {
    pub fn get_software(&self) -> Result<&str, Utf8Error> {
        str::from_utf8(&self.bytes[2..2 + self.get_value_length() as usize])
    }
}

impl GenericAttrReader for SoftwareAttributeReader<'_> {
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

pub enum Attribute<'a> {
    MappedAddress(MappedAddressAttributeReader<'a>),
    ReflectedFrom(ReflectedFromAttributeReader<'a>),
    ResponseAddress(ResponseAddressAttributeReader<'a>),
    ChangeAddress(ChangeAddressAttributeReader<'a>),
    SourceAddress(SourceAddressAttributeReader<'a>),
    ChangedAddress(ChangedAddressAttributeReader<'a>),
    XorMappedAddress(XorMappedAddressAttributeReader<'a>),
    OptXorMappedAddress(OptXorMappedAddressAttributeReader<'a>),
    OtherAddress(OtherAddressAttributeReader<'a>),
    ResponseOrigin(ResponseOriginAttributeReader<'a>),
    Username(UsernameAttributeReader<'a>),
    Password(PasswordAttributeReader<'a>),
    MessageIntegrity(MessageIntegrityAttributeReader<'a>),
    Fingerprint(FingerprintAttributeReader<'a>),
    ErrorCode(ErrorCodeAttributeReader<'a>),
    Realm(RealmAttributeReader<'a>),
    Nonce(NonceAttributeReader<'a>),
    UnknownAttributes(UnknownAttributesAttributeReader<'a>),
    Software(SoftwareAttributeReader<'a>),
    AlternateServer(AlternateServerAttributeReader<'a>),
}

impl GenericAttrReader for Attribute<'_> {
    fn get_bytes(&self) -> &[u8] {
        match self {
            Attribute::MappedAddress(r) => r.get_bytes(),
            Attribute::ResponseAddress(r) => r.get_bytes(),
            Attribute::ChangeAddress(r) => r.get_bytes(),
            Attribute::SourceAddress(r) => r.get_bytes(),
            Attribute::ChangedAddress(r) => r.get_bytes(),
            Attribute::XorMappedAddress(r) => r.get_bytes(),
            Attribute::OptXorMappedAddress(r) => r.get_bytes(),
            Attribute::OtherAddress(r) => r.get_bytes(),
            Attribute::ResponseOrigin(r) => r.get_bytes(),
            Attribute::Username(r) => r.get_bytes(),
            Attribute::Password(r) => r.get_bytes(),
            Attribute::MessageIntegrity(r) => r.get_bytes(),
            Attribute::Fingerprint(r) => r.get_bytes(),
            Attribute::ErrorCode(r) => r.get_bytes(),
            Attribute::Realm(r) => r.get_bytes(),
            Attribute::Nonce(r) => r.get_bytes(),
            Attribute::UnknownAttributes(r) => r.get_bytes(),
            Attribute::ReflectedFrom(r) => r.get_bytes(),
            Attribute::Software(r) => r.get_bytes(),
            Attribute::AlternateServer(r) => r.get_bytes(),
        }
    }

    fn get_value_raw(&self) -> &[u8] {
        match self {
            Attribute::MappedAddress(r) => r.get_value_raw(),
            Attribute::ResponseAddress(r) => r.get_value_raw(),
            Attribute::ChangeAddress(r) => r.get_value_raw(),
            Attribute::SourceAddress(r) => r.get_value_raw(),
            Attribute::ChangedAddress(r) => r.get_value_raw(),
            Attribute::XorMappedAddress(r) => r.get_value_raw(),
            Attribute::OptXorMappedAddress(r) => r.get_value_raw(),
            Attribute::OtherAddress(r) => r.get_value_raw(),
            Attribute::ResponseOrigin(r) => r.get_value_raw(),
            Attribute::Username(r) => r.get_value_raw(),
            Attribute::Password(r) => r.get_value_raw(),
            Attribute::MessageIntegrity(r) => r.get_value_raw(),
            Attribute::Fingerprint(r) => r.get_value_raw(),
            Attribute::ErrorCode(r) => r.get_value_raw(),
            Attribute::Realm(r) => r.get_value_raw(),
            Attribute::Nonce(r) => r.get_value_raw(),
            Attribute::UnknownAttributes(r) => r.get_value_raw(),
            Attribute::ReflectedFrom(r) => r.get_value_raw(),
            Attribute::Software(r) => r.get_value_raw(),
            Attribute::AlternateServer(r) => r.get_value_raw(),
        }
    }

    fn get_type_raw(&self) -> u16 {
        match self {
            Attribute::MappedAddress(r) => r.get_type_raw(),
            Attribute::ResponseAddress(r) => r.get_type_raw(),
            Attribute::ChangeAddress(r) => r.get_type_raw(),
            Attribute::SourceAddress(r) => r.get_type_raw(),
            Attribute::ChangedAddress(r) => r.get_type_raw(),
            Attribute::XorMappedAddress(r) => r.get_type_raw(),
            Attribute::OptXorMappedAddress(r) => r.get_type_raw(),
            Attribute::OtherAddress(r) => r.get_type_raw(),
            Attribute::ResponseOrigin(r) => r.get_type_raw(),
            Attribute::Username(r) => r.get_type_raw(),
            Attribute::Password(r) => r.get_type_raw(),
            Attribute::MessageIntegrity(r) => r.get_type_raw(),
            Attribute::Fingerprint(r) => r.get_type_raw(),
            Attribute::ErrorCode(r) => r.get_type_raw(),
            Attribute::Realm(r) => r.get_type_raw(),
            Attribute::Nonce(r) => r.get_type_raw(),
            Attribute::UnknownAttributes(r) => r.get_type_raw(),
            Attribute::ReflectedFrom(r) => r.get_type_raw(),
            Attribute::Software(r) => r.get_type_raw(),
            Attribute::AlternateServer(r) => r.get_type_raw(),
        }
    }

    fn get_value_length(&self) -> u16 {
        match self {
            Attribute::MappedAddress(r) => r.get_value_length(),
            Attribute::ResponseAddress(r) => r.get_value_length(),
            Attribute::ChangeAddress(r) => r.get_value_length(),
            Attribute::SourceAddress(r) => r.get_value_length(),
            Attribute::ChangedAddress(r) => r.get_value_length(),
            Attribute::XorMappedAddress(r) => r.get_value_length(),
            Attribute::OptXorMappedAddress(r) => r.get_value_length(),
            Attribute::OtherAddress(r) => r.get_value_length(),
            Attribute::ResponseOrigin(r) => r.get_value_length(),
            Attribute::Username(r) => r.get_value_length(),
            Attribute::Password(r) => r.get_value_length(),
            Attribute::MessageIntegrity(r) => r.get_value_length(),
            Attribute::Fingerprint(r) => r.get_value_length(),
            Attribute::ErrorCode(r) => r.get_value_length(),
            Attribute::Realm(r) => r.get_value_length(),
            Attribute::Nonce(r) => r.get_value_length(),
            Attribute::UnknownAttributes(r) => r.get_value_length(),
            Attribute::ReflectedFrom(r) => r.get_value_length(),
            Attribute::Software(r) => r.get_value_length(),
            Attribute::AlternateServer(r) => r.get_value_length(),
        }
    }

    fn get_total_length(&self) -> u16 {
        match self {
            Attribute::MappedAddress(r) => r.get_total_length(),
            Attribute::ResponseAddress(r) => r.get_total_length(),
            Attribute::ChangeAddress(r) => r.get_total_length(),
            Attribute::SourceAddress(r) => r.get_total_length(),
            Attribute::ChangedAddress(r) => r.get_total_length(),
            Attribute::XorMappedAddress(r) => r.get_total_length(),
            Attribute::OptXorMappedAddress(r) => r.get_total_length(),
            Attribute::OtherAddress(r) => r.get_total_length(),
            Attribute::ResponseOrigin(r) => r.get_total_length(),
            Attribute::Username(r) => r.get_total_length(),
            Attribute::Password(r) => r.get_total_length(),
            Attribute::MessageIntegrity(r) => r.get_total_length(),
            Attribute::Fingerprint(r) => r.get_total_length(),
            Attribute::ErrorCode(r) => r.get_total_length(),
            Attribute::Realm(r) => r.get_total_length(),
            Attribute::Nonce(r) => r.get_total_length(),
            Attribute::UnknownAttributes(r) => r.get_total_length(),
            Attribute::ReflectedFrom(r) => r.get_total_length(),
            Attribute::Software(r) => r.get_total_length(),
            Attribute::AlternateServer(r) => r.get_total_length(),
        }
    }

    fn get_rfc_spec(&self) -> RfcSpec {
        match self {
            Attribute::MappedAddress(r) => r.get_rfc_spec(),
            Attribute::ResponseAddress(r) => r.get_rfc_spec(),
            Attribute::ChangeAddress(r) => r.get_rfc_spec(),
            Attribute::SourceAddress(r) => r.get_rfc_spec(),
            Attribute::ChangedAddress(r) => r.get_rfc_spec(),
            Attribute::XorMappedAddress(r) => r.get_rfc_spec(),
            Attribute::OptXorMappedAddress(r) => r.get_rfc_spec(),
            Attribute::OtherAddress(r) => r.get_rfc_spec(),
            Attribute::ResponseOrigin(r) => r.get_rfc_spec(),
            Attribute::Username(r) => r.get_rfc_spec(),
            Attribute::Password(r) => r.get_rfc_spec(),
            Attribute::MessageIntegrity(r) => r.get_rfc_spec(),
            Attribute::Fingerprint(r) => r.get_rfc_spec(),
            Attribute::ErrorCode(r) => r.get_rfc_spec(),
            Attribute::Realm(r) => r.get_rfc_spec(),
            Attribute::Nonce(r) => r.get_rfc_spec(),
            Attribute::UnknownAttributes(r) => r.get_rfc_spec(),
            Attribute::ReflectedFrom(r) => r.get_rfc_spec(),
            Attribute::Software(r) => r.get_rfc_spec(),
            Attribute::AlternateServer(r) => r.get_rfc_spec(),
        }
    }

    fn check_compliance(&self) -> Vec<ComplianceError> {
        match self {
            Attribute::MappedAddress(r) => r.check_compliance(),
            Attribute::ResponseAddress(r) => r.check_compliance(),
            Attribute::ChangeAddress(r) => r.check_compliance(),
            Attribute::SourceAddress(r) => r.check_compliance(),
            Attribute::ChangedAddress(r) => r.check_compliance(),
            Attribute::XorMappedAddress(r) => r.check_compliance(),
            Attribute::OptXorMappedAddress(r) => r.check_compliance(),
            Attribute::OtherAddress(r) => r.check_compliance(),
            Attribute::ResponseOrigin(r) => r.check_compliance(),
            Attribute::Username(r) => r.check_compliance(),
            Attribute::Password(r) => r.check_compliance(),
            Attribute::MessageIntegrity(r) => r.check_compliance(),
            Attribute::Fingerprint(r) => r.check_compliance(),
            Attribute::ErrorCode(r) => r.check_compliance(),
            Attribute::Realm(r) => r.check_compliance(),
            Attribute::Nonce(r) => r.check_compliance(),
            Attribute::UnknownAttributes(r) => r.check_compliance(),
            Attribute::ReflectedFrom(r) => r.check_compliance(),
            Attribute::Software(r) => r.check_compliance(),
            Attribute::AlternateServer(r) => r.check_compliance(),
        }
    }

    fn is_deprecated(&self) -> bool {
        match self {
            Attribute::MappedAddress(r) => r.is_deprecated(),
            Attribute::ResponseAddress(r) => r.is_deprecated(),
            Attribute::ChangeAddress(r) => r.is_deprecated(),
            Attribute::SourceAddress(r) => r.is_deprecated(),
            Attribute::ChangedAddress(r) => r.is_deprecated(),
            Attribute::XorMappedAddress(r) => r.is_deprecated(),
            Attribute::OptXorMappedAddress(r) => r.is_deprecated(),
            Attribute::OtherAddress(r) => r.is_deprecated(),
            Attribute::ResponseOrigin(r) => r.is_deprecated(),
            Attribute::Username(r) => r.is_deprecated(),
            Attribute::Password(r) => r.is_deprecated(),
            Attribute::MessageIntegrity(r) => r.is_deprecated(),
            Attribute::Fingerprint(r) => r.is_deprecated(),
            Attribute::ErrorCode(r) => r.is_deprecated(),
            Attribute::Realm(r) => r.is_deprecated(),
            Attribute::Nonce(r) => r.is_deprecated(),
            Attribute::UnknownAttributes(r) => r.is_deprecated(),
            Attribute::ReflectedFrom(r) => r.is_deprecated(),
            Attribute::Software(r) => r.is_deprecated(),
            Attribute::AlternateServer(r) => r.is_deprecated(),
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

        let bytes = &self.attr_bytes[self.curr_offset..self.attr_bytes.len()];

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
            0x0002 => Ok(Attribute::ResponseAddress(ResponseAddressAttributeReader { mapped_address_reader: MappedAddressAttributeReader { bytes } })),
            0x0003 => Ok(Attribute::ChangeAddress(ChangeAddressAttributeReader { mapped_address_reader: MappedAddressAttributeReader { bytes } })),
            0x0004 => Ok(Attribute::SourceAddress(SourceAddressAttributeReader { mapped_address_reader: MappedAddressAttributeReader { bytes } })),
            0x0005 => Ok(Attribute::ChangedAddress(ChangedAddressAttributeReader { mapped_address_reader: MappedAddressAttributeReader { bytes } })),
            0x0006 => Ok(Attribute::Username(UsernameAttributeReader { bytes })),
            0x0007 => Ok(Attribute::Password(PasswordAttributeReader { bytes })),
            0x0008 => Ok(Attribute::MessageIntegrity(MessageIntegrityAttributeReader { bytes })),
            0x000A => Ok(Attribute::UnknownAttributes(UnknownAttributesAttributeReader { bytes })),
            0x000B => Ok(Attribute::ReflectedFrom(ReflectedFromAttributeReader { mapped_address_reader: MappedAddressAttributeReader { bytes } })),
            0x0009 => Ok(Attribute::ErrorCode(ErrorCodeAttributeReader { bytes })),
            0x0014 => Ok(Attribute::Realm(RealmAttributeReader { bytes })),
            0x0015 => Ok(Attribute::Nonce(NonceAttributeReader { bytes })),
            0x0020 => Ok(Attribute::XorMappedAddress(XorMappedAddressAttributeReader { bytes, transaction_id })),
            0x8020 => Ok(Attribute::OptXorMappedAddress(OptXorMappedAddressAttributeReader { xor_mapped_address_reader: XorMappedAddressAttributeReader { bytes, transaction_id } })),
            0x8022 => Ok(Attribute::Software(SoftwareAttributeReader { bytes })),
            0x8023 => Ok(Attribute::AlternateServer(AlternateServerAttributeReader { mapped_address_reader: MappedAddressAttributeReader { bytes } })),
            0x802b => Ok(Attribute::ResponseOrigin(ResponseOriginAttributeReader { mapped_address_reader: MappedAddressAttributeReader { bytes } })),
            0x802c => Ok(Attribute::OtherAddress(OtherAddressAttributeReader { mapped_address_reader: MappedAddressAttributeReader { bytes } })),
            0x8028 => Ok(Attribute::Fingerprint(FingerprintAttributeReader { bytes })),
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
            attr_bytes: &self.bytes[20..(self.bytes.len())],
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
