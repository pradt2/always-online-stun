mod base;
mod response_origin;
mod alternate_server;
mod other_address;
mod xor_mapped_address;
mod opt_xor_mapped_address;
mod mapped_address;
mod response_address;
mod change_address;
mod source_address;
mod changed_address;
mod reflected_from;
mod username;
mod password;
mod realm;
mod nonce;
mod unknown_attributes;
mod message_integrity;
mod fingerprint;
mod error_code;
mod software;

pub use alternate_server::AlternateServerAttributeReader;
pub use change_address::ChangeAddressAttributeReader;
pub use changed_address::ChangedAddressAttributeReader;
pub use error_code::ErrorCodeAttributeReader;
pub use fingerprint::FingerprintAttributeReader;
pub use mapped_address::MappedAddressAttributeReader;
pub use message_integrity::MessageIntegrityAttributeReader;
pub use nonce::NonceAttributeReader;
pub use opt_xor_mapped_address::OptXorMappedAddressAttributeReader;
pub use other_address::OtherAddressAttributeReader;
pub use password::PasswordAttributeReader;
pub use realm::RealmAttributeReader;
pub use reflected_from::ReflectedFromAttributeReader;
pub use response_address::ResponseAddressAttributeReader;
pub use response_origin::ResponseOriginAttributeReader;
pub use software::SoftwareAttributeReader;
pub use source_address::SourceAddressAttributeReader;
pub use unknown_attributes::UnknownAttributesAttributeReader;
pub use username::UsernameAttributeReader;
pub use xor_mapped_address::XorMappedAddressAttributeReader;
pub use base::*;

use crate::stun_codec::enums::{ComplianceError, RfcSpec};

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
