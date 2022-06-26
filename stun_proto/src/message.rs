use std::convert::TryInto;
use super::enums::{ComplianceError, MessageClass, Method};
use super::attrs::*;

pub struct StunMessageReader<'a> {
    pub(crate) bytes: &'a [u8],
}

impl StunMessageReader<'_> {
    pub fn get_message_type(&self) -> u16 {
        u16::from_be_bytes(self.bytes[0..2].try_into().unwrap())
    }

    pub fn get_method_raw(&self) -> u16 {
        let msg_type = self.get_message_type();
        let method_code: u16 = msg_type & 0b0011111011101111;
        method_code
    }


    pub fn get_method(&self) -> Result<Method, u16> {
        let method_code = self.get_method_raw();
        match method_code {
            1 => Ok(Method::Binding),
            _ => Err(method_code)
        }
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
                        MalformedAttrReader::new(bytes)
                    )
                )
            );
            self.curr_offset = self.attr_bytes.len();
            return item;
        }

        let typ = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        let transaction_id = self.transaction_id;

        let res = match typ {
            0x0001 => Ok(Attribute::MappedAddress(MappedAddressAttributeReader::new(bytes))),
            0x0002 => Ok(Attribute::ResponseAddress(ResponseAddressAttributeReader::new(bytes))),
            0x0003 => Ok(Attribute::ChangeAddress(ChangeAddressAttributeReader::new(bytes))),
            0x0004 => Ok(Attribute::SourceAddress(SourceAddressAttributeReader::new(bytes))),
            0x0005 => Ok(Attribute::ChangedAddress(ChangedAddressAttributeReader::new(bytes))),
            0x0006 => Ok(Attribute::Username(UsernameAttributeReader::new(bytes))),
            0x0007 => Ok(Attribute::Password(PasswordAttributeReader::new(bytes))),
            0x0008 => Ok(Attribute::MessageIntegrity(MessageIntegrityAttributeReader::new(bytes))),
            0x000A => Ok(Attribute::UnknownAttributes(UnknownAttributesAttributeReader::new(bytes))),
            0x000B => Ok(Attribute::ReflectedFrom(ReflectedFromAttributeReader::new(bytes))),
            0x0009 => Ok(Attribute::ErrorCode(ErrorCodeAttributeReader::new(bytes))),
            0x0014 => Ok(Attribute::Realm(RealmAttributeReader::new(bytes))),
            0x0015 => Ok(Attribute::Nonce(NonceAttributeReader::new(bytes))),
            0x0020 => Ok(Attribute::XorMappedAddress(XorMappedAddressAttributeReader::new(bytes, transaction_id))),
            0x8020 => Ok(Attribute::OptXorMappedAddress(OptXorMappedAddressAttributeReader::new(bytes, transaction_id))),
            0x8022 => Ok(Attribute::Software(SoftwareAttributeReader::new(bytes))),
            0x8023 => Ok(Attribute::AlternateServer(AlternateServerAttributeReader::new(bytes))),
            0x802b => Ok(Attribute::ResponseOrigin(ResponseOriginAttributeReader::new(bytes))),
            0x802c => Ok(Attribute::OtherAddress(OtherAddressAttributeReader::new(bytes))),
            0x8028 => Ok(Attribute::Fingerprint(FingerprintAttributeReader::new(bytes))),
            _ => Err(NonParsableAttribute::Unknown(UnknownAttrReader::new(bytes)))
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