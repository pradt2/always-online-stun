use super::*;

pub use super::attrs::{SocketAddr};
pub use super::base::ReaderErr;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MessageType {
    BindingRequest = 0x0001,
    BindingIndication = 0x0011,
    BindingResponse = 0x0101,
    BindingErrorResponse = 0x0111,
}

impl TryFrom<u16> for MessageType {
    type Error = ReaderErr;

    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(MessageType::BindingRequest),
            0x0011 => Ok(MessageType::BindingIndication),
            0x0101 => Ok(MessageType::BindingResponse),
            0x0111 => Ok(MessageType::BindingErrorResponse),
            _ => Err(ReaderErr::UnexpectedValue)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum StunError {
    TryAlternate = 300,
    BadRequest = 400,
    Unauthorized = 401,
    UnknownAttribute = 420,
    StaleNonce = 438,
    ServerError = 500,
}

impl TryFrom<u16> for StunError {
    type Error = ReaderErr;

    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        match value {
            400 => Ok(StunError::BadRequest),
            401 => Ok(StunError::Unauthorized),
            420 => Ok(StunError::UnknownAttribute),
            438 => Ok(StunError::StaleNonce),
            500 => Ok(StunError::ServerError),
            _ => Err(ReaderErr::UnexpectedValue),
        }
    }
}

impl StunError {
    pub fn get_name(&self) -> &'static str {
        match self {
            StunError::TryAlternate => "Try Alternate",
            StunError::BadRequest => "Bad Request",
            StunError::Unauthorized => "Unauthorized",
            StunError::UnknownAttribute => "Unknown Attribute",
            StunError::StaleNonce => "Stale Credentials",
            StunError::ServerError => "Server Error",
        }
    }

    pub fn get_reason(&self) -> &'static str {
        match self {
            StunError::TryAlternate => "The client should contact an alternate server for this request.",
            StunError::BadRequest => "The request was malformed. The client should not retry the request without modification from the previous attempt.",
            StunError::Unauthorized => "The Binding Request did not contain a MESSAGE-INTEGRITY attribute.",
            StunError::UnknownAttribute => "The server did not understand a mandatory attribute in the request.",
            StunError::StaleNonce => "The NONCE used by the client was no longer valid.",
            StunError::ServerError => "The server has suffered a temporary error. The client should try again.",
        }
    }
}

pub struct Reader<'a> {
    header: RawMsgHeaderReader<'a>,
    attr_bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        let header_bytes = bytes.get(0..20).unwrap_or(bytes);
        let attr_bytes = bytes.get(20..).unwrap_or(&bytes[0..0]);
        Self {
            header: RawMsgHeaderReader::new(header_bytes),
            attr_bytes,
        }
    }

    pub fn get_message_type(&self) -> Result<MessageType> {
        self.header.get_message_type()
            .ok_or(ReaderErr::NotEnoughBytes)?
            .try_into()
    }

    pub fn get_message_length(&self) -> Option<u16> {
        self.header.get_message_length()
    }

    pub fn get_transaction_id(&self) -> Option<u128> {
        Some(self.header.get_transaction_id()? & (u128::MAX >> 32)) // this clears out the magic cookie
    }

    pub fn get_magic_cookie(&self) -> Option<u32> {
        self.header.get_magic_cookie()
    }

    pub fn get_attributes(&self) -> AttributeIterator {
        let magic_cookie = self.get_magic_cookie().unwrap_or(0);
        let transaction_id = self.get_transaction_id().unwrap_or(0);
        AttributeIterator::new(self.attr_bytes, magic_cookie, transaction_id)
    }
}

pub struct Writer<'a> {
    header: RawMsgHeaderWriter<'a>,
    attr_bytes: &'a mut [u8],
    attr_bytes_used: u16,
    transaction_id_full: u128,
}

impl<'a> Writer<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        if bytes.len() < 20 {
            // for such a small buffer,
            // attr is guarateed to get a slice of zero length
            // but who are we to judge
            let (header_bytes, attr_bytes) = bytes.split_at_mut(bytes.len());
            Self {
                header: RawMsgHeaderWriter::new(header_bytes),
                attr_bytes,
                attr_bytes_used: 0,
                transaction_id_full: 0,
            }
        } else {
            let (header_bytes, attr_bytes) = bytes.split_at_mut(20);
            Self {
                header: RawMsgHeaderWriter::new(header_bytes),
                attr_bytes,
                attr_bytes_used: 0,
                transaction_id_full: 0,
            }
        }
    }

    pub fn set_message_type(&mut self, typ: MessageType) -> Option<()> {
        self.header.set_message_type(typ as u16)
    }

    pub fn set_message_length(&mut self, len: u16) -> Option<()> {
        self.header.set_message_length(len)
    }

    pub fn update_message_length(&mut self) -> Option<()> {
        self.set_message_length(self.attr_bytes_used)
    }

    pub fn finish(mut self) -> Option<u16> {
        self.update_message_length()?;
        Some(20 + self.attr_bytes_used)
    }

    pub fn set_magic_cookie(&mut self, magic_cookie: u32) -> Option<()> {
        self.header.set_magic_cookie(magic_cookie)?;
        self.transaction_id_full = ((magic_cookie as u128) << 96) | (self.transaction_id_full & (u128::MAX >> 32));
        Some(())
    }

    pub fn set_transaction_id(&mut self, tid: u128) -> Option<()> {
        let tid = (0x2112A442 << 96) | (tid & (u128::MAX >> 32)); // force set the magic cookie
        self.header.set_transaction_id(tid)?;
        self.transaction_id_full = tid;
        Some(())
    }

    pub fn add_attr(&mut self, attr: WriterAttribute) -> Option<()> {
        match attr {
            WriterAttribute::MappedAddress(addr) => self.add_attr_inner(0x0001, |value_dest| {
                let mut w = SocketAddrWriter::new(value_dest);
                match addr {
                    SocketAddr::V4(ip, port) => w.write_ipv4_addr(ip, port),
                    SocketAddr::V6(ip, port) => w.write_ipv6_addr(ip, port),
                }
            }),
            WriterAttribute::Username(username) => self.add_attr_inner(0x0006, |value_dest| {
                StringWriter::new(value_dest).write(username)
            }),
            WriterAttribute::MessageIntegrity(value) => self.add_attr_inner(0x0008, |value_dest| {
                MessageIntegrityWriter::new(value_dest).write(value)
            }),
            WriterAttribute::ErrorCode(error) => self.add_attr_inner(0x0009, |value_dest| {
                let mut writer = ErrorCodeWriter::new(value_dest);
                Some(writer.write_code(error as u16)? + writer.write_reason(error.get_reason())?)
            }),
            WriterAttribute::UnknownAttributes(attrs) => self.add_attr_inner(0x000A, |value_dest| {
                UnknownAttrsWriter::new(value_dest).write(attrs, attrs.get(attrs.len() - 1).map(|val| *val))
            }),
            WriterAttribute::Realm(realm) => self.add_attr_inner(0x0014, |value_dest| {
               StringWriter::new(value_dest).write(realm)
            }),
            WriterAttribute::Nonce(nonce) => self.add_attr_inner(0x0015, |value_dest| {
                StringWriter::new(value_dest).write(nonce)
            }),
            WriterAttribute::XorMappedAddress(addr) => {
                let magic_cookie = (self.transaction_id_full >> 96) as u32;
                let transaction_id = self.transaction_id_full;
                self.add_attr_inner(0x0020, |value_dest| {
                    let mut w = XorSocketAddrWriter::new(value_dest);
                    match addr {
                        SocketAddr::V4(ip, port) => w.write_ipv4_addr(ip, port, magic_cookie),
                        SocketAddr::V6(ip, port) => w.write_ipv6_addr(ip, port, magic_cookie, transaction_id),
                    }
                })
            },
            WriterAttribute::Software(software) => self.add_attr_inner(0x8022, |value_dest| {
                StringWriter::new(value_dest).write(software)
            }),
            WriterAttribute::AlternateServer(addr) => self.add_attr_inner(0x8023, |value_dest| {
                let mut w = SocketAddrWriter::new(value_dest);
                match addr {
                    SocketAddr::V4(ip, port) => w.write_ipv4_addr(ip, port),
                    SocketAddr::V6(ip, port) => w.write_ipv6_addr(ip, port),
                }
            }),
            WriterAttribute::Fingerprint(fingerprint) => self.add_attr_inner(0x8028, |value_dest| {
                FingerprintWriter::new(value_dest).write(fingerprint)
            }),
            WriterAttribute::OptionalAttribute {typ, value} => self.add_attr_inner(typ, |value_dest| {
                value_dest.get_mut(0..value.len())?
                    .copy_from_slice(value);

                Some(value.len() as u16)
            })
        }?;
        Some(())
    }

    fn add_attr_inner<T: Fn(& mut [u8]) -> Option<u16>>(&mut self, attr_type: u16, value_gen: T) -> Option<u16> {
        let idx = self.attr_bytes_used as usize;

        let value_buf = self.attr_bytes.get_mut(idx + 4..)?;

        let value_len = value_gen(value_buf)?;

        let header_buf = self.attr_bytes.get_mut(idx..idx + 4)?;

        let type_bytes = attr_type.to_be_bytes();
        header_buf[0..2].copy_from_slice(&type_bytes);

        let value_len_bytes = value_len.to_be_bytes();
        header_buf[2..4].copy_from_slice(&value_len_bytes);

        let value_len_with_padding = get_nearest_greater_multiple_of_4(value_len);

        let padding_dest = self.attr_bytes
            .get_mut(idx + 4 + value_len as usize..idx + 4 + value_len_with_padding as usize)?;

        padding_dest.fill(0); // setting padding bytes to 0

        self.attr_bytes_used += 4 + value_len_with_padding;
        Some(4 + value_len_with_padding)
    }
}

pub struct StunErrorReader<'a> {
    base_reader: ErrorCodeReader<'a>,
}

impl<'a> StunErrorReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            base_reader: ErrorCodeReader::new(bytes)
        }
    }

    pub fn get_error(&self) -> Result<StunError> {
        let error = self.base_reader.get_code()
            .ok_or(ReaderErr::NotEnoughBytes)?
            .try_into()?;
        Ok(error)
    }

    pub fn get_reason(&self) -> Result<&str> {
        self.base_reader.get_reason()
    }

    pub unsafe fn get_reason_unchecked(&self) -> Option<&str> {
        self.base_reader.get_reason_unchecked()
    }
}

pub enum ReaderAttribute<'a> {
    MappedAddress(SocketAddrReader<'a>),
    Username(StringReader<'a>),
    MessageIntegrity(MessageIntegrityReader<'a>),
    ErrorCode(StunErrorReader<'a>),
    UnknownAttributes(UnknownAttrsReader<'a>),
    Realm(StringReader<'a>),
    Nonce(StringReader<'a>),
    XorMappedAddress(XorSocketAddrReader<'a>),
    Software(StringReader<'a>),
    AlternateServer(SocketAddrReader<'a>),
    Fingerprint(FingerprintReader<'a>),
    OptionalAttribute { typ: u16, value: &'a [u8] },
}

pub enum WriterAttribute<'a, 'b> {
    MappedAddress(SocketAddr),
    Username(&'b str),
    MessageIntegrity(&'b [u8; 20]),
    ErrorCode(StunError),
    UnknownAttributes(&'a [u16]),
    Realm(&'a str),
    Nonce(&'a str),
    XorMappedAddress(SocketAddr),
    Software(&'a str),
    AlternateServer(SocketAddr),
    Fingerprint(u32),
    OptionalAttribute { typ: u16, value: &'a [u8] },
}

pub struct AttributeIterator<'a> {
    base_iter: BaseAttributeIterator<'a>,
    magic_cookie: u32,
    transaction_id: u128,
}

impl<'a> AttributeIterator<'a> {
    fn new(bytes: &'a [u8], magic_cookie: u32, transaction_id: u128) -> Self {
        Self {
            base_iter: BaseAttributeIterator::new(bytes),
            magic_cookie,
            transaction_id,
        }
    }
}

impl<'a> Iterator for AttributeIterator<'a> {
    type Item = Result<ReaderAttribute<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.base_iter.next() {
            None => None,
            Some(Err(err)) => Some(Err(err)),
            Some(Ok((typ, value))) => match typ {
                0x0001 => Some(Ok(ReaderAttribute::MappedAddress(SocketAddrReader::new(value)))),
                0x0006 => Some(Ok(ReaderAttribute::Username(StringReader::new(value)))),
                0x0008 => Some(Ok(ReaderAttribute::MessageIntegrity(MessageIntegrityReader::new(value)))),
                0x0009 => Some(Ok(ReaderAttribute::ErrorCode(StunErrorReader::new(value)))),
                0x000A => Some(Ok(ReaderAttribute::UnknownAttributes(UnknownAttrsReader::new(value)))),
                0x0014 => Some(Ok(ReaderAttribute::Realm(StringReader::new(value)))),
                0x0015 => Some(Ok(ReaderAttribute::Nonce(StringReader::new(value)))),
                0x0020 => Some(Ok(ReaderAttribute::XorMappedAddress(XorSocketAddrReader::new(value, self.magic_cookie, self.transaction_id)))),
                0x8022 => Some(Ok(ReaderAttribute::Software(StringReader::new(value)))),
                0x8023 => Some(Ok(ReaderAttribute::AlternateServer(SocketAddrReader::new(value)))),
                0x8028 => Some(Ok(ReaderAttribute::Fingerprint(FingerprintReader::new(value)))),
                typ if typ > 0x7FFF => Some(Ok(ReaderAttribute::OptionalAttribute { typ, value })),
                _ => Some(Err(ReaderErr::UnexpectedValue))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: [u8; 20] = [
        0x00, 0x01,             // type: Binding Request
        0x00, 0x04,             // length: 4 (header does not count)
        0x21, 0x12, 0xA4, 0x42, // magic cookie
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, // transaction id (12 bytes total)
    ];

    #[test]
    fn read_message_type() {
        assert_eq!(MessageType::BindingRequest, Reader::new(&[0x00, 0x01]).get_message_type().unwrap());
        assert_eq!(MessageType::BindingIndication, Reader::new(&[0x00, 0x11]).get_message_type().unwrap());
        assert_eq!(MessageType::BindingResponse, Reader::new(&[0x01, 0x01]).get_message_type().unwrap());
        assert_eq!(MessageType::BindingErrorResponse, Reader::new(&[0x01, 0x11]).get_message_type().unwrap());
    }

    #[test]
    fn read_message_header() {
        let r = Reader::new(&HEADER);
        assert_eq!(MessageType::BindingRequest, r.get_message_type().unwrap());
        assert_eq!(4u16, r.get_message_length().unwrap());
        assert_eq!(1u128, r.get_transaction_id().unwrap());
    }

    #[test]
    fn write_message_header() {
        let mut buffer = [0u8; 20];

        let mut w = Writer::new(&mut buffer);
        w.set_message_type(MessageType::BindingRequest).unwrap();
        w.set_message_length(4).unwrap();
        w.set_transaction_id(1).unwrap();

        assert_eq!(HEADER, buffer);
    }

    #[test]
    fn read_resolve_attrs() {
        if let Some(Ok(ReaderAttribute::MappedAddress(_))) = AttributeIterator::new(&[0x00, 0x01, 0x00, 0x00], 0, 0).next() {} else {
            assert!(false, "Expected attribute MAPPED-ADDRESS");
        }

        if let Some(Ok(ReaderAttribute::Username(_))) = AttributeIterator::new(&[0x00, 0x06, 0x00, 0x00], 0, 0).next() {} else {
            assert!(false, "Expected attribute USERNAME");
        }

        if let Some(Ok(ReaderAttribute::MessageIntegrity(_))) = AttributeIterator::new(&[0x00, 0x08, 0x00, 0x00], 0, 0).next() {} else {
            assert!(false, "Expected attribute MESSAGE-INTEGRITY");
        }

        if let Some(Ok(ReaderAttribute::ErrorCode(_))) = AttributeIterator::new(&[0x00, 0x09, 0x00, 0x00], 0, 0).next() {} else {
            assert!(false, "Expected attribute ERROR-CODE");
        }

        if let Some(Ok(ReaderAttribute::UnknownAttributes(_))) = AttributeIterator::new(&[0x00, 0x0A, 0x00, 0x00], 0, 0).next() {} else {
            assert!(false, "Expected attribute UNKNOWN-ATTRIBUTES");
        }

        if let Some(Ok(ReaderAttribute::Realm(_))) = AttributeIterator::new(&[0x00, 0x14, 0x00, 0x00], 0, 0).next() {} else {
            assert!(false, "Expected attribute REALM");
        }

        if let Some(Ok(ReaderAttribute::Nonce(_))) = AttributeIterator::new(&[0x00, 0x15, 0x00, 0x00], 0, 0).next() {} else {
            assert!(false, "Expected attribute NONCE");
        }

        if let Some(Ok(ReaderAttribute::XorMappedAddress(_))) = AttributeIterator::new(&[0x00, 0x20, 0x00, 0x00], 0, 0).next() {} else {
            assert!(false, "Expected attribute XOR-MAPPED-ADDRESS");
        }

        for optional_attr in 0x0000..=0x7FFF as u16 {
            if let Some(Ok(ReaderAttribute::OptionalAttribute { .. })) = AttributeIterator::new(&((optional_attr as u32) << 16).to_be_bytes(), 0, 0).next() {
                assert!(false, "Unexpected generic optional attribute for code {:#06X}", optional_attr);
            }
        }

        for optional_attr in 0x8000..=0xFFFF as u16 {
            match optional_attr {
                0x8022 | 0x8023 | 0x8028 => continue,
                _ => {}
            }
            if let Some(Ok(ReaderAttribute::OptionalAttribute { .. })) = AttributeIterator::new(&((optional_attr as u32) << 16).to_be_bytes(), 0, 0).next() {} else {
                assert!(false, "Expected generic optional attribute for code {:#06X}", optional_attr);
            }
        }
    }

    const MAPPED_ADDRESS_V4: [u8; 12] = [
        0x00, 0x01,             // type: MappedAddress
        0x00, 0x08,             // value length
        0x00, 0x01,             // address family
        0x0A, 0x0B,             // port
        0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
    ];

    const MOCK_IPV4: u32 = 0xC0D0E0F;
    const MOCK_IPV4_PORT: u16 = 0x0A0B;

    #[test]
    fn read_mapped_address_attr_ipv4() {
        let mut r = AttributeIterator::new(&MAPPED_ADDRESS_V4, 0, 0);

        if let Some(Ok(ReaderAttribute::MappedAddress(r))) = r.next() {
            let addr = if let Ok(addr) = r.get_address() { addr } else {
                assert!(false, "Test address should be a valid address");
                return;
            };

            if let SocketAddr::V4(ip, port) = addr {
                assert_eq!(MOCK_IPV4_PORT, port);
                assert_eq!(MOCK_IPV4, ip);
            } else {
                assert!(false, "Test address should be a V4 address");
            }
        } else {
            assert!(false, "Iterator should return a valid MappingAddress attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_mapped_address_attr_ipv4() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::MappedAddress(SocketAddr::V4(MOCK_IPV4, MOCK_IPV4_PORT))).unwrap();
        assert_eq!(MAPPED_ADDRESS_V4, buffer[20..])
    }

    const MAPPED_ADDRESS_V6: [u8; 24] = [
        0x00, 0x01,             // type: MappedAddress
        0x00, 0x14,             // value length
        0x00, 0x02,             // address family: IPv6
        0x0B, 0x0C,             // port
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, // ipv6 address
    ];

    const MOCK_IPV6: u128 = 0x000102030405060708090A0B0C0D0E0F;
    const MOCK_IPV6_PORT: u16 = 0x0B0C;

    #[test]
    fn read_mapped_address_attr_ipv6() {
        let mut r = AttributeIterator::new(&MAPPED_ADDRESS_V6, 0, 0);

        if let Some(Ok(ReaderAttribute::MappedAddress(r))) = r.next() {
            let addr = if let Ok(addr) = r.get_address() { addr } else {
                assert!(false, "Test address should be a valid address");
                return;
            };

            if let SocketAddr::V6(ip, port) = addr {
                assert_eq!(MOCK_IPV6_PORT, port);
                assert_eq!(MOCK_IPV6, ip);
            } else {
                assert!(false, "Test address should be a V6 address");
            }
        } else {
            assert!(false, "Iterator should return a valid MappingAddress attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_mapped_address_attr_ipv6() {
        let mut buffer = [0; 44];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::MappedAddress(SocketAddr::V6(MOCK_IPV6, MOCK_IPV6_PORT))).unwrap();
        assert_eq!(MAPPED_ADDRESS_V6, buffer[20..])
    }

    const MESSAGE_INTEGRITY: [u8; 24] = [
        0x00, 0x08,             // type: MessageIntegrity
        0x00, 0x14,             // value length
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, // hash
    ];

    #[test]
    fn read_message_integrity_attr() {
        let mut r = AttributeIterator::new(&MESSAGE_INTEGRITY, 0, 0);

        if let Some(Ok(ReaderAttribute::MessageIntegrity(r))) = r.next() {
            assert_eq!([0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                           0x10, 0x11, 0x12, 0x13] as [u8; 20], *r.get_value().unwrap());
        } else {
            assert!(false, "Iterator should return a valid MessageIntegrity attribute");
        }

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_message_integrity_attr() {
        let mut buffer = [0; 44];
        let mut w = Writer::new(&mut buffer);
        w.add_attr(WriterAttribute::MessageIntegrity(&[0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13])).unwrap();
        assert_eq!(MESSAGE_INTEGRITY, buffer[20..]);
    }

    const USERNAME: [u8; 12] = [
        0x00, 0x06, // type: Username
        0x00, 0x06, // value length
        0x75, 0x73,
        0x65, 0x72,
        0x31, 0x32, // 'user12'
        0x00, 0x00, // padding
    ];

    const MOCK_USERNAME: &'static str = "user12";

    #[test]
    fn read_username_attr() {
        let mut r = AttributeIterator::new(&USERNAME, 0, 0);

        if let Some(Ok(ReaderAttribute::Username(r))) = r.next() {
            assert_eq!(MOCK_USERNAME, r.get_value().unwrap());
        } else {
            assert!(false, "Iterator should return a valid Username attribute");
        }

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_username_attr() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);
        w.add_attr(WriterAttribute::Username(MOCK_USERNAME)).unwrap();
        assert_eq!(USERNAME, buffer[20..]);
    }

    const ERROR_CODE: [u8; 13] = [
        0x00, 0x09,                   // type: ErrorCode
        0x00, 0x09,                   // value length
        0x00, 0x00,                   // reserved
        0x80, 0x00,                   // class 4, num 00 = code 400
        0x68, 0x65, 0x6C, 0x6C, 0x6F, // reason = 'hello'
    ];

    #[test]
    fn read_error_code() {
        let mut r = AttributeIterator::new(&ERROR_CODE, 0, 0);

        if let Some(Ok(ReaderAttribute::ErrorCode(r))) = r.next() {
            let error = if let Ok(addr) = r.get_error() { addr } else {
                assert!(false, "Test address should be a valid address");
                return;
            };

            if let StunError::BadRequest = error {

            } else {
                assert!(false, "Error code is not BadRequest");
            }
        } else {
            assert!(false, "Iterator should return a valid ErrorCode attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_error_code() {
        let mut buffer = [0u8; 256];

        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::ErrorCode(StunError::BadRequest)).expect("Buffer too small");

        assert_eq!(ERROR_CODE[0..2], buffer[20..][0..2]); // TODO fixme
    }

    const UNKNOWN_ATTIBUTES: [u8; 8] = [
        0x00, 0x0A, // type: UnknownAttributes
        0x00, 0x02, // value length
        0x00, 0x01, // unknown attr
        0x00, 0x01, // the same unknown attr as padding
    ];

    #[test]
    fn read_unknown_attributes() {
        let mut r = AttributeIterator::new(&UNKNOWN_ATTIBUTES, 0, 0);

        if let Some(Ok(ReaderAttribute::UnknownAttributes(r))) = r.next() {
            let mut r = r.unknown_type_codes();

            if let Some(Ok(unknown_attr)) = r.next() {
                assert_eq!(1, unknown_attr);
            } else {
                assert!(false, "Unknown attribute value is unreadable");
            }

            assert!(r.next().is_none(), "There should be only one unknown attribute value");

        } else {
            assert!(false, "Iterator should return a valid UnknownAttributes attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_unknown_attributes() {
        let mut buffer = [0; 28];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::UnknownAttributes(&[1])).unwrap();
        assert_eq!(UNKNOWN_ATTIBUTES[4..], buffer[20..][4..]);
    }

    const REALM: [u8; 12] = [
        0x00, 0x14, // type: Realm
        0x00, 0x06, // value length
        0x75, 0x73,
        0x65, 0x72,
        0x31, 0x32, // 'user12'
        0x00, 0x00, // padding
    ];

    const MOCK_REALM: &'static str = "user12";

    #[test]
    fn read_realm_attr() {
        let mut r = AttributeIterator::new(&REALM, 0, 0);

        if let Some(Ok(ReaderAttribute::Realm(r))) = r.next() {
            assert_eq!(MOCK_REALM, r.get_value().unwrap());
        } else {
            assert!(false, "Iterator should return a valid Realm attribute");
        }

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_realm_attr() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);
        w.add_attr(WriterAttribute::Realm(MOCK_REALM)).unwrap();
        assert_eq!(REALM, buffer[20..]);
    }

    const NONCE: [u8; 12] = [
        0x00, 0x15, // type: Nonce
        0x00, 0x06, // value length
        0x75, 0x73,
        0x65, 0x72,
        0x31, 0x32, // 'user12'
        0x00, 0x00, // padding
    ];

    const MOCK_NONCE: &'static str = "user12";

    #[test]
    fn read_nonce_attr() {
        let mut r = AttributeIterator::new(&NONCE, 0, 0);

        if let Some(Ok(ReaderAttribute::Nonce(r))) = r.next() {
            assert_eq!(MOCK_NONCE, r.get_value().unwrap());
        } else {
            assert!(false, "Iterator should return a valid Nonce attribute");
        }

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_nonce_attr() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);
        w.add_attr(WriterAttribute::Nonce(MOCK_NONCE)).unwrap();
        assert_eq!(NONCE, buffer[20..]);
    }

    const XOR_MAPPED_ADDRESS_V4: [u8; 12] = [
        0x00, 0x20,             // type: XorMappedAddress
        0x00, 0x08,             // value length
        0x00, 0x01,             // address family
        0x0A, 0x0B,             // port
        0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
    ];

    const XOR_MOCK_IPV4: u32 = 0xC0D0E0F ^ 0x0;

    #[test]
    fn read_xor_mapped_address_attr_ipv4() {
        let mut r = AttributeIterator::new(&XOR_MAPPED_ADDRESS_V4, 0, 0);

        if let Some(Ok(ReaderAttribute::XorMappedAddress(r))) = r.next() {
            let addr = if let Ok(addr) = r.get_address() { addr } else {
                assert!(false, "Test address should be a valid address");
                return;
            };

            if let SocketAddr::V4(ip, port) = addr {
                assert_eq!(MOCK_IPV4_PORT, port);
                assert_eq!(XOR_MOCK_IPV4, ip);
            } else {
                assert!(false, "Test address should be a V4 address");
            }
        } else {
            assert!(false, "Iterator should return a valid XorMappingAddress attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_xor_mapped_address_attr_ipv4() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::XorMappedAddress(SocketAddr::V4(XOR_MOCK_IPV4, MOCK_IPV4_PORT))).unwrap();
        assert_eq!(XOR_MAPPED_ADDRESS_V4, buffer[20..])
    }

    const XOR_MAPPED_ADDRESS_V6: [u8; 24] = [
        0x00, 0x20,             // type: XorMappedAddress
        0x00, 0x14,             // value length
        0x00, 0x02,             // address family: IPv6
        0x0B, 0x0C,             // port
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, // ipv6 address
    ];

    const XOR_MOCK_IPV6: u128 = 0x000102030405060708090A0B0C0D0E0F ^ 0x0;

    #[test]
    fn read_xor_mapped_address_attr_ipv6() {
        let mut r = AttributeIterator::new(&XOR_MAPPED_ADDRESS_V6, 0, 0);

        if let Some(Ok(ReaderAttribute::XorMappedAddress(r))) = r.next() {
            let addr = if let Ok(addr) = r.get_address() { addr } else {
                assert!(false, "Test address should be a valid address");
                return;
            };

            if let SocketAddr::V6(ip, port) = addr {
                assert_eq!(MOCK_IPV6_PORT, port);
                assert_eq!(XOR_MOCK_IPV6, ip);
            } else {
                assert!(false, "Test address should be a V6 address");
            }
        } else {
            assert!(false, "Iterator should return a valid XorMappingAddress attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_xor_mapped_address_attr_ipv6() {
        let mut buffer = [0; 44];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::XorMappedAddress(SocketAddr::V6(XOR_MOCK_IPV6, MOCK_IPV6_PORT))).unwrap();
        assert_eq!(XOR_MAPPED_ADDRESS_V6, buffer[20..])
    }

    const SOFTWARE: [u8; 12] = [
        0x80, 0x22, // type: Software
        0x00, 0x06, // value length
        0x75, 0x73,
        0x65, 0x72,
        0x31, 0x32, // 'user12'
        0x00, 0x00, // padding
    ];

    const MOCK_SOFTWARE: &'static str = "user12";

    #[test]
    fn read_software_attr() {
        let mut r = AttributeIterator::new(&SOFTWARE, 0, 0);

        if let Some(Ok(ReaderAttribute::Software(r))) = r.next() {
            assert_eq!(MOCK_SOFTWARE, r.get_value().unwrap());
        } else {
            assert!(false, "Iterator should return a valid Username attribute");
        }

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_software_attr() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);
        w.add_attr(WriterAttribute::Software(MOCK_SOFTWARE)).unwrap();
        assert_eq!(SOFTWARE, buffer[20..]);
    }

    const ALTERNATE_SERVER_V4: [u8; 12] = [
        0x80, 0x23,             // type: AlternateServer
        0x00, 0x08,             // value length
        0x00, 0x01,             // address family
        0x0A, 0x0B,             // port
        0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
    ];

    #[test]
    fn read_alternate_server_attr_ipv4() {
        let mut r = AttributeIterator::new(&ALTERNATE_SERVER_V4, 0, 0);

        if let Some(Ok(ReaderAttribute::AlternateServer(r))) = r.next() {
            let addr = if let Ok(addr) = r.get_address() { addr } else {
                assert!(false, "Test address should be a valid address");
                return;
            };

            if let SocketAddr::V4(ip, port) = addr {
                assert_eq!(MOCK_IPV4_PORT, port);
                assert_eq!(MOCK_IPV4, ip);
            } else {
                assert!(false, "Test address should be a V4 address");
            }
        } else {
            assert!(false, "Iterator should return a valid AlternateServer attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_alternate_server_attr_ipv4() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::AlternateServer(SocketAddr::V4(MOCK_IPV4, MOCK_IPV4_PORT))).unwrap();
        assert_eq!(ALTERNATE_SERVER_V4, buffer[20..])
    }

    const ALTERNATE_SERVER_V6: [u8; 24] = [
        0x80, 0x23,             // type: AlternateServer
        0x00, 0x14,             // value length
        0x00, 0x02,             // address family: IPv6
        0x0B, 0x0C,             // port
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, // ipv6 address
    ];

    #[test]
    fn read_alternate_server_attr_ipv6() {
        let mut r = AttributeIterator::new(&ALTERNATE_SERVER_V6, 0, 0);

        if let Some(Ok(ReaderAttribute::AlternateServer(r))) = r.next() {
            let addr = if let Ok(addr) = r.get_address() { addr } else {
                assert!(false, "Test address should be a valid address");
                return;
            };

            if let SocketAddr::V6(ip, port) = addr {
                assert_eq!(MOCK_IPV6_PORT, port);
                assert_eq!(MOCK_IPV6, ip);
            } else {
                assert!(false, "Test address should be a V6 address");
            }
        } else {
            assert!(false, "Iterator should return a valid AlternateServer attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_alternate_server_attr_ipv6() {
        let mut buffer = [0; 44];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::AlternateServer(SocketAddr::V6(MOCK_IPV6, MOCK_IPV6_PORT))).unwrap();
        assert_eq!(ALTERNATE_SERVER_V6, buffer[20..])
    }

    const FINGERPRINT: [u8; 8] = [
        0x80, 0x28,             // type: Fingerprint
        0x00, 0x04,             // value length
        0x01, 0x02, 0x03, 0x04  // fingerprint value
    ];

    const FINGERPRINT_VALUE: u32 = 0x01020304 ^ 0x5354554E;

    #[test]
    fn read_fingerprint_attr() {
        let mut r = AttributeIterator::new(&FINGERPRINT, 0, 0);

        if let Some(Ok(ReaderAttribute::Fingerprint(r))) = r.next() {
            assert_eq!(FINGERPRINT_VALUE, r.get_value().unwrap());
        } else {
            assert!(false, "Iterator should return a valid Fingerprint attribute");
        }

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_fingerprint_attr() {
        let mut buffer = [0; 28];
        let mut w = Writer::new(&mut buffer);
        w.add_attr(WriterAttribute::Fingerprint(FINGERPRINT_VALUE)).unwrap();
        assert_eq!(FINGERPRINT, buffer[20..]);
    }
}
