use super::*;

pub use super::attrs::{SocketAddr};
pub use super::base::ReaderErr;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MessageType {
    BindingRequest = 0x0001,
    BindingResponse = 0x0101,
    BindingErrorResponse = 0x0111,
    SharedSecretRequest = 0x0002,
    SharedSecretResponse = 0x0102,
    SharedSecretErrorResponse = 0x0112,
}

impl TryFrom<u16> for MessageType {
    type Error = ReaderErr;

    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(MessageType::BindingRequest),
            0x0101 => Ok(MessageType::BindingResponse),
            0x0111 => Ok(MessageType::BindingErrorResponse),
            0x0002 => Ok(MessageType::SharedSecretRequest),
            0x0102 => Ok(MessageType::SharedSecretResponse),
            0x0112 => Ok(MessageType::SharedSecretErrorResponse),
            _ => Err(ReaderErr::UnexpectedValue)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum StunError {
    BadRequest = 400,
    Unauthorized = 401,
    UnknownAttribute = 420,
    StaleCredentials = 430,
    IntegrityCheckFailure = 431,
    MissingUsername = 432,
    UseTls = 433,
    ServerError = 500,
    GlobalFailure = 600,
}

impl TryFrom<u16> for StunError {
    type Error = ReaderErr;

    fn try_from(value: u16) -> core::result::Result<Self, Self::Error> {
        match value {
            400 => Ok(StunError::BadRequest),
            401 => Ok(StunError::Unauthorized),
            420 => Ok(StunError::UnknownAttribute),
            430 => Ok(StunError::StaleCredentials),
            431 => Ok(StunError::IntegrityCheckFailure),
            432 => Ok(StunError::MissingUsername),
            433 => Ok(StunError::UseTls),
            500 => Ok(StunError::ServerError),
            600 => Ok(StunError::GlobalFailure),
            _ => Err(ReaderErr::UnexpectedValue),
        }
    }
}

impl StunError {
    pub fn get_name(&self) -> &'static str {
        match self {
            StunError::BadRequest => "Bad Request",
            StunError::Unauthorized => "Unauthorized",
            StunError::UnknownAttribute => "Unknown Attribute",
            StunError::StaleCredentials => "Stale Credentials",
            StunError::IntegrityCheckFailure => "Integrity Check Failure",
            StunError::MissingUsername => "Missing Username",
            StunError::UseTls => "Use TLS",
            StunError::ServerError => "Server Error",
            StunError::GlobalFailure => "Global Failure",
        }
    }

    pub fn get_reason(&self) -> &'static str {
        match self {
            StunError::BadRequest => "The request was malformed. The client should not retry the request without modification from the previous attempt.",
            StunError::Unauthorized => "The Binding Request did not contain a MESSAGE-INTEGRITY attribute.",
            StunError::UnknownAttribute => "The server did not understand a mandatory attribute in the request.",
            StunError::StaleCredentials => "The Binding Request did contain a MESSAGE-INTEGRITY attribute, but it used a shared secret that has expired. The client should obtain a new shared secret and try again.",
            StunError::IntegrityCheckFailure => "The Binding Request contained a MESSAGE-INTEGRITY attribute, but the HMAC failed verification. This could be a sign of a potential attack, or client implementation error.",
            StunError::MissingUsername => "The Binding Request contained a MESSAGE-INTEGRITY attribute, but not a USERNAME attribute. Both must be present for integrity checks.",
            StunError::UseTls => "The Shared Secret request has to be sent over TLS, but was not received over TLS.",
            StunError::ServerError => "The server has suffered a temporary error. The client should try again.",
            StunError::GlobalFailure => " The server is refusing to fulfill the request. The client should not retry.",
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
        self.header.get_message_type()?.try_into()
    }

    pub fn get_message_length(&self) -> Result<u16> {
        self.header.get_message_length()
    }

    pub fn get_transaction_id(&self) -> Result<u128> {
        self.header.get_transaction_id()
    }

    pub fn attrs(&self) -> AttributeIterator {
        AttributeIterator::new(self.attr_bytes)
    }
}

pub struct Writer<'a> {
    header: RawMsgHeaderWriter<'a>,
    attr_bytes: &'a mut [u8],
    attr_bytes_used: u16,
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
            }
        } else {
            let (header_bytes, attr_bytes) = bytes.split_at_mut(20);
            Self {
                header: RawMsgHeaderWriter::new(header_bytes),
                attr_bytes,
                attr_bytes_used: 0,
            }
        }
    }

    pub fn set_message_type(&mut self, typ: MessageType) -> Result<()> {
        self.header.set_message_type(typ as u16)
    }

    pub fn set_message_length(&mut self, len: u16) -> Result<()> {
        self.header.set_message_length(len)
    }

    pub fn update_message_length(&mut self) -> Result<()> {
        self.set_message_length(self.attr_bytes_used)
    }

    pub fn set_transaction_id(&mut self, tid: u128) -> Result<()> {
        self.header.set_transaction_id(tid)
    }

    pub fn add_attr(&mut self, attr: WriterAttribute) -> Result<u16> {
        match attr {
            WriterAttribute::MappedAddress(addr) => self.add_attr_inner(0x0001, |value_dest| {
                let mut w = SocketAddrWriter::new(value_dest);
                match addr {
                    SocketAddr::V4(ip, port) => w.write_ipv4_addr(ip, port),
                    SocketAddr::V6(ip, port) => w.write_ipv6_addr(ip, port),
                }
            }),
            WriterAttribute::ResponseAddress(addr) => self.add_attr_inner(0x0002, |value_dest| {
                let mut w = SocketAddrWriter::new(value_dest);
                match addr {
                    SocketAddr::V4(ip, port) => w.write_ipv4_addr(ip, port),
                    SocketAddr::V6(ip, port) => w.write_ipv6_addr(ip, port),
                }
            }),
            WriterAttribute::ChangeRequest { change_ip, change_port } => self.add_attr_inner(0x0003, |value_dest| {
                ChangeRequestWriter::new(value_dest).write(change_ip, change_port)
            }),
            WriterAttribute::SourceAddress(addr) => self.add_attr_inner(0x0004, |value_dest| {
                let mut w = SocketAddrWriter::new(value_dest);
                match addr {
                    SocketAddr::V4(ip, port) => w.write_ipv4_addr(ip, port),
                    SocketAddr::V6(ip, port) => w.write_ipv6_addr(ip, port),
                }
            }),
            WriterAttribute::ChangedAddress(addr) => self.add_attr_inner(0x0005, |value_dest| {
                let mut w = SocketAddrWriter::new(value_dest);
                match addr {
                    SocketAddr::V4(ip, port) => w.write_ipv4_addr(ip, port),
                    SocketAddr::V6(ip, port) => w.write_ipv6_addr(ip, port),
                }
            }),
            WriterAttribute::Username(username) => self.add_attr_inner(0x0006, |value_dest| {
               StringWriter::new(value_dest).write(username)
            }),
            WriterAttribute::Password(password) => self.add_attr_inner(0x0007, |value_dest| {
               StringWriter::new(value_dest).write(password)
            }),
            WriterAttribute::MessageIntegrity(value) => self.add_attr_inner(0x0008, |value_dest| {
                MessageIntegrityWriter::new(value_dest).write(value)
            }),
            WriterAttribute::ErrorCode(error) => self.add_attr_inner(0x0009, |value_dest| {
                let mut writer = ErrorCodeWriter::new(value_dest);
                Ok(writer.set_code(error as u16)? + writer.set_reason(error.get_reason())?)
            }),
            WriterAttribute::UnknownAttributes(attrs) => self.add_attr_inner(0x000A, |value_dest| {
                UnknownAttrsWriter::new(value_dest).write(attrs, attrs.get(attrs.len() - 1).map(|val| *val))
            }),
            WriterAttribute::ReflectedFrom(addr) => self.add_attr_inner(0x000B, |value_dest| {
                let mut w = SocketAddrWriter::new(value_dest);
                match addr {
                    SocketAddr::V4(ip, port) => w.write_ipv4_addr(ip, port),
                    SocketAddr::V6(ip, port) => w.write_ipv6_addr(ip, port),
                }
            }),
            WriterAttribute::OptionalAttribute {typ, value} => self.add_attr_inner(typ, |value_dest| {
                value_dest.get_mut(0..2).ok_or(ReaderErr::NotEnoughBytes)?.copy_from_slice(&typ.to_be_bytes());
                value_dest.get_mut(2..value.len()).ok_or(ReaderErr::NotEnoughBytes)?.copy_from_slice(value);
                Ok(2 + value.len() as u16)
            })
        }
    }

    fn add_attr_inner<T: Fn(& mut [u8]) -> Result<u16>>(&mut self, attr_type: u16, value_gen: T) -> Result<u16> {
        let idx = self.attr_bytes_used as usize;

        let type_dest = self.attr_bytes.get_mut(idx..idx + 2).ok_or(ReaderErr::NotEnoughBytes)?;
        let type_bytes = u16::to_be_bytes(attr_type);
        type_dest.copy_from_slice(&type_bytes);

        let value_dest = self.attr_bytes.get_mut(idx + 4..).ok_or(ReaderErr::NotEnoughBytes)?;

        let value_len = value_gen(value_dest)?;

        let value_len_dest = self.attr_bytes.get_mut(idx + 2..idx + 4).ok_or(ReaderErr::NotEnoughBytes)?;
        let value_len_bytes = u16::to_be_bytes(value_len);
        value_len_dest.copy_from_slice(&value_len_bytes);

        let value_len_with_padding = get_nearest_greater_multiple_of_4(value_len);

        let padding_dest = self.attr_bytes.get_mut(idx + 4 + value_len as usize..idx + 4 + value_len_with_padding as usize).ok_or(ReaderErr::NotEnoughBytes)?;
        padding_dest.fill(0); // setting padding bytes to 0

        self.attr_bytes_used += 4 + value_len_with_padding;
        Ok(4 + value_len_with_padding)
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
        let error = self.base_reader.get_code()?.try_into()?;
        Ok(error)
    }

    pub fn get_reason(&self) -> Result<&str> {
        self.base_reader.get_reason()
    }

    pub unsafe fn get_reason_unchecked(&self) -> Result<&str> {
        self.base_reader.get_reason_unchecked()
    }
}

pub enum ReaderAttribute<'a> {
    MappedAddress(SocketAddrReader<'a>),
    ResponseAddress(SocketAddrReader<'a>),
    ChangeRequest(ChangeRequestReader<'a>),
    SourceAddress(SocketAddrReader<'a>),
    ChangedAddress(SocketAddrReader<'a>),
    Username(StringReader<'a>),
    Password(StringReader<'a>),
    MessageIntegrity(MessageIntegrityReader<'a>),
    ErrorCode(StunErrorReader<'a>),
    UnknownAttributes(UnknownAttrsReader<'a>),
    ReflectedFrom(SocketAddrReader<'a>),
    OptionalAttribute { typ: u16, value: &'a [u8] },
}

pub enum WriterAttribute<'a, 'b> {
    MappedAddress(SocketAddr),
    ResponseAddress(SocketAddr),
    ChangeRequest { change_ip: bool, change_port: bool },
    SourceAddress(SocketAddr),
    ChangedAddress(SocketAddr),
    Username(&'b str),
    Password(&'b str),
    MessageIntegrity(&'b [u8; 20]),
    ErrorCode(StunError),
    UnknownAttributes(&'a [u16]),
    ReflectedFrom(SocketAddr),
    OptionalAttribute { typ: u16, value: &'a [u8] },
}

pub struct AttributeIterator<'a> {
    base_iter: BaseAttributeIterator<'a>,
}

impl<'a> AttributeIterator<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            base_iter: BaseAttributeIterator::new(bytes)
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
                0x0002 => Some(Ok(ReaderAttribute::ResponseAddress(SocketAddrReader::new(value)))),
                0x0003 => Some(Ok(ReaderAttribute::ChangeRequest(ChangeRequestReader::new(value)))),
                0x0004 => Some(Ok(ReaderAttribute::SourceAddress(SocketAddrReader::new(value)))),
                0x0005 => Some(Ok(ReaderAttribute::ChangedAddress(SocketAddrReader::new(value)))),
                0x0006 => Some(Ok(ReaderAttribute::Username(StringReader::new(value)))),
                0x0007 => Some(Ok(ReaderAttribute::Password(StringReader::new(value)))),
                0x0008 => Some(Ok(ReaderAttribute::MessageIntegrity(MessageIntegrityReader::new(value)))),
                0x0009 => Some(Ok(ReaderAttribute::ErrorCode(StunErrorReader::new(value)))),
                0x000A => Some(Ok(ReaderAttribute::UnknownAttributes(UnknownAttrsReader::new(value)))),
                0x000B => Some(Ok(ReaderAttribute::ReflectedFrom(SocketAddrReader::new(value)))),
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
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01, // transaction id (16 bytes total)
    ];

    #[test]
    fn read_message_type() {
        assert_eq!(MessageType::BindingRequest, Reader::new(&[0x00, 0x01]).get_message_type().unwrap());
        assert_eq!(MessageType::BindingResponse, Reader::new(&[0x01, 0x01]).get_message_type().unwrap());
        assert_eq!(MessageType::BindingErrorResponse, Reader::new(&[0x01, 0x11]).get_message_type().unwrap());
        assert_eq!(MessageType::SharedSecretRequest, Reader::new(&[0x00, 0x02]).get_message_type().unwrap());
        assert_eq!(MessageType::SharedSecretResponse, Reader::new(&[0x01, 0x02]).get_message_type().unwrap());
        assert_eq!(MessageType::SharedSecretErrorResponse, Reader::new(&[0x01, 0x12]).get_message_type().unwrap());
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
        if let Some(Ok(ReaderAttribute::MappedAddress(_))) = AttributeIterator::new(&[0x00, 0x01, 0x00, 0x00]).next() {} else {
            assert!(false, "Expected attribute MAPPED-ADDRESS");
        }

        if let Some(Ok(ReaderAttribute::ResponseAddress(_))) = AttributeIterator::new(&[0x00, 0x02, 0x00, 0x00]).next() {} else {
            assert!(false, "Expected attribute RESPONSE-ADDRESS");
        }

        if let Some(Ok(ReaderAttribute::ChangeRequest(_))) = AttributeIterator::new(&[0x00, 0x03, 0x00, 0x00]).next() {} else {
            assert!(false, "Expected attribute CHANGE-REQUEST");
        }

        if let Some(Ok(ReaderAttribute::SourceAddress(_))) = AttributeIterator::new(&[0x00, 0x04, 0x00, 0x00]).next() {} else {
            assert!(false, "Expected attribute SOURCE-ADDRESS");
        }

        if let Some(Ok(ReaderAttribute::ChangedAddress(_))) = AttributeIterator::new(&[0x00, 0x05, 0x00, 0x00]).next() {} else {
            assert!(false, "Expected attribute CHANGED-ADDRESS");
        }

        if let Some(Ok(ReaderAttribute::Username(_))) = AttributeIterator::new(&[0x00, 0x06, 0x00, 0x00]).next() {} else {
            assert!(false, "Expected attribute USERNAME");
        }

        if let Some(Ok(ReaderAttribute::Password(_))) = AttributeIterator::new(&[0x00, 0x07, 0x00, 0x00]).next() {} else {
            assert!(false, "Expected attribute PASSWORD");
        }

        if let Some(Ok(ReaderAttribute::MessageIntegrity(_))) = AttributeIterator::new(&[0x00, 0x08, 0x00, 0x00]).next() {} else {
            assert!(false, "Expected attribute MESSAGE-INTEGRITY");
        }

        if let Some(Ok(ReaderAttribute::ErrorCode(_))) = AttributeIterator::new(&[0x00, 0x09, 0x00, 0x00]).next() {} else {
            assert!(false, "Expected attribute ERROR-CODE");
        }

        if let Some(Ok(ReaderAttribute::UnknownAttributes(_))) = AttributeIterator::new(&[0x00, 0x0A, 0x00, 0x00]).next() {} else {
            assert!(false, "Expected attribute UNKNOWN-ATTRIBUTES");
        }

        if let Some(Ok(ReaderAttribute::ReflectedFrom(_))) = AttributeIterator::new(&[0x00, 0x0B, 0x00, 0x00]).next() {} else {
            assert!(false, "Expected attribute REFLECTED-FROM");
        }

        for optional_attr in 0x0000..=0x7FFF as u16 {
            if let Some(Ok(ReaderAttribute::OptionalAttribute { .. })) = AttributeIterator::new(&u32::to_be_bytes((optional_attr as u32) << 16)).next() {
                assert!(false, "Unexpected generic optional attribute for code {:#06X}", optional_attr);
            }
        }

        for optional_attr in 0x8000..=0xFFFF as u16 {
            if let Some(Ok(ReaderAttribute::OptionalAttribute { .. })) = AttributeIterator::new(&u32::to_be_bytes((optional_attr as u32) << 16)).next() {} else {
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
        let mut r = AttributeIterator::new(&MAPPED_ADDRESS_V4);

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
        let mut r = AttributeIterator::new(&MAPPED_ADDRESS_V6);

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

    const RESPONSE_ADDRESS_V4: [u8; 12] = [
        0x00, 0x02,             // type: ResponseAddress
        0x00, 0x08,             // value length
        0x00, 0x01,             // address family
        0x0A, 0x0B,             // port
        0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
    ];

    #[test]
    fn read_response_address_attr_ipv4() {
        let mut r = AttributeIterator::new(&RESPONSE_ADDRESS_V4);

        if let Some(Ok(ReaderAttribute::ResponseAddress(r))) = r.next() {
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
            assert!(false, "Iterator should return a valid ResponseAddress attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_response_address_attr_ipv4() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::ResponseAddress(SocketAddr::V4(MOCK_IPV4, MOCK_IPV4_PORT))).unwrap();
        assert_eq!(RESPONSE_ADDRESS_V4, buffer[20..])
    }

    const RESPONSE_ADDRESS_V6: [u8; 24] = [
        0x00, 0x02,             // type: ResponseAddress
        0x00, 0x14,             // value length
        0x00, 0x02,             // address family: IPv6
        0x0B, 0x0C,             // port
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, // ipv6 address
    ];

    #[test]
    fn read_response_address_attr_ipv6() {
        let mut r = AttributeIterator::new(&RESPONSE_ADDRESS_V6);

        if let Some(Ok(ReaderAttribute::ResponseAddress(r))) = r.next() {
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
            assert!(false, "Iterator should return a valid ResponseAddress attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_response_address_attr_ipv6() {
        let mut buffer = [0; 44];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::ResponseAddress(SocketAddr::V6(MOCK_IPV6, MOCK_IPV6_PORT))).unwrap();
        assert_eq!(RESPONSE_ADDRESS_V6, buffer[20..])
    }

    const CHANGE_REQUEST: [u8; 8] = [
        0x00, 0x03,                     // type: ChangeRequest
        0x00, 0x04,                     // value length
        0x00, 0x00, 0x00, 0x04 | 0x02,  // change both ip and port
    ];

    #[test]
    fn read_change_request_attr() {
        let mut r = AttributeIterator::new(&CHANGE_REQUEST);

        if let Some(Ok(ReaderAttribute::ChangeRequest(r))) = r.next() {
            assert!(r.get_change_ip().unwrap(), "Test flag change_ip should be true");
            assert!(r.get_change_port().unwrap(), "Test flag change_port should be true");
        } else {
            assert!(false, "Iterator should return a valid ChangeRequest attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_change_request_attr() {
        let mut buffer = [0; 28];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::ChangeRequest { change_ip: true, change_port: true }).unwrap();

        assert_eq!(CHANGE_REQUEST, buffer[20..]);
    }

    const SOURCE_ADDRESS_V4: [u8; 12] = [
        0x00, 0x04,             // type: SourceAddress
        0x00, 0x08,             // value length
        0x00, 0x01,             // address family
        0x0A, 0x0B,             // port
        0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
    ];

    #[test]
    fn read_source_address_attr_ipv4() {
        let mut r = AttributeIterator::new(&SOURCE_ADDRESS_V4);

        if let Some(Ok(ReaderAttribute::SourceAddress(r))) = r.next() {
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
            assert!(false, "Iterator should return a valid SourceAddress attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_source_address_attr_ipv4() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::SourceAddress(SocketAddr::V4(MOCK_IPV4, MOCK_IPV4_PORT))).unwrap();
        assert_eq!(SOURCE_ADDRESS_V4, buffer[20..])
    }

    const SOURCE_ADDRESS_V6: [u8; 24] = [
        0x00, 0x04,             // type: SourceAddress
        0x00, 0x14,             // value length
        0x00, 0x02,             // address family: IPv6
        0x0B, 0x0C,             // port
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, // ipv6 address
    ];

    #[test]
    fn read_source_address_attr_ipv6() {
        let mut r = AttributeIterator::new(&SOURCE_ADDRESS_V6);

        if let Some(Ok(ReaderAttribute::SourceAddress(r))) = r.next() {
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
            assert!(false, "Iterator should return a valid SourceAddress attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_source_address_attr_ipv6() {
        let mut buffer = [0; 44];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::SourceAddress(SocketAddr::V6(MOCK_IPV6, MOCK_IPV6_PORT))).unwrap();
        assert_eq!(SOURCE_ADDRESS_V6, buffer[20..])
    }

    const CHANGED_ADDRESS_V4: [u8; 12] = [
        0x00, 0x05,             // type: ChangedAddress
        0x00, 0x08,             // value length
        0x00, 0x01,             // address family
        0x0A, 0x0B,             // port
        0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
    ];

    #[test]
    fn read_changed_address_attr_ipv4() {
        let mut r = AttributeIterator::new(&CHANGED_ADDRESS_V4);

        if let Some(Ok(ReaderAttribute::ChangedAddress(r))) = r.next() {
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
            assert!(false, "Iterator should return a valid ChangedAddress attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_changed_address_attr_ipv4() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::ChangedAddress(SocketAddr::V4(MOCK_IPV4, MOCK_IPV4_PORT))).unwrap();
        assert_eq!(CHANGED_ADDRESS_V4, buffer[20..])
    }

    const CHANGED_ADDRESS_V6: [u8; 24] = [
        0x00, 0x05,             // type: ChangedAddress
        0x00, 0x14,             // value length
        0x00, 0x02,             // address family: IPv6
        0x0B, 0x0C,             // port
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, // ipv6 address
    ];

    #[test]
    fn read_changed_address_attr_ipv6() {
        let mut r = AttributeIterator::new(&CHANGED_ADDRESS_V6);

        if let Some(Ok(ReaderAttribute::ChangedAddress(r))) = r.next() {
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
            assert!(false, "Iterator should return a valid ChangedAddress attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_changed_address_attr_ipv6() {
        let mut buffer = [0; 44];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::ChangedAddress(SocketAddr::V6(MOCK_IPV6, MOCK_IPV6_PORT))).unwrap();
        assert_eq!(CHANGED_ADDRESS_V6, buffer[20..])
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
    fn read_message_integrity_addr() {
        let mut r = AttributeIterator::new(&MESSAGE_INTEGRITY);

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
    fn write_message_integrity_addr() {
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
        let mut r = AttributeIterator::new(&USERNAME);

        if let Some(Ok(ReaderAttribute::Username(r))) = r.next() {
            assert_eq!(MOCK_USERNAME, r.get_value().unwrap());
        } else {
            assert!(false, "Iterator should return a valid Username attribute");
        }

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_username_addr() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);
        w.add_attr(WriterAttribute::Username(MOCK_USERNAME)).unwrap();
        assert_eq!(USERNAME, buffer[20..]);
    }

    const PASSWORD: [u8; 12] = [
        0x00, 0x07, // type: Password
        0x00, 0x06, // value length
        0x70, 0x61,
        0x73, 0x73,
        0x31, 0x32, // 'pass12'
        0x00, 0x00, // padding
    ];

    const MOCK_PASSWORD: &'static str = "pass12";

    #[test]
    fn read_password_attr() {
        let mut r = AttributeIterator::new(&PASSWORD);

        if let Some(Ok(ReaderAttribute::Password(r))) = r.next() {
            assert_eq!(MOCK_PASSWORD, r.get_value().unwrap());
        } else {
            assert!(false, "Iterator should return a valid Password attribute");
        }

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_password_addr() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);
        w.add_attr(WriterAttribute::Password(MOCK_PASSWORD)).unwrap();
        assert_eq!(PASSWORD, buffer[20..]);
    }

    const REFLECTED_FROM_V4: [u8; 12] = [
        0x00, 0x0B,             // type: ReflectedFrom
        0x00, 0x08,             // value length
        0x00, 0x01,             // address family
        0x0A, 0x0B,             // port
        0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
    ];

    #[test]
    fn read_reflected_from_attr_ipv4() {
        let mut r = AttributeIterator::new(&REFLECTED_FROM_V4);

        if let Some(Ok(ReaderAttribute::ReflectedFrom(r))) = r.next() {
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
            assert!(false, "Iterator should return a valid ReflectedFrom attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_reflected_from_attr_ipv4() {
        let mut buffer = [0; 32];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::ReflectedFrom(SocketAddr::V4(MOCK_IPV4, MOCK_IPV4_PORT))).unwrap();
        assert_eq!(REFLECTED_FROM_V4, buffer[20..])
    }

    const REFLECTED_FROM_V6: [u8; 24] = [
        0x00, 0x0B,             // type: ReflectedFrom
        0x00, 0x14,             // value length
        0x00, 0x02,             // address family: IPv6
        0x0B, 0x0C,             // port
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, // ipv6 address
    ];

    #[test]
    fn read_reflected_from_attr_ipv6() {
        let mut r = AttributeIterator::new(&REFLECTED_FROM_V6);

        if let Some(Ok(ReaderAttribute::ReflectedFrom(r))) = r.next() {
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
            assert!(false, "Iterator should return a valid ReflectedFrom attribute");
            return;
        };

        assert!(r.next().is_none(), "There should be only one attribute");
    }

    #[test]
    fn write_reflected_from_attr_ipv6() {
        let mut buffer = [0; 44];
        let mut w = Writer::new(&mut buffer);

        w.add_attr(WriterAttribute::ReflectedFrom(SocketAddr::V6(MOCK_IPV6, MOCK_IPV6_PORT))).unwrap();
        assert_eq!(REFLECTED_FROM_V6, buffer[20..])
    }

}
