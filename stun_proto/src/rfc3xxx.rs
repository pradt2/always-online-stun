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

    pub fn attrs(&self) -> Result<AttributeIterator> {
        let transaction_id = self.header.get_transaction_id()?;
        Ok(AttributeIterator::new(self.attr_bytes, transaction_id))
    }
}

pub struct Writer<'a> {
    header: RawMsgHeaderWriter<'a>,
    attr_bytes: &'a mut [u8],
}

impl<'a> Writer<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        if bytes.len() <= 20 {
            let (header_bytes, attr_bytes) = bytes.split_at_mut(20);
            Self {
                header: RawMsgHeaderWriter::new(header_bytes),
                attr_bytes,
            }
        } else {
            // for such a small buffer,
            // attr is guarateed to get a slice of zero length
            // but who are we to judge
            let (header_bytes, attr_bytes) = bytes.split_at_mut(bytes.len());
            Self {
                header: RawMsgHeaderWriter::new(header_bytes),
                attr_bytes,
            }
        }
    }

    pub fn set_message_type(&mut self, typ: MessageType) -> Result<()> {
        self.header.set_message_type(typ as u16)
    }

    pub fn set_message_length(&mut self, len: u16) -> Result<()> {
        self.header.set_message_length(len)
    }

    pub fn set_transaction_id(&mut self, tid: u128) -> Result<()> {
        self.header.set_transaction_id(tid)
    }
}

pub enum Attribute<'a> {
    MappedAddress(SocketAddrReader<'a>),
    ResponseAddress(SocketAddrReader<'a>),
    ChangeAddress(SocketAddrReader<'a>),
    SourceAddress(SocketAddrReader<'a>),
    ChangedAddress(SocketAddrReader<'a>),
    Username(StringReader<'a>),
    Password(StringReader<'a>),
    MessageIntegrity(MessageIntegrityReader<'a>),
    UnknownAttributes(UnknownAttrsReader<'a>),
    ReflectedFrom(SocketAddrReader<'a>),
    ErrorCode(ErrorCodeReader<'a>),
    Realm(StringReader<'a>),
    Nonce(StringReader<'a>),
    XorMappedAddress(XorSocketAddrReader<'a>),
    OptXorMappedAddress(XorSocketAddrReader<'a>),
    Software(StringReader<'a>),
    AlternateServer(SocketAddrReader<'a>),
    ResponseOrigin(SocketAddrReader<'a>),
    OtherAddress(SocketAddrReader<'a>),
    Fingerprint(FingerprintReader<'a>),
}

pub struct AttributeIterator<'a> {
    base_iter: BaseAttributeIterator<'a>,
    transaction_id: u128,
}

impl<'a> AttributeIterator<'a> {
    fn new(bytes: &'a [u8], transaction_id: u128) -> Self {
        Self {
            base_iter: BaseAttributeIterator::new(bytes),
            transaction_id,
        }
    }
}

impl<'a> Iterator for AttributeIterator<'a> {
    type Item = Result<Attribute<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.base_iter.next() {
            None => None,
            Some(Err(err)) => Some(Err(err)),
            Some(Ok((typ, bytes))) => match typ {
                0x0001 => Some(Ok(Attribute::MappedAddress(SocketAddrReader::new(bytes)))),
                0x0002 => Some(Ok(Attribute::ResponseAddress(SocketAddrReader::new(bytes)))),
                0x0003 => Some(Ok(Attribute::ChangeAddress(SocketAddrReader::new(bytes)))),
                0x0004 => Some(Ok(Attribute::SourceAddress(SocketAddrReader::new(bytes)))),
                0x0005 => Some(Ok(Attribute::ChangedAddress(SocketAddrReader::new(bytes)))),
                0x0006 => Some(Ok(Attribute::Username(StringReader::new(bytes)))),
                0x0007 => Some(Ok(Attribute::Password(StringReader::new(bytes)))),
                0x0008 => Some(Ok(Attribute::MessageIntegrity(MessageIntegrityReader::new(bytes)))),
                0x000A => Some(Ok(Attribute::UnknownAttributes(UnknownAttrsReader::new(bytes)))),
                0x000B => Some(Ok(Attribute::ReflectedFrom(SocketAddrReader::new(bytes)))),
                0x0009 => Some(Ok(Attribute::ErrorCode(ErrorCodeReader::new(bytes)))),
                0x0014 => Some(Ok(Attribute::Realm(StringReader::new(bytes)))),
                0x0015 => Some(Ok(Attribute::Nonce(StringReader::new(bytes)))),
                0x0020 => Some(Ok(Attribute::XorMappedAddress(XorSocketAddrReader::new(bytes, self.transaction_id)))),
                0x8020 => Some(Ok(Attribute::OptXorMappedAddress(XorSocketAddrReader::new(bytes, self.transaction_id)))),
                0x8022 => Some(Ok(Attribute::Software(StringReader::new(bytes)))),
                0x8023 => Some(Ok(Attribute::AlternateServer(SocketAddrReader::new(bytes)))),
                0x802b => Some(Ok(Attribute::ResponseOrigin(SocketAddrReader::new(bytes)))),
                0x802c => Some(Ok(Attribute::OtherAddress(SocketAddrReader::new(bytes)))),
                0x8028 => Some(Ok(Attribute::Fingerprint(FingerprintReader::new(bytes)))),
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
    fn read_mapped_address_attr() {
        let attr = [
            0x00, 0x01,             // type (MappedAddress)
            0x00, 0x08,             // value length
            0x00, 0x01,             // address family
            0x0A, 0x0B,             // port
            0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
        ];

        assert_eq!(1, AttributeIterator::new(&attr, 0).count());

        let r = AttributeIterator::new(&attr, 0).next();

        let r = if let Some(Ok(Attribute::MappedAddress(r))) = r { r } else {
            assert!(false, "Iterator should return a valid MappingAddress attribute");
            return;
        };

        let addr = if let Ok(addr) = r.get_address() { addr } else {
            assert!(false, "Test address should be a valid address");
            return;
        };

        if let SocketAddr::V4 { addr, port } = addr {
            assert_eq!(0x0A0B, port);
            assert_eq!(0x0C0D0E0F, addr);
        } else {
            assert!(false, "Test address should be a V4 address");
        }
    }

    #[test]
    fn read_message() {
        let attr = [
            0x00, 0x01,             // method: Binding , class: Request
            0x00, 0x0C,             // length: 12 (only data after 20-byte header)
            0x00, 0x00, 0x00, 0x00, // magic cookie (RFC spec constant)
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, // transaction id (12 bytes total)
            0x00, 0x01,             // type (MappedAddress)
            0x00, 0x08,             // value length
            0x00, 0x01,             // address family
            0x0A, 0x0B,             // port
            0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
        ];

        let r = Reader::new(&attr);

        // assert_eq!(Method::Binding, r.get_method().unwrap());
        // assert_eq!(Class::Request, r.get_class().unwrap());
        // assert_eq!(0x2112A442, r.get_magic_cookie().unwrap());
        assert_eq!(1u128, r.get_transaction_id().unwrap());

        assert_eq!(1, r.attrs().unwrap().count());

        let r = r.attrs().unwrap().next();

        let r = if let Some(Ok(Attribute::MappedAddress(r))) = r { r } else {
            assert!(false, "Iterator should return a valid MappingAddress attribute");
            return;
        };

        let addr = if let Ok(addr) = r.get_address() { addr } else {
            assert!(false, "Test address should be a valid address");
            return;
        };

        if let SocketAddr::V4 { addr, port } = addr {
            assert_eq!(0x0A0B, port);
            assert_eq!(0x0C0D0E0F, addr);
        } else {
            assert!(false, "Test address should be a V4 address");
        }
    }
}
