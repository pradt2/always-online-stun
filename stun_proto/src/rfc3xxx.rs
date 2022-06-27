use super::*;
pub use super::base::*;

pub struct Reader<'a> {
    header: MsgHeaderReader<'a>,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            header: MsgHeaderReader::new(bytes)
        }
    }

    /// Gets the message method.
    /// <br><br>
    ///
    /// Currently the method `Binding` is the only method in the RFC specs.
    /// <br><br>
    ///
    /// Ignores the first two bits of the message header, as they should always be 0.
    /// <br><br>
    ///
    /// Returns
    /// - `Result::NotEnoughBytes` if the message is not large enough
    /// - `Result::UnexpectedValue` if the value doesn't correspond to a known method
    /// <br><br>
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// use stun_proto::rfc3xxx::*;
    /// let msg = [0x0, 0x1];
    /// let r = Reader::new(&msg);
    /// assert_eq!(Method::Binding, r.get_method().unwrap());
    /// ```
    ///
    /// The message is not large enough:
    /// ```
    /// use stun_proto::rfc3xxx::*;
    /// let msg = [];
    /// let r = Reader::new(&msg);
    /// assert_eq!(ReaderErr::NotEnoughBytes, r.get_method().unwrap_err());
    /// ```
    ///
    /// The value does not correspond to a known method:
    /// ```
    /// use stun_proto::rfc3xxx::*;
    /// let msg = [0x0, 0xF];
    /// let r = Reader::new(&msg);
    /// assert_eq!(ReaderErr::UnexpectedValue, r.get_method().unwrap_err());
    /// ```
    pub fn get_method(&self) -> Result<Method> {
        self.header.get_method()
    }

    /// Gets the message class.
    /// <br><br>
    ///
    /// Ignores all header bits except the 5th and the 9th bit.
    /// <br><br>
    ///
    /// Returns
    /// - `Result::NotEnoughBytes` if the message is not large enough
    /// <br><br>
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// use stun_proto::rfc3xxx::*;
    /// let msg = [0x0, 0x1];
    /// let r = Reader::new(&msg);
    /// assert_eq!(Class::Request, r.get_class().unwrap());
    /// ```
    ///
    /// The message is not large enough:
    /// ```
    /// use stun_proto::rfc3xxx::*;
    /// let msg = [];
    /// let r = Reader::new(&msg);
    /// assert_eq!(ReaderErr::NotEnoughBytes, r.get_class().unwrap_err());
    /// ```
    pub fn get_class(&self) -> Result<Class> {
        self.header.get_class()
    }

    pub fn get_magic_cookie(&self) -> Result<u32> {
        self.header.get_magic_cookie()
    }

    pub fn get_transaction_id(&self) -> Result<u128> {
        self.header.get_transaction_id()
    }

    pub fn attrs(&self) -> Result<AttributeIterator> {
        let bytes = self.header.get_attributes()?;
        let transaction_id = self.header.get_transaction_id()?;
        Ok(AttributeIterator::new(bytes, transaction_id))
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

    #[test]
    fn message_header() {
        let msg = [
            0x00, 0x01,             // method: Binding , class: Request
            0x00, 0x00,             // length: 0 (header does not count)
            0x21, 0x12, 0xA4, 0x42, // magic cookie (RFC spec constant)
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, // transaction id (12 bytes total)
        ];

        let r = MsgHeaderReader::new(&msg);

        assert_eq!(Method::Binding, r.get_method().unwrap());
        assert_eq!(Class::Request, r.get_class().unwrap());
        assert_eq!(0x2112A442, r.get_magic_cookie().unwrap());
        assert_eq!(1u128, r.get_transaction_id().unwrap());
    }

    #[test]
    fn mapped_address_attr() {
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
    fn message() {
        let attr = [
            0x00, 0x01,             // method: Binding , class: Request
            0x00, 0x0C,             // length: 12 (only data after 20-byte header)
            0x21, 0x12, 0xA4, 0x42, // magic cookie (RFC spec constant)
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

        assert_eq!(Method::Binding, r.get_method().unwrap());
        assert_eq!(Class::Request, r.get_class().unwrap());
        assert_eq!(0x2112A442, r.get_magic_cookie().unwrap());
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
