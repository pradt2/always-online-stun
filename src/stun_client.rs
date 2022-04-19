use std::convert::TryInto;
use std::fmt::format;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

#[derive(Debug)]
enum MessageClass {
    Request,
    Indirection,
    SuccessResponse,
    ErrorResponse
}

#[derive(Debug)]
enum Method {
    Binding
}

struct StunHeaderReader<'a> {
    bytes: &'a [u8],
}

#[derive(Debug)]
enum StunReaderError {
    NotEnoughBytes {
        expected: usize,
        actual: usize,
    },
    UnknownMethod {
        code: u16
    },
    UnknownAddressFamily {
        code: u8
    }
}

#[derive(PartialEq)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

type StunReaderResult<T> = Result<T, StunReaderError>;

impl StunHeaderReader<'_> {
    const HEADER_SIZE: usize = 20;

    fn new(bytes: &[u8]) -> StunReaderResult<StunHeaderReader> {
        if bytes.len() < StunHeaderReader::HEADER_SIZE {
            Err(StunReaderError::NotEnoughBytes {
                expected: StunHeaderReader::HEADER_SIZE,
                actual: bytes.len(),
            })
        } else {
            Ok(StunHeaderReader { bytes: &bytes[0..20] })
        }
    }

    fn get_message_type(&self) -> u16 {
        let msg_type: u16 = u16::from_be_bytes(self.bytes[0..2].try_into().unwrap() );
        msg_type
    }

    fn get_class(&self) -> MessageClass {
        let msg_type = self.get_message_type();
        let mut class: u16 = 0;
        class = bitwise::copy_bit(msg_type, 4u8, class, 0u8);
        class = bitwise::copy_bit(msg_type, 8u8, class, 1u8);
        match class {
            0 => MessageClass::Request,
            1 => MessageClass::Indirection,
            2 => MessageClass::SuccessResponse,
            3 => MessageClass::ErrorResponse,
            _ => panic!("Impossible message class")
        }
    }

    fn get_method(&self) -> StunReaderResult<Method> {
        let msg_type = self.get_message_type();
        let method_code: u16 = bitwise::extract_bits(msg_type, 0u8, 4u8)
            | bitwise::extract_bits(msg_type, 4u8, 3u8)
            | bitwise::extract_bits(msg_type, 9u8, 5u8);
        match method_code {
            1 => Ok(Method::Binding),
            _ => Err(StunReaderError::UnknownMethod { code: method_code })
        }
    }

    fn get_length(&self) -> u16 {
        let length: u16 = u16::from_be_bytes(self.bytes[2..4].try_into().unwrap());
        length
    }

    fn get_cookie(&self) -> u32 {
        let cookie: u32 = u32::from_be_bytes(self.bytes[4..8].try_into().unwrap());
        cookie
    }

    fn get_transaction_id(&self) -> (u32, u32, u32) {
        let transaction_id = (u32::from_ne_bytes(self.bytes[8..12].try_into().unwrap()),
                              u32::from_ne_bytes(self.bytes[12..16].try_into().unwrap()),
                              u32::from_ne_bytes(self.bytes[16..20].try_into().unwrap()));
        transaction_id
    }

    fn get_used_bytes(&self) -> u16 {
        20
    }

    fn to_string(&self) -> String {
        format!("Method: {:?} , Class {:?}\n", self.get_method(), self.get_class())
    }
}

fn get_attr_length(bytes: &[u8]) -> u16 {
    let length = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
    length
}

fn get_attr_length_padded(bytes: &[u8]) -> u16 {
    let length_padded = (get_attr_length(bytes) + 4 - 1) & (-4i16 as u16); // bring attr length to the nearest multiple of 4 to account for padding
    length_padded
}

fn get_attr_type(bytes: &[u8]) -> u16 {
    let typ = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
    typ
}

struct MappedAddressReader<'a> {
    bytes: &'a [u8]
}

impl MappedAddressReader<'_> {
    fn supports(bytes: &[u8]) -> bool {
        let supports = if bytes.len() < 2 { false } else {  get_attr_type(bytes) == 0x0001 };
        supports
    }

    fn new(bytes: &[u8]) -> StunReaderResult<MappedAddressReader> {
        if bytes.len() < 12 {
            Err(StunReaderError::NotEnoughBytes { expected: 12, actual: bytes.len() })
        } else {
            let reader = MappedAddressReader { bytes };
            if reader.get_family()? == AddressFamily::Ipv6 && bytes.len() < 24 {
                Err(StunReaderError::NotEnoughBytes { expected: 24, actual: bytes.len() })
            } else {
                Ok(reader)
            }
        }
    }

    fn get_family(&self) -> StunReaderResult<AddressFamily> {
        let family = self.bytes[5];
        match family {
            1 => Ok(AddressFamily::Ipv4),
            2 => Ok(AddressFamily::Ipv6),
            _ => Err(StunReaderError::UnknownAddressFamily { code: family })
        }
    }

    fn get_port(&self) -> u16 {
        let port: u16 = u16::from_be_bytes(self.bytes[6..8].try_into().unwrap());
        port
    }

    fn get_addr(&self) -> StunReaderResult<IpAddr> {
        match self.get_family()? {
            AddressFamily::Ipv4 => {
                let ip_num= u32::from_be_bytes(self.bytes[8..12].try_into().unwrap());
                Ok(IpAddr::V4(Ipv4Addr::from(ip_num)))
            },
            AddressFamily::Ipv6 => {
                let ip_num = u128::from_be_bytes(self.bytes[8..24].try_into().unwrap());
                Ok(IpAddr::V6(Ipv6Addr::from(ip_num)))
            },
        }
    }

    fn get_used_bytes(&self) -> u16 {
        let used_bytes = 4 + get_attr_length_padded(self.bytes);
        used_bytes
    }

    fn to_string(&self) -> String {
        format!("MappedAddress {:?}", SocketAddr::new(self.get_addr().unwrap(), self.get_port()))
    }
}

struct AnyAttributeReader<'a> {
    bytes: &'a [u8]
}

impl AnyAttributeReader<'_> {
    fn supports(bytes: &[u8]) -> bool {
        let supports = if bytes.len() < 2 { false } else { true };
        supports
    }

    fn new(bytes: &[u8]) -> StunReaderResult<AnyAttributeReader> {
        if bytes.len() < 2 {
            Err(StunReaderError::NotEnoughBytes { expected: 12, actual: bytes.len() })
        } else {
            let reader = AnyAttributeReader { bytes };
            Ok(reader)
        }
    }

    fn get_used_bytes(&self) -> u16 {
        let used_bytes = 4 + get_attr_length_padded(self.bytes);
        used_bytes
    }

    fn to_string(&self) -> String {
        format!("AnyAttribute type {:04x} len {} bytes {:?}", get_attr_type(self.bytes), get_attr_length(self.bytes), &self.bytes[4..get_attr_length_padded(self.bytes) as usize] )
    }
}


// RFC 5780
struct ResponseOriginReader<'a> {
    bytes: &'a [u8]
}

impl ResponseOriginReader<'_> {
    fn supports(bytes: &[u8]) -> bool {
        let supports = if bytes.len() < 2 { false } else {  get_attr_type(bytes) == 0x802b };
        supports
    }

    fn new(bytes: &[u8]) -> StunReaderResult<ResponseOriginReader> {
        if bytes.len() < 12 {
            Err(StunReaderError::NotEnoughBytes { expected: 12, actual: bytes.len() })
        } else {
            let reader = ResponseOriginReader { bytes };
            if reader.get_family()? == AddressFamily::Ipv6 && bytes.len() < 24 {
                Err(StunReaderError::NotEnoughBytes { expected: 24, actual: bytes.len() })
            } else {
                Ok(reader)
            }
        }
    }

    fn get_family(&self) -> StunReaderResult<AddressFamily> {
        let family = self.bytes[5];
        match family {
            1 => Ok(AddressFamily::Ipv4),
            2 => Ok(AddressFamily::Ipv6),
            _ => Err(StunReaderError::UnknownAddressFamily { code: family })
        }
    }

    fn get_port(&self) -> u16 {
        let port: u16 = u16::from_be_bytes(self.bytes[6..8].try_into().unwrap());
        port
    }

    fn get_addr(&self) -> StunReaderResult<IpAddr> {
        match self.get_family()? {
            AddressFamily::Ipv4 => {
                let octets: [u8; 4] = self.bytes[8..12].try_into().unwrap();
                Ok(IpAddr::V4(Ipv4Addr::from(octets)))
            },
            AddressFamily::Ipv6 => {
                let octets: [u8; 16] = self.bytes[8..24].try_into().unwrap();
                Ok(IpAddr::V6(Ipv6Addr::from(octets)))
            },
        }
    }

    fn get_used_bytes(&self) -> u16 {
        let used_bytes = 4 + get_attr_length_padded(self.bytes);
        used_bytes
    }

    fn to_string(&self) -> String {
        format!("ResponseOrigin {:?}", SocketAddr::new(self.get_addr().unwrap(), self.get_port()))
    }
}

struct XorMappedAddressReader<'a> {
    bytes: &'a [u8],
    transaction_id: &'a (u32, u32, u32),
}

impl XorMappedAddressReader<'_> {
    fn supports(bytes: &[u8]) -> bool {
        let supports = if bytes.len() < 2 { false } else {  get_attr_type(bytes) == 0x0020 };
        supports
    }

    fn new<'a>(bytes: &'a [u8], transaction_id: &'a (u32, u32, u32)) -> StunReaderResult<XorMappedAddressReader<'a>> {
        if bytes.len() < 12 {
            Err(StunReaderError::NotEnoughBytes { expected: 12, actual: bytes.len() })
        } else {
            let reader = XorMappedAddressReader { bytes , transaction_id };
            if reader.get_family()? == AddressFamily::Ipv6 && bytes.len() < 24 {
                Err(StunReaderError::NotEnoughBytes { expected: 24, actual: bytes.len() })
            } else {
                Ok(reader)
            }
        }
    }

    fn get_family(&self) -> StunReaderResult<AddressFamily> {
        let family = self.bytes[5];
        match family {
            1 => Ok(AddressFamily::Ipv4),
            2 => Ok(AddressFamily::Ipv6),
            _ => Err(StunReaderError::UnknownAddressFamily { code: family })
        }
    }

    fn get_port(&self) -> u16 {
        let port: u16 = u16::from_be_bytes(self.bytes[6..8].try_into().unwrap()) ^ 0x2112; // xor with top half of magic cookie
        port
    }

    fn get_addr(&self) -> StunReaderResult<IpAddr> {
        match self.get_family()? {
            AddressFamily::Ipv4 => {
                let ip_num = u32::from_be_bytes(self.bytes[8..12].try_into().unwrap()) ^ 0x2112A442; // xor with magic cookie
                Ok(IpAddr::V4(Ipv4Addr::from(ip_num)))
            },
            AddressFamily::Ipv6 => {
                let t_id = self.transaction_id;
                let ip_num = u128::from_be_bytes(self.bytes[8..24].try_into().unwrap()) ^ (0x2112A442_u128 << 92 | (t_id.2 as u128) << 64 | (t_id.1 as u128) << 32 | t_id.0 as u128);
                Ok(IpAddr::V6(Ipv6Addr::from(ip_num)))
            },
        }
    }

    fn get_used_bytes(&self) -> u16 {
        let used_bytes = 4 + get_attr_length_padded(self.bytes);
        used_bytes
    }

    fn to_string(&self) -> String {
        format!("XorMappedAddress {:?}", SocketAddr::new(self.get_addr().unwrap(), self.get_port()))
    }
}

struct ComprehensionOptionalXorMappedAddressReader<'a> {
    bytes: &'a [u8],
    transaction_id: &'a (u32, u32, u32),
}

impl ComprehensionOptionalXorMappedAddressReader<'_> {
    fn supports(bytes: &[u8]) -> bool {
        let supports = if bytes.len() < 2 { false } else {  get_attr_type(bytes) == 0x8020 };
        supports
    }

    fn new<'a>(bytes: &'a [u8], transaction_id: &'a (u32, u32, u32)) -> StunReaderResult<ComprehensionOptionalXorMappedAddressReader<'a>> {
        if bytes.len() < 12 {
            Err(StunReaderError::NotEnoughBytes { expected: 12, actual: bytes.len() })
        } else {
            let reader = ComprehensionOptionalXorMappedAddressReader { bytes , transaction_id };
            if reader.get_family()? == AddressFamily::Ipv6 && bytes.len() < 24 {
                Err(StunReaderError::NotEnoughBytes { expected: 24, actual: bytes.len() })
            } else {
                Ok(reader)
            }
        }
    }

    fn get_family(&self) -> StunReaderResult<AddressFamily> {
        let family = self.bytes[5];
        match family {
            1 => Ok(AddressFamily::Ipv4),
            2 => Ok(AddressFamily::Ipv6),
            _ => Err(StunReaderError::UnknownAddressFamily { code: family })
        }
    }

    fn get_port(&self) -> u16 {
        let port: u16 = u16::from_be_bytes(self.bytes[6..8].try_into().unwrap()) ^ 0x2112; // xor with top half of magic cookie
        port
    }

    fn get_addr(&self) -> StunReaderResult<IpAddr> {
        match self.get_family()? {
            AddressFamily::Ipv4 => {
                let ip_num = u32::from_be_bytes(self.bytes[8..12].try_into().unwrap()) ^ 0x2112A442; // xor with magic cookie
                Ok(IpAddr::V4(Ipv4Addr::from(ip_num)))
            },
            AddressFamily::Ipv6 => {
                let t_id = self.transaction_id;
                let ip_num = u128::from_be_bytes(self.bytes[8..24].try_into().unwrap()) ^ (0x2112A442_u128 << 92 | (t_id.2 as u128) << 64 | (t_id.1 as u128) << 32 | t_id.0 as u128);
                Ok(IpAddr::V6(Ipv6Addr::from(ip_num)))
            },
        }
    }

    fn get_used_bytes(&self) -> u16 {
        let used_bytes = 4 + get_attr_length_padded(self.bytes);
        used_bytes
    }

    fn to_string(&self) -> String {
        format!("ComprehensionOptionalXorMappedAddress {:?}", SocketAddr::new(self.get_addr().unwrap(), self.get_port()))
    }
}

enum RfcSpec {
    Rfc3489,
    Rfc5245,
    Rfc5389,
    Rfc5766,
    Rfc5780
}

enum MessageAttribute {
    Reserved0x0000,
    MappedAddress,
    ResponseAddress,
    ChangeAddress,
    SourceAddress,
    ChangedAddress,
    Username,
    Password,
    MessageIntegrity,
    ErrorCode,
    UnknownAttribute,
    ReflectedFrom,
    Realm,
    Nonce,
    XorMappedAddress,
    OptXorMappedAddress,
    Software,
    AlternateServer,
    Fingerprint
}

impl MessageAttribute {
    fn get_code(&self) -> u16 {
        match self {
            MessageAttribute::Reserved0x0000        => { 0x0000 }
            MessageAttribute::MappedAddress         => { 0x0001 }
            MessageAttribute::ResponseAddress       => { 0x0002 }
            MessageAttribute::ChangeAddress         => { 0x0003 }
            MessageAttribute::SourceAddress         => { 0x0004 }
            MessageAttribute::ChangedAddress        => { 0x0005 }
            MessageAttribute::Username              => { 0x0006 }
            MessageAttribute::Password              => { 0x0007 }
            MessageAttribute::MessageIntegrity      => { 0x0008 }
            MessageAttribute::ErrorCode             => { 0x0009 }
            MessageAttribute::UnknownAttribute      => { 0x000A }
            MessageAttribute::ReflectedFrom         => { 0x000B }
            MessageAttribute::Realm                 => { 0x0014 }
            MessageAttribute::Nonce                 => { 0x0015 }
            MessageAttribute::XorMappedAddress      => { 0x0020 }
            MessageAttribute::OptXorMappedAddress   => { 0x8020 }
            MessageAttribute::Software              => { 0x8022 }
            MessageAttribute::AlternateServer       => { 0x8023 }
            MessageAttribute::Fingerprint           => { 0x8028 }
        }
    }
}

pub(crate) fn read_stun_message(bytes: &[u8]) {

    let r = StunHeaderReader::new(bytes).unwrap();
    println!("{}", r.to_string());
    let mut bytes = &bytes[r.get_used_bytes() as usize ..];
    let t_id = r.get_transaction_id();
    loop {
        if MappedAddressReader::supports(bytes) {
            let r = MappedAddressReader::new(bytes).unwrap();
            println!("{}", r.to_string());
            bytes = &bytes[r.get_used_bytes() as usize ..];
        } else if XorMappedAddressReader::supports(bytes) {
            let r = XorMappedAddressReader::new(bytes, &t_id).unwrap();
            println!("{}", r.to_string());
            bytes = &bytes[r.get_used_bytes() as usize ..];
        } else if ResponseOriginReader::supports(bytes) {
            let r = ResponseOriginReader::new(bytes).unwrap();
            println!("{}", r.to_string());
            bytes = &bytes[r.get_used_bytes() as usize ..];
        } else if ComprehensionOptionalXorMappedAddressReader::supports(bytes) {
            let r = ComprehensionOptionalXorMappedAddressReader::new(bytes, &t_id).unwrap();
            println!("{}", r.to_string());
            bytes = &bytes[r.get_used_bytes() as usize ..];
        } else if AnyAttributeReader::supports(bytes) {
            let r = AnyAttributeReader::new(bytes).unwrap();
            println!("{}", r.to_string());
            bytes = &bytes[r.get_used_bytes() as usize ..];
        } else {
            println!("Bytes left {}", bytes.len());
            break;
        }
    }
}
