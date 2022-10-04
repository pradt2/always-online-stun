use crate::endian::{u16be, u32be, u128be};

pub struct Msg<'a> {
    reader: RawMsg<'a>,
}

impl<'a> Msg<'a> {
    fn from(buf: &'a [u8]) -> Option<Self> {
        Some(Self {
            reader: RawMsg::from(buf)?
        })
    }

    fn typ(&self) -> MsgType {
        MsgType::from(self.reader.typ.get())
    }

    fn tid(&self) -> u128 {
        self.reader.tid.get()
    }

    fn attrs_iter(&self) -> AttrIter {
        AttrIter { raw_iter: self.reader.attrs_iter(), tid: self.reader.tid, attr: Attr::Other { typ: 0, val: &[] } }
    }
}

enum MsgType {
    #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
    BindingRequest,

    #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
    BindingResponse,

    #[cfg(any(feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
    BindingIndication,

    #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
    BindingErrorResponse,

    #[cfg(feature = "rfc3489")]
    SharedSecretRequest,

    #[cfg(feature = "rfc3489")]
    SharedSecretResponse,

    #[cfg(feature = "rfc3489")]
    SharedSecretErrorResponse,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    AllocateRequest,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    AllocateResponse,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    AllocateErrorResponse,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    RefreshRequest,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    RefreshResponse,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    RefreshErrorResponse,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    SendIndication,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    DataIndication,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    CreatePermissionRequest,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    CreatePermissionResponse,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    CreatePermissionErrorResponse,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    ChannelBindRequest,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    ChannelBindResponse,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    ChannelBindErrorResponse,

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectRequest,

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectResponse,

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectErrorResponse,

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectionBindRequest,

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectionBindResponse,

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectionBindErrorResponse,

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectionAttemptIndication,

    #[cfg(feature = "iana")]
    GooglePing,

    Other(u16),
}

impl From<u16> for MsgType {
    fn from(val: u16) -> Self {
        match val {
            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            0x0001 => MsgType::BindingRequest,

            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            0x0011 => MsgType::BindingResponse,

            #[cfg(any(feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            0x0101 => MsgType::BindingIndication,

            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            0x0111 => MsgType::BindingErrorResponse,

            #[cfg(feature = "rfc3489")]
            0x0002 => MsgType::SharedSecretRequest,

            #[cfg(feature = "rfc3489")]
            0x0102 => MsgType::SharedSecretResponse,

            #[cfg(feature = "rfc3489")]
            0x0112 => MsgType::SharedSecretErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::AllocateRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::AllocateResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::AllocateErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::RefreshRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::RefreshResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::RefreshErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::SendIndication,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::DataIndication,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::CreatePermissionRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::CreatePermissionResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::CreatePermissionErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::ChannelBindRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::ChannelBindResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0000 => MsgType::ChannelBindErrorResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x0000 => MsgType::ConnectRequest,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x0000 => MsgType::ConnectResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x0000 => MsgType::ConnectErrorResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x0000 => MsgType::ConnectionBindRequest,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x0000 => MsgType::ConnectionBindResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x0000 => MsgType::ConnectionBindErrorResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x0000 => MsgType::ConnectionAttemptIndication,

            #[cfg(feature = "iana")]
            0x000 => MsgType::GooglePing,

            val => MsgType::Other(val),
        }
    }
}

#[derive(Copy, Clone)]
pub enum SocketAddr {
    V4(u32, u16),
    V6(u128, u16),
}

#[derive(Copy, Clone)]
enum Attr<'a> {
    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    MappedAddress(SocketAddr),

    #[cfg(feature = "rfc3489")]
    ResponseAddress(SocketAddr),

    #[cfg(any(feature = "rfc3489", feature = "rfc5780", feature = "iana"))]
    ChangeRequest { change_ip: bool, change_port: bool },

    #[cfg(feature = "rfc3489")]
    SourceAddress(SocketAddr),

    #[cfg(feature = "rfc3489")]
    ChangedAddress(SocketAddr),

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    Username(&'a str),

    #[cfg(feature = "rfc3489")]
    Password(&'a str),

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    Realm(&'a str),

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    Nonce(&'a str),

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    MessageIntegrity(&'a [u8; 20]),

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    MessageIntegritySha256(&'a [u8; 32]),

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    Fingerprint(u32),

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    XorMappedAddress(SocketAddr),

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    Software(&'a str),

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    AlternateServer(SocketAddr),

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    ErrorCode { code: u16, reason: &'a str },

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    UnknownAttributes(&'a [u16be]),

    #[cfg(feature = "rfc3489")]
    ReflectedFrom(SocketAddr),

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    Priority(u32),

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    UseCandidate,

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    IceControlled(u64),

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    IceControlling(u64),

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    ResponseOrigin(SocketAddr),

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    OtherAddress(SocketAddr),

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    ResponsePort(u16),

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    Padding(&'a [u8]),

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    CacheTimeout(u32),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    ChannelNumber(u16),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    Lifetime(u32),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    XorPeerAddress(SocketAddr),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    Data(&'a [u8]),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    XorRelayedAddress(SocketAddr),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    EvenPort(bool),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    RequestedTransport(u8), // can be narrowed down

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    DontFragment,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    ReservationToken(u64),

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    RequestedAddressFamily(u8), // can be narrowed down

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    AdditionalAddressFamily(u8), // can be narrowed down

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    AddressErrorCode { family: u8, code: u16, reason: &'a str }, // family and code can be narrowed down

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    Icmp { typ: u8, code: u8, data: u32 }, // maybe can be narrowed down

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    Userhash(&'a [u8; 32]),

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    PasswordAlgorithm(PasswordAlgorithm<'a>),

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    PasswordAlgorithms(PasswordAlgorithmIter<'a>),

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    AlternateDomain(&'a str),

    #[cfg(any(feature = "rfc6679", feature = "iana"))]
    EcnCheck { valid: bool, val: u8 },

    #[cfg(any(feature = "rfc7635", feature = "iana"))]
    ThirdPartyAuthorisation(&'a str),

    #[cfg(any(feature = "rfc7635", feature = "iana"))]
    AccessToken { nonce: &'a [u8], mac: &'a [u8], timestamp: u64, lifetime: u32 },

    #[cfg(any(feature = "rfc8016", feature = "iana"))]
    MobilityTicket(&'a [u8]),

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectionId(u32),

    Other { typ: u16, val: &'a [u8] },
}

#[cfg(any(feature = "rfc8489", feature = "iana"))]
#[derive(Copy, Clone)]
#[cfg(any(feature = "rfc8489", feature = "iana"))]
pub enum PasswordAlgorithm<'a> {
    Other { typ: u16, params: &'a [u8] }
}

#[cfg(any(feature = "rfc8489", feature = "iana"))]
#[derive(Copy, Clone)]
#[cfg(any(feature = "rfc8489", feature = "iana"))]
struct PasswordAlgorithmIter<'a> { buf: &'a [u8]}

impl<'a> TryFrom<(RawAttr<'a>, &'a u128be)> for Attr<'a> {
    type Error = ();

    fn try_from(value: (RawAttr<'a>, &'a u128be)) -> Result<Self, Self::Error> {
        let (attr, tid) = value;

        if (attr.len.get() as usize + 3) & !3 != attr.val.len() { return Err(()); }

        fn parse_address(buf: &[u8]) -> Option<SocketAddr> {
            let addr_family = buf.get(0..2).map(u16be::from_slice)??.get();
            let port = buf.get(2..4).map(u16be::from_slice)??.get();

            if addr_family == 1 {
                let ip = buf.get(4..8).map(u32be::from_slice)??.get();
                return Some(SocketAddr::V4(ip, port));
            }
            if addr_family == 2 {
                let ip = buf.get(4..20).map(u128be::from_slice)??.get();
                return Some(SocketAddr::V6(ip, port));
            }
            return None;
        }

        fn parse_xor_address(buf: &[u8], tid: &u128be) -> Option<SocketAddr> {
            let addr_family = buf.get(0..2).map(u16be::from_slice)??.get();
            let port = buf.get(2..4).map(u16be::from_slice)??.get();

            if addr_family == 1 {
                let ip = buf.get(4..8).map(u32be::from_slice)??.get();
                let ip = ip ^ tid.as_slice().get(0..4).map(u32be::from_slice)??.get();
                return Some(SocketAddr::V4(ip, port));
            }
            if addr_family == 2 {
                let ip = buf.get(4..20).map(u128be::from_slice)??.get();
                let ip = ip ^ tid.get();
                return Some(SocketAddr::V6(ip, port));
            }
            return None;
        }

        fn parse_string(buf: &[u8]) -> Option<&str> {
            core::str::from_utf8(buf).ok()
        }

        fn parse_message_integrity(buf: &[u8]) -> Option<&[u8; 20]> {
            buf.get(0..20)?.try_into().ok()
        }

        fn parse_fingerprint(buf: &[u8]) -> Option<u32> {
            Some(buf.get(0..4).map(u32be::from_slice)??.get())
        }

        fn parse_error_code(buf: &[u8]) -> Option<(u16, &str)> {
            let class = *buf.get(2)? as u16 >> 5; // we only care about 3 MSB
            let num = *buf.get(3)? as u16;

            let code = class * 100 + num;

            let reason = buf.get(4..).map(|buf| core::str::from_utf8(buf).ok())??;
            Some((code, reason))
        }

        fn parse_unknown_attrs(buf: &[u8]) -> Option<&[u16be]> {
            if buf.len() % 2 != 0 { return None; }
            unsafe { Some(core::mem::transmute(buf)) }
        }

        fn parse_change_request(buf: &[u8]) -> Option<(bool, bool)> {
            let change_ip = buf.get(3).map(|b| b & 0x40 != 0)?;
            let change_port = buf.get(3).map(|b| b & 0x20 != 0)?;
            Some((change_ip, change_port))
        }

        fn parse<'a>(typ: u16, val: &'a [u8], tid: &'a u128be) -> Option<Attr<'a>> {
            Some(match typ {
                0x0001 => Attr::MappedAddress(parse_address(val)?),
                0x0002 => Attr::ResponseAddress(parse_address(val)?),
                0x0003 => {
                    let (change_ip, change_port) = parse_change_request(val)?;
                    Attr::ChangeRequest { change_ip, change_port }
                }
                0x0004 => Attr::SourceAddress(parse_address(val)?),
                0x0005 => Attr::ChangedAddress(parse_address(val)?),
                0x0006 => Attr::Username(parse_string(val)?),
                0x0007 => Attr::Password(parse_string(val)?),
                0x0008 => Attr::MessageIntegrity(parse_message_integrity(val)?),
                0x0009 => {
                    let (code, reason) = parse_error_code(val)?;
                    Attr::ErrorCode { code, reason }
                }
                0x000A => Attr::UnknownAttributes(parse_unknown_attrs(val)?),
                0x000B => Attr::ReflectedFrom(parse_address(val)?),
                0x0014 => Attr::Realm(parse_string(val)?),
                0x0015 => Attr::Nonce(parse_string(val)?),
                0x0020 => Attr::XorMappedAddress(parse_xor_address(val, tid)?),
                0x8022 => Attr::Software(parse_string(val)?),
                0x8023 => Attr::AlternateServer(parse_address(val)?),
                0x8028 => Attr::Fingerprint(parse_fingerprint(val)?),
                typ => Attr::Other { typ, val },
            })
        }

        parse(attr.typ.get(), attr.val.get(0..attr.len.get() as usize).ok_or(())?, tid).ok_or(())
    }
}

struct AttrIter<'a> {
    raw_iter: RawIter<'a>,
    tid: &'a u128be,
    attr: Attr<'a>,
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let raw_attr = self.raw_iter.next()?;
        self.attr = Attr::try_from((raw_attr, self.tid)).ok()?;
        Some(self.attr)
    }
}

pub struct RawMsg<'a> {
    pub typ: &'a u16be,
    pub len: &'a u16be,
    pub tid: &'a u128be,
    pub attrs: &'a [u8],
}

impl<'a> RawMsg<'a> {
    pub fn from(buf: &'a [u8]) -> Option<Self> {
        let len = buf.get(2..4).map(u16be::from_slice)??;
        Some(Self {
            typ: buf.get(0..2).map(u16be::from_slice)??,
            len: len,
            tid: buf.get(4..20).map(u128be::from_slice)??,
            attrs: buf.get(20..20 + len.get() as usize).or(buf.get(20..))?, // do not read over what is specified by length
        })
    }

    pub fn attrs_iter(&self) -> RawIter {
        RawIter { buf: self.attrs }
    }
}

pub struct RawAttr<'a> {
    pub typ: &'a u16be,
    pub len: &'a u16be,
    pub val: &'a [u8],
}

impl<'a> RawAttr<'a> {
    fn from(buf: &'a [u8]) -> Option<Self> {
        let len = buf.get(2..4).map(u16be::from_slice)??;
        Some(Self {
            typ: buf.get(0..2).map(u16be::from_slice)??,
            len: len,
            val: buf.get(4..4 + (len.get() as usize + 3) & !3).or(buf.get(4..))?, // get val up to and including padding bytes
        })
    }
}

pub struct RawIter<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for RawIter<'a> {
    type Item = RawAttr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() { return None; }
        if let Some(attr) = RawAttr::from(self.buf) {
            self.buf = self.buf.get(4 + attr.val.len()..)?;
            Some(attr)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: [u8; 28] = [
        0x00, 0x01,                     // type: Binding Request
        0x00, 0x08,                     // length: 8 (header does not count)
        0x21, 0x12, 0xA4, 0x42,         // magic cookie
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,         // transaction id (16 bytes total incl. magic cookie)
        0x00, 0x03,                     // type: ChangeRequest
        0x00, 0x04,                     // length: 4 (only value bytes count)
        0x00, 0x00, 0x00, 0x40 | 0x20,  // change both ip and port
    ];

    #[test]
    fn read_raw() {
        let msg = RawMsg::from(&MSG).unwrap();

        assert_eq!(0x0001, msg.typ.get());
        assert_eq!(0x0008, msg.len.get());
        assert_eq!(0x2112A442_00000000_00000000_00000001, msg.tid.get());
        assert_eq!(&MSG[20..28], msg.attrs);
        assert_eq!(1, msg.attrs_iter().count());

        let attr = msg.attrs_iter().next().unwrap();

        assert_eq!(0x0003, attr.typ.get());
        assert_eq!(0x0004, attr.len.get());
        assert_eq!(&MSG[24..28], attr.val);
    }

    #[test]
    fn read() {
        let msg = Msg::from(&MSG).unwrap();

        if let MsgType::BindingRequest = msg.typ() {} else { assert!(false); }

        assert_eq!(0x2112A442_00000000_00000000_00000001, msg.tid());

        assert_eq!(1, msg.attrs_iter().count());

        let attr = msg.attrs_iter().next().unwrap();

        if let Attr::ChangeRequest { change_ip, change_port } = attr {
            assert_eq!(true, change_ip);
            assert_eq!(true, change_port);
        } else {
            assert!(false);
        }
    }
}
