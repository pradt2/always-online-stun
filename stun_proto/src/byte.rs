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
    #[cfg(any(rfc3489, rfc5349, rfc8489, iana))]
    BindingRequest,

    #[cfg(any(rfc3489, rfc5349, rfc8489, iana))]
    BindingResponse,

    #[cfg(any(rfc5349, rfc8489, iana))]
    BindingIndication,

    #[cfg(any(rfc3489, rfc5349, rfc8489, iana))]
    BindingErrorResponse,

    #[cfg(rfc3489)]
    SharedSecretRequest,

    #[cfg(rfc3489)]
    SharedSecretResponse,

    #[cfg(rfc3489)]
    SharedSecretErrorResponse,

    #[cfg(any(rfc5766, rfc8656, iana))]
    AllocateRequest,

    #[cfg(any(rfc5766, rfc8656, iana))]
    AllocateResponse,

    #[cfg(any(rfc5766, rfc8656, iana))]
    AllocateErrorResponse,

    #[cfg(any(rfc5766, rfc8656, iana))]
    RefreshRequest,

    #[cfg(any(rfc5766, rfc8656, iana))]
    RefreshResponse,

    #[cfg(any(rfc5766, rfc8656, iana))]
    RefreshErrorResponse,

    #[cfg(any(rfc5766, rfc8656, iana))]
    SendIndication,

    #[cfg(any(rfc5766, rfc8656, iana))]
    DataIndication,

    #[cfg(any(rfc5766, rfc8656, iana))]
    CreatePermissionRequest,

    #[cfg(any(rfc5766, rfc8656, iana))]
    CreatePermissionResponse,

    #[cfg(any(rfc5766, rfc8656, iana))]
    CreatePermissionErrorResponse,

    #[cfg(any(rfc5766, rfc8656, iana))]
    ChannelBindRequest,

    #[cfg(any(rfc5766, rfc8656, iana))]
    ChannelBindResponse,

    #[cfg(any(rfc5766, rfc8656, iana))]
    ChannelBindErrorResponse,

    #[cfg(any(rfc6062, iana))]
    ConnectRequest,

    #[cfg(any(rfc6062, iana))]
    ConnectResponse,

    #[cfg(any(rfc6062, iana))]
    ConnectErrorResponse,

    #[cfg(any(rfc6062, iana))]
    ConnectionBindRequest,

    #[cfg(any(rfc6062, iana))]
    ConnectionBindResponse,

    #[cfg(any(rfc6062, iana))]
    ConnectionBindErrorResponse,

    #[cfg(any(rfc6062, iana))]
    ConnectionAttemptIndication,

    #[cfg(iana)]
    GooglePing,

    Other(u16),
}

impl From<u16> for MsgType {
    fn from(val: u16) -> Self {
        match val {
            #[cfg(any(rfc3489, rfc5349, rfc8489, iana))]
            0x0001 => MsgType::BindingRequest,

            #[cfg(any(rfc3489, rfc5349, rfc8489, iana))]
            0x0011 => MsgType::BindingResponse,

            #[cfg(any(rfc5349, rfc8489, iana))]
            0x0101 => MsgType::BindingIndication,

            #[cfg(any(rfc3489, rfc5349, rfc8489, iana))]
            0x0111 => MsgType::BindingErrorResponse,

            #[cfg(rfc3489)]
            0x0002 => MsgType::SharedSecretRequest,

            #[cfg(rfc3489)]
            0x0102 => MsgType::SharedSecretResponse,

            #[cfg(rfc3489)]
            0x0112 => MsgType::SharedSecretErrorResponse,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::AllocateRequest,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::AllocateResponse,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::AllocateErrorResponse,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::RefreshRequest,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::RefreshResponse,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::RefreshErrorResponse,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::SendIndication,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::DataIndication,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::CreatePermissionRequest,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::CreatePermissionResponse,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::CreatePermissionErrorResponse,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::ChannelBindRequest,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::ChannelBindResponse,

            #[cfg(any(rfc5766, rfc8656, iana))]
            0x0000 => MsgType::ChannelBindErrorResponse,

            #[cfg(any(rfc6062, iana))]
            0x0000 => MsgType::ConnectRequest,

            #[cfg(any(rfc6062, iana))]
            0x0000 => MsgType::ConnectResponse,

            #[cfg(any(rfc6062, iana))]
            0x0000 => MsgType::ConnectErrorResponse,

            #[cfg(any(rfc6062, iana))]
            0x0000 => MsgType::ConnectionBindRequest,

            #[cfg(any(rfc6062, iana))]
            0x0000 => MsgType::ConnectionBindResponse,

            #[cfg(any(rfc6062, iana))]
            0x0000 => MsgType::ConnectionBindErrorResponse,

            #[cfg(any(rfc6062, iana))]
            0x0000 => MsgType::ConnectionAttemptIndication,

            #[cfg(iana)]
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
    #[cfg(any(rfc3489, rfc5389, rfc8489, iana))]
    MappedAddress(SocketAddr),

    #[cfg(rfc3489)]
    ResponseAddress(SocketAddr),

    #[cfg(any(rfc3489, rfc5780, iana))]
    ChangeRequest { change_ip: bool, change_port: bool },

    #[cfg(rfc3489)]
    SourceAddress(SocketAddr),

    #[cfg(rfc3489)]
    ChangedAddress(SocketAddr),

    #[cfg(any(rfc3489, rfc5389, rfc8489, iana))]
    Username(&'a str),

    #[cfg(rfc3489)]
    Password(&'a str),

    #[cfg(any(rfc5389, rfc8489, iana))]
    Realm(&'a str),

    #[cfg(any(rfc5389, rfc8489, iana))]
    Nonce(&'a str),

    #[cfg(any(rfc3489, rfc5389, rfc8489, iana))]
    MessageIntegrity(&'a [u8; 20]),

    #[cfg(any(rfc8489, iana))]
    MessageIntegritySha256(&'a [u8; 32]),

    #[cfg(any(rfc5389, rfc8489, iana))]
    Fingerprint(u32),

    #[cfg(any(rfc5389, rfc8489, iana))]
    XorMappedAddress(SocketAddr),

    #[cfg(any(rfc5389, rfc8489, iana))]
    Software(&'a str),

    #[cfg(any(rfc5389, rfc8489, iana))]
    AlternateServer(SocketAddr),

    #[cfg(any(rfc3489, rfc5389, rfc8489, iana))]
    ErrorCode { code: u16, reason: &'a str },

    #[cfg(any(rfc3489, rfc5389, rfc8489, iana))]
    UnknownAttributes(&'a [u16be]),

    #[cfg(rfc3489)]
    ReflectedFrom(SocketAddr),

    #[cfg(any(rfc5425, rfc8445, iana))]
    Priority(u32),

    #[cfg(any(rfc5425, rfc8445, iana))]
    UseCandidate,

    #[cfg(any(rfc5425, rfc8445, iana))]
    IceControlled(u64),

    #[cfg(any(rfc5425, rfc8445, iana))]
    IceControlling(u64),

    #[cfg(any(rfc5780, iana))]
    ResponseOrigin(SocketAddr),

    #[cfg(any(rfc5780, iana))]
    OtherAddress(SocketAddr),

    #[cfg(any(rfc5780, iana))]
    ResponsePort(u16),

    #[cfg(any(rfc5780, iana))]
    Padding(&'a [u8]),

    #[cfg(any(rfc5780, iana))]
    CacheTimeout(u32),

    #[cfg(any(rfc5766, rfc8656, iana))]
    ChannelNumber(u16),

    #[cfg(any(rfc5766, rfc8656, iana))]
    Lifetime(u32),

    #[cfg(any(rfc5766, rfc8656, iana))]
    XorPeerAddress(SocketAddr),

    #[cfg(any(rfc5766, rfc8656, iana))]
    Data(&'a [u8]),

    #[cfg(any(rfc5766, rfc8656, iana))]
    XorRelayedAddress(SocketAddr),

    #[cfg(any(rfc5766, rfc8656, iana))]
    EvenPort(bool),

    #[cfg(any(rfc5766, rfc8656, iana))]
    RequestedTransport(u8), // can be narrowed down

    #[cfg(any(rfc5766, rfc8656, iana))]
    DontFragment,

    #[cfg(any(rfc5766, rfc8656, iana))]
    ReservationToken(u64),

    #[cfg(any(rfc8656, iana))]
    RequestedAddressFamily(u8), // can be narrowed down

    #[cfg(any(rfc8656, iana))]
    AdditionalAddressFamily(u8), // can be narrowed down

    #[cfg(any(rfc8656, iana))]
    AddressErrorCode { family: u8, code: u16, reason: &'a str }, // family and code can be narrowed down

    #[cfg(any(rfc8656, iana))]
    Icmp { typ: u8, code: u8, data: u32 }, // maybe can be narrowed down

    #[cfg(any(rfc8489, iana))]
    Userhash(&'a [u8; 32]),

    #[cfg(any(rfc8489, iana))]
    PasswordAlgorithm(PasswordAlgorithm<'a>),

    #[cfg(any(rfc8489, iana))]
    PasswordAlgorithms(PasswordAlgorithmIter<'a>),

    #[cfg(any(rfc8489, iana))]
    AlternateDomain(&'a str),

    #[cfg(any(rfc6679, iana))]
    EcnCheck{ valid: bool, val: u8 },

    #[cfg(any(rfc7635, iana))]
    ThirdPartyAuthorisation(&'a str),

    #[cfg(any(rfc7635, iana))]
    AccessToken{ nonce: &'a [u8], mac: &'a [u8], timestamp: u64, lifetime: u32 },

    #[cfg(any(rfc8016, iana))]
    MobilityTicket(&'a [u8]),

    #[cfg(any(rfc6062, iana))]
    ConnectionId(u32),

    Other { typ: u16, val: & 'a [u8] },
}

#[cfg(any(rfc8489, iana))]
pub enum PasswordAlgorithm<'a> {
    Other { typ: u16, params: &'a [u8] }
}

#[cfg(any(rfc8489, iana))]
struct PasswordAlgorithmIter<'a> {

}

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