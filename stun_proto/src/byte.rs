use crate::endian::{u16be};

use endianeer::prelude::*;

pub struct Msg<'a> {
    reader: RawMsg<'a>,
}

impl<'a> Msg<'a> {
    fn from(buf: &'a [u8]) -> Self {
        Self {
            reader: RawMsg::from(buf)
        }
    }

    fn typ(&self) -> Option<MsgType> {
        Some(MsgType::from(self.reader.typ().map(u16::of_be)?))
    }

    fn tid(&self) -> Option<u128> {
        Some(self.reader.tid().map(u128::of_be)?)
    }

    fn attrs_iter(&self) -> Option<AttrIter> {
        Some(AttrIter { raw_iter: self.reader.attrs_iter(), tid: self.reader.tid()? })
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
    V4([u8; 4], u16),
    V6([u8; 16], u16),
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

impl<'a> Attr<'a> {

    fn from(raw: RawAttr<'a>, tid: &'a [u8; 16]) -> Option<Attr<'a>> {
        let typ = raw.typ().map(u16::of_be)?;
        let len = raw.len().map(u16::of_be)?;
        let val = raw.val()
            .map(|val| val.get(0..len as usize))
            .flatten()?;

        Self::parse(typ, val, tid)
    }

    fn parse(typ: u16, val: &'a [u8], tid: &'a [u8; 16]) -> Option<Attr<'a>> {
        Some(match typ {
            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0001 => Attr::MappedAddress(Self::parse_address(val)?),

            #[cfg(feature = "rfc3489")]
            0x0002 => Attr::ResponseAddress(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc3489", feature = "rfc5780", feature = "iana"))]
            0x0003 => {
                let (change_ip, change_port) = Self::parse_change_request(val)?;
                Attr::ChangeRequest { change_ip, change_port }
            }

            #[cfg(feature = "rfc3489")]
            0x0004 => Attr::SourceAddress(Self::parse_address(val)?),

            #[cfg(feature = "rfc3489")]
            0x0005 => Attr::ChangedAddress(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0006 => Attr::Username(Self::parse_string(val)?),

            #[cfg(feature = "rfc3489")]
            0x0007 => Attr::Password(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0008 => Attr::MessageIntegrity(Self::parse_message_integrity(val)?),

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0009 => {
                let (code, reason) = Self::parse_error_code(val)?;
                Attr::ErrorCode { code, reason }
            }

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x000A => Attr::UnknownAttributes(Self::parse_unknown_attrs(val)?),

            #[cfg(feature = "rfc3489")]
            0x000B => Attr::ReflectedFrom(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x000C => Attr::ChannelNumber(0), // TODO add parsing

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x000D => Attr::Lifetime(0), // TODO add parsing

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0012 => Attr::XorPeerAddress(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0013 => Attr::Data(val),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0016 => Attr::XorRelayedAddress(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            0x0017 => Attr::RequestedAddressFamily(0), // TODO add parsing

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0018 => Attr::EvenPort(false), // TODO add parsing

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0019 => Attr::RequestedTransport(0), // TODO add parsing

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0014 => Attr::Realm(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0015 => Attr::Nonce(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x001A => Attr::DontFragment,

            #[cfg(any(feature = "rfc7635", feature = "iana"))]
            0x001B => Attr::AccessToken {
                nonce: &[],
                mac: &[],
                timestamp: 0,
                lifetime: 0, // TODO add parsing
            },

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            0x001C => Attr::MessageIntegritySha256(&[0u8; 32]), // TODO add parsing

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            0x001D => Attr::PasswordAlgorithm(PasswordAlgorithm::Other { typ: 0, params: &[] }), // TODO add parsing

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            0x001E => Attr::Userhash(&[0u8; 32]), // TODO add parsing

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0020 => Attr::XorMappedAddress(Self::parse_xor_address(val, tid)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0022 => Attr::ReservationToken(0), // TODO add parsing

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            0x0024 => Attr::Priority(0), // TODO parsing

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            0x0025 => Attr::UseCandidate,

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            0x0026 => Attr::Padding(val),

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            0x0027 => Attr::ResponsePort(0), // TODO add padding

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x002A => Attr::ConnectionId(0), // TODO add parsing

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            0x8000 => Attr::AdditionalAddressFamily(0), // TODO add parsing

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            0x8001 => Attr::AddressErrorCode {
                family: 0,
                code: 0,
                reason: "", // TODO add parsing
            },

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            0x8002 => Attr::PasswordAlgorithms(PasswordAlgorithmIter { buf: val }),

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            0x8003 => Attr::AlternateDomain(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            0x8004 => Attr::Icmp {
                typ: 0,
                code: 0,
                data: 0, // TODO add parsing
            },

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x8022 => Attr::Software(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x8023 => Attr::AlternateServer(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            0x8027 => Attr::CacheTimeout(0), // TODO add padding

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x8028 => Attr::Fingerprint(Self::parse_fingerprint(val)?),

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            0x8029 => Attr::IceControlled(0), // TODO add parsing

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            0x802A => Attr::IceControlling(0), // TODO add parsing

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            0x802B => Attr::ResponseOrigin(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            0x802C => Attr::OtherAddress(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc6679", feature = "iana"))]
            0x802D => Attr::EcnCheck { valid: false, val: 0 }, // TODO add parsing

            #[cfg(any(feature = "rfc7635", feature = "iana"))]
            0x802E => Attr::ThirdPartyAuthorisation(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc8016", feature = "iana"))]
            0x8030 => Attr::MobilityTicket(val),

            typ => Attr::Other { typ, val },
        })
    }

    fn parse_address(buf: &[u8]) -> Option<SocketAddr> {
        let addr_family = buf.get(0..2)
            .map(carve)?
            .map(u16::of_be)?;

        let port = buf.get(2..4)
            .map(carve)?
            .map(u16::of_be)?;

        if addr_family == 1 {
            let ip = buf.get(4..8)
                .map(carve)??;

            return Some(SocketAddr::V4(*ip, port));
        }

        if addr_family == 2 {
            let ip = buf.get(4..20)
                .map(carve)??;

            return Some(SocketAddr::V6(*ip, port));
        }

        return None;
    }

    fn parse_xor_address(buf: &[u8], tid: &[u8; 16]) -> Option<SocketAddr> {
        let addr_family = buf.get(0..2)
            .map(carve)?
            .map(u16::of_be)?;

        let port = buf.get(2..4)
            .map(carve)?
            .map(u16::of_be)?; // TODO port is xor'ed as well

        if addr_family == 1 {
            let cookie = tid.get(0..4)
                .map(carve)?
                .map(u32::of_be)?;

            let ip = buf.get(4..8)
                .map(carve)?
                .map(u32::of_be)
                .map(|ip| ip ^ cookie)
                .map(u32::to_be_bytes)?;

            return Some(SocketAddr::V4(ip, port));
        }

        if addr_family == 2 {
            let tid: u128 = tid.to_be();

            let ip = buf.get(4..20)
                .map(carve)?
                .map(u128::of_be)
                .map(|ip| ip ^ tid)
                .map(u128::to_be_bytes)?;

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
        buf.get(0..4).map(carve)?.map(u32::of_be)
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
struct PasswordAlgorithmIter<'a> {
    buf: &'a [u8],
}

struct AttrIter<'a> {
    raw_iter: RawIter<'a>,
    tid: &'a [u8; 16],
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let raw_attr = self.raw_iter.next()?;
        Attr::from(raw_attr, self.tid)
    }
}

pub struct RawMsg<'a> {
    buf: &'a [u8],
}

impl<'a> RawMsg<'a> {
    fn from(buf: &'a [u8]) -> Self {
        let buf = buf.get(2..4)
            .map(carve)
            .flatten()
            .map(u16::of_be)
            .map(|len| 20 + len)
            .map(|len| buf.get(0..len as usize))
            .flatten()
            .unwrap_or(buf);
        Self { buf }
    }
    fn typ(&self) -> Option<&'a [u8; 2]> { self.buf.get(0..2).map(carve)? }
    fn len(&self) -> Option<&'a [u8; 2]> { self.buf.get(2..4).map(carve)? }
    fn tid(&self) -> Option<&'a [u8; 16]> { self.buf.get(4..20).map(carve)? }
    fn attrs(&self) -> Option<&'a [u8]> { self.buf.get(20..) }
    fn attrs_iter(&self) -> RawIter {
        RawIter { buf: self.attrs().unwrap_or(&[]) }
    }
}

pub struct RawAttr<'a> {
    buf: &'a [u8],
}

impl<'a> RawAttr<'a> {
    fn from(buf: &'a [u8]) -> Self { Self { buf } }
    fn typ(&self) -> Option<&'a [u8; 2]> { self.buf.get(0..2).map(carve)? }
    fn len(&self) -> Option<&'a [u8; 2]> { self.buf.get(2..4).map(carve)? }
    fn val(&self) -> Option<&'a [u8]> {
        let val = self.len()
            .map(u16::of_be)
            .map(|len| len + 3 & !3)
            .map(|len| self.buf.get(4..len as usize))
            .flatten()
            .unwrap_or(self.buf);
        Some(val)
    }
}

pub struct RawIter<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for RawIter<'a> {
    type Item = RawAttr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() { return None; }
        let attr = RawAttr::from(self.buf);
        self.buf = attr.val()
            .map(<[u8]>::len)
            .map(|len| 4 + len)
            .map(|len| self.buf.get(len..))
            .flatten()
            .unwrap_or(&[]);
        Some(attr)
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

    // #[test]
    // fn read_raw() {
    //     let msg = RawMsg::from(&MSG);
    //
    //     assert_eq!(0x0001, msg.typ.get());
    //     assert_eq!(0x0008, msg.len.get());
    //     assert_eq!(0x2112A442_00000000_00000000_00000001, msg.tid.get());
    //     assert_eq!(&MSG[20..28], msg.attrs);
    //     assert_eq!(1, msg.attrs_iter().count());
    //
    //     let attr = msg.attrs_iter().next().unwrap();
    //
    //     assert_eq!(0x0003, attr.typ.get());
    //     assert_eq!(0x0004, attr.len.get());
    //     assert_eq!(&MSG[24..28], attr.val);
    // }
    //
    // #[test]
    // fn read() {
    //     let msg = Msg::from(&MSG).unwrap();
    //
    //     if let MsgType::BindingRequest = msg.typ() {} else { assert!(false); }
    //
    //     assert_eq!(0x2112A442_00000000_00000000_00000001, msg.tid());
    //
    //     assert_eq!(1, msg.attrs_iter().count());
    //
    //     let attr = msg.attrs_iter().next().unwrap();
    //
    //     if let Attr::ChangeRequest { change_ip, change_port } = attr {
    //         assert_eq!(true, change_ip);
    //         assert_eq!(true, change_port);
    //     } else {
    //         assert!(false);
    //     }
    // }
}
