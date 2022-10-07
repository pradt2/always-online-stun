use core::time::Duration;

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

    pub fn typ(&self) -> Option<MsgType> {
        self.reader.typ().map(u16::of_be).map(MsgType::from)
    }

    pub fn cookie(&self) -> Option<u32> {
        self.reader.tid()?.get(0..4).map(carve)?.map(u32::of_be)
    }

    pub fn tid(&self) -> Option<u128> {
        self.reader.tid().map(u128::of_be)
    }

    pub fn attrs_iter(&self) -> Option<AttrIter> {
        Some(AttrIter { raw_iter: self.reader.attrs_iter(), tid: self.reader.tid()? })
    }
}

pub enum MsgType {
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

    Other(u16),
}

impl From<u16> for MsgType {
    fn from(val: u16) -> Self {
        match val {
            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            0x0001 => MsgType::BindingRequest,

            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            0x0101 => MsgType::BindingResponse,

            #[cfg(any(feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            0x0011 => MsgType::BindingIndication,

            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            0x0111 => MsgType::BindingErrorResponse,

            #[cfg(feature = "rfc3489")]
            0x0002 => MsgType::SharedSecretRequest,

            #[cfg(feature = "rfc3489")]
            0x0102 => MsgType::SharedSecretResponse,

            #[cfg(feature = "rfc3489")]
            0x0112 => MsgType::SharedSecretErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0003 => MsgType::AllocateRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0103 => MsgType::AllocateResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0113 => MsgType::AllocateErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0004 => MsgType::RefreshRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0104 => MsgType::RefreshResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0114 => MsgType::RefreshErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0016 => MsgType::SendIndication,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0017 => MsgType::DataIndication,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0008 => MsgType::CreatePermissionRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0108 => MsgType::CreatePermissionResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0118 => MsgType::CreatePermissionErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0009 => MsgType::ChannelBindRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0109 => MsgType::ChannelBindResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0119 => MsgType::ChannelBindErrorResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x000A => MsgType::ConnectRequest,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x010A => MsgType::ConnectResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x011A => MsgType::ConnectErrorResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x000B => MsgType::ConnectionBindRequest,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x010B => MsgType::ConnectionBindResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x011B => MsgType::ConnectionBindErrorResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x001C => MsgType::ConnectionAttemptIndication,

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
pub enum AddressFamily {
    IPv4,
    IPv6,
    Other(u8),
}

impl AddressFamily {
    fn from(fam: &u8) -> Self {
        match fam {
            1 => Self::IPv4,
            2 => Self::IPv6,
            fam => Self::Other(*fam),
        }
    }
}

#[derive(Copy, Clone)]
pub enum TransportProtocol {
    UDP,
    Other(u8),
}

impl TransportProtocol {
    fn from(proto: &u8) -> Self {
        match proto {
            17 => Self::UDP,
            proto => Self::Other(*proto),
        }
    }
}

#[derive(Copy, Clone)]
pub enum ErrorCode {
    Other(u16),
}

impl ErrorCode {
    fn from(buf: &[u8; 2]) -> Self {
        let class = buf[0] as u16 >> 5; // we only care about 3 MSB
        let num = buf[1] as u16;

        let code = class * 100 + num;

        match code {
            code => Self::Other(code),
        }
    }
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
    ErrorCode { code: ErrorCode, reason: &'a str },

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    UnknownAttributes(UnknownAttrIter<'a>),

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
    CacheTimeout(Duration),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    ChannelNumber(u16),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    Lifetime(Duration),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    XorPeerAddress(SocketAddr),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    Data(&'a [u8]),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    XorRelayedAddress(SocketAddr),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    EvenPort(bool),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    RequestedTransport(TransportProtocol),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    DontFragment,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    ReservationToken(u64),

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    RequestedAddressFamily(AddressFamily),

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    AdditionalAddressFamily(AddressFamily),

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    AddressErrorCode { family: AddressFamily, code: ErrorCode, reason: &'a str },

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
    AccessToken { nonce: &'a [u8], mac: &'a [u8], timestamp: Duration, lifetime: Duration },

    #[cfg(any(feature = "rfc8016", feature = "iana"))]
    MobilityTicket(&'a [u8]),

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectionId(u32),

    #[cfg(any(feature = "rfc7982", feature = "iana"))]
    TransactionTransmitCounter { req: u8, res: u8 },

    Other { typ: u16, val: &'a [u8] },
}

impl<'a> Attr<'a> {
    fn from(raw: RawAttr<'a>, tid: &'a [u8; 16]) -> Option<Attr<'a>> {
        let typ = raw.typ().map(u16::of_be)?;
        let len = raw.len().map(u16::of_be)?;
        let val = raw.val()
            .map(|val| val.get(0..len as usize))
            .flatten()?;

        Some(match typ {
            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0001 => Self::MappedAddress(Self::parse_address(val)?),

            #[cfg(feature = "rfc3489")]
            0x0002 => Self::ResponseAddress(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc3489", feature = "rfc5780", feature = "iana"))]
            0x0003 => {
                let (change_ip, change_port) = Self::parse_change_request(val)?;
                Self::ChangeRequest { change_ip, change_port }
            }

            #[cfg(feature = "rfc3489")]
            0x0004 => Self::SourceAddress(Self::parse_address(val)?),

            #[cfg(feature = "rfc3489")]
            0x0005 => Self::ChangedAddress(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0006 => Self::Username(Self::parse_string(val)?),

            #[cfg(feature = "rfc3489")]
            0x0007 => Self::Password(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0008 => Self::MessageIntegrity(Self::parse_message_integrity(val)?),

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0009 => {
                let (code, reason) = Self::parse_error_code(val)?;
                Self::ErrorCode { code, reason }
            }

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x000A => Self::UnknownAttributes(UnknownAttrIter { buf: val }),

            #[cfg(feature = "rfc3489")]
            0x000B => Self::ReflectedFrom(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x000C => Self::ChannelNumber(val.get(0..2).map(carve)?.map(u16::of_be)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x000D => Self::Lifetime(Duration::from_secs(val.get(0..4).map(carve)?.map(u32::of_be)? as u64)),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0012 => Self::XorPeerAddress(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0013 => Self::Data(val),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0016 => Self::XorRelayedAddress(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            0x0017 => Self::RequestedAddressFamily(val.get(0).map(AddressFamily::from)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0018 => Self::EvenPort(val.get(0).map(|val| val & 1 == 1)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0019 => Self::RequestedTransport(val.get(0).map(TransportProtocol::from)?),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0014 => Self::Realm(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0015 => Self::Nonce(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x001A => Self::DontFragment,

            #[cfg(any(feature = "rfc7635", feature = "iana"))]
            0x001B => {
                let (nonce, mac, timestamp, lifetime) = Self::parse_access_token(val)?;
                Self::AccessToken {
                    nonce,
                    mac,
                    timestamp,
                    lifetime,
                }
            }

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            0x001C => Self::MessageIntegritySha256(val.get(0..32).map(carve)??),

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            0x001D => Self::PasswordAlgorithm(Self::parse_password_algorithm(val)?),

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            0x001E => Self::Userhash(val.get(0..32).map(carve)??),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0020 => Self::XorMappedAddress(Self::parse_xor_address(val, tid)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0022 => Self::ReservationToken(val.get(0..8).map(carve)?.map(u64::of_be)?),

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            0x0024 => Self::Priority(val.get(0..4).map(carve)?.map(u32::of_be)?),

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            0x0025 => Self::UseCandidate,

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            0x0026 => Self::Padding(val),

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            0x0027 => Self::ResponsePort(val.get(0..2).map(carve)?.map(u16::of_be)?),

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            0x002A => Self::ConnectionId(val.get(0..4).map(carve)?.map(u32::of_be)?),

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            0x8000 => Self::AdditionalAddressFamily(val.get(0).map(AddressFamily::from)?),

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            0x8001 => {
                let (family, code, reason) = Self::parse_address_error_code(val)?;
                Self::AddressErrorCode {
                    family,
                    code,
                    reason,
                }
            }

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            0x8002 => {
                Self::PasswordAlgorithms(PasswordAlgorithmIter {
                    raw_iter: RawIter {
                        buf: val
                    }
                })
            }

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            0x8003 => Self::AlternateDomain(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            0x8004 => Self::Icmp {
                typ: *val.get(2)?,
                code: *val.get(3)?,
                data: val.get(4..8).map(carve)?.map(u32::of_be)?,
            },

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x8022 => Self::Software(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x8023 => Self::AlternateServer(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc7982", feature = "iana"))]
            0x8025 => Self::TransactionTransmitCounter {
                req: *val.get(2)?,
                res: *val.get(3)?,
            },

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            0x8027 => {
                let timeout = val.get(0..4)
                    .map(carve)?
                    .map(u32::of_be)
                    .map(|val| val as u64)
                    .map(Duration::from_secs)?;

                Self::CacheTimeout(timeout)
            }

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x8028 => Self::Fingerprint(Self::parse_fingerprint(val)?),

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            0x8029 => Self::IceControlled(val.get(0..8).map(carve)?.map(u64::of_be)?),

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            0x802A => Self::IceControlling(val.get(0..8).map(carve)?.map(u64::of_be)?),

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            0x802B => Self::ResponseOrigin(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            0x802C => Self::OtherAddress(Self::parse_address(val)?),

            #[cfg(any(feature = "rfc6679", feature = "iana"))]
            0x802D => Self::EcnCheck {
                valid: val.get(3).map(|val| val & 128 != 0)?,
                val: val.get(3).map(|val| (val & 96) >> 5)?,
            },

            #[cfg(any(feature = "rfc7635", feature = "iana"))]
            0x802E => Self::ThirdPartyAuthorisation(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc8016", feature = "iana"))]
            0x8030 => Self::MobilityTicket(val),

            typ => Self::Other { typ, val },
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

        let port_mask = tid.get(0..2)
            .map(carve)?
            .map(u16::of_be)?;

        let port = buf.get(2..4)
            .map(carve)?
            .map(u16::of_be)
            .map(|port| port ^ port_mask)?;

        if addr_family == 1 {
            let cookie = tid.get(0..4)
                .map(carve)?
                .map(u32::of_be)?;

            let ip = buf.get(4..8)
                .map(carve)?
                .map(u32::of_be)
                .map(|ip| ip ^ cookie)
                .map(u32::to_be_bytes)?;

            Some(SocketAddr::V4(ip, port))
        } else if addr_family == 2 {
            let tid: u128 = tid.to_be();

            let ip = buf.get(4..20)
                .map(carve)?
                .map(u128::of_be)
                .map(|ip| ip ^ tid)
                .map(u128::to_be_bytes)?;

            Some(SocketAddr::V6(ip, port))
        } else { None }
    }

    fn parse_string(buf: &[u8]) -> Option<&str> {
        core::str::from_utf8(buf).ok()
    }

    fn parse_message_integrity(buf: &[u8]) -> Option<&[u8; 20]> {
        buf.get(0..20)?
            .try_into()
            .ok()
    }

    fn parse_fingerprint(buf: &[u8]) -> Option<u32> {
        buf.get(0..4)
            .map(carve)?
            .map(u32::of_be)
    }

    fn parse_error_code(buf: &[u8]) -> Option<(ErrorCode, &str)> {
        let code = ErrorCode::from(buf.get(2..4).map(carve)??);
        let reason = buf.get(4..).map(Self::parse_string)??;
        Some((code, reason))
    }

    fn parse_change_request(buf: &[u8]) -> Option<(bool, bool)> {
        let change_ip = buf.get(3).map(|b| b & 0x40 != 0)?;
        let change_port = buf.get(3).map(|b| b & 0x20 != 0)?;
        Some((change_ip, change_port))
    }

    fn parse_access_token(buf: &[u8]) -> Option<(&[u8], &[u8], Duration, Duration)> {
        let mut cursor = 0usize;

        let nonce_len = buf.get(cursor..cursor + 2)
            .map(carve)?
            .map(u16::of_be)? as usize;

        cursor += 2;

        let nonce = buf.get(cursor..cursor + nonce_len)?;

        cursor += nonce_len;

        let mac_len = buf.get(cursor..cursor + 2)
            .map(carve)?
            .map(u16::of_be)? as usize;

        cursor += 2;

        let mac = buf.get(cursor..cursor + mac_len)?;

        cursor += mac_len;

        let timestamp_bytes: &[u8; 8] = buf.get(cursor..cursor + 8)
            .map(carve)??;

        cursor += 8;

        let timestamp_seconds = timestamp_bytes.get(0..4)
            .map(carve)?
            .map(u32::of_be)
            .map(|val| (val as u64) << 16)? | timestamp_bytes.get(4..6)
            .map(carve)?
            .map(u16::of_be)? as u64;

        let timestamp_frac = timestamp_bytes.get(6..8)
            .map(carve)?
            .map(u16::of_be)? as f64 / 64000_f64;

        let timestamp = Duration::from_secs_f64(timestamp_seconds as f64 + timestamp_frac);

        let lifetime_secs = buf.get(cursor..cursor + 4)
            .map(carve)?
            .map(u32::of_be)?;

        let lifetime = Duration::from_secs(lifetime_secs as u64);

        Some((nonce, mac, timestamp, lifetime))
    }

    fn parse_password_algorithm(buf: &[u8]) -> Option<PasswordAlgorithm> {
        PasswordAlgorithmIter { raw_iter: RawIter { buf } }.next()
    }

    fn parse_address_error_code(buf: &'a [u8]) -> Option<(AddressFamily, ErrorCode, &'a str)> {
        let address_family = buf.get(0)
            .map(AddressFamily::from)?;

        let error_code = buf.get(2..4)
            .map(carve)?
            .map(ErrorCode::from)?;

        let reason = Self::parse_string(buf.get(4..)?)?;

        Some((address_family, error_code, reason))
    }
}

#[derive(Copy, Clone)]
struct UnknownAttrIter<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for UnknownAttrIter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        let attr = self.buf.get(0..2)
            .map(carve)?
            .map(u16::of_be)?;

        self.buf = self.buf.get(2..)?;
        Some(attr)
    }
}

#[cfg(any(feature = "rfc8489", feature = "iana"))]
#[derive(Copy, Clone)]
#[cfg(any(feature = "rfc8489", feature = "iana"))]
pub enum PasswordAlgorithm<'a> {
    Md5,
    Sha256,
    Other { typ: u16, params: &'a [u8] },
}

impl<'a> PasswordAlgorithm<'a> {
    fn from(typ: u16, params: &'a [u8]) -> Self {
        match typ {
            1 => PasswordAlgorithm::Md5,
            2 => PasswordAlgorithm::Sha256,
            typ => PasswordAlgorithm::Other { typ, params },
        }
    }
}

#[cfg(any(feature = "rfc8489", feature = "iana"))]
#[derive(Copy, Clone)]
#[cfg(any(feature = "rfc8489", feature = "iana"))]
struct PasswordAlgorithmIter<'a> {
    raw_iter: RawIter<'a>,
}

impl<'a> Iterator for PasswordAlgorithmIter<'a> {
    type Item = PasswordAlgorithm<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let attr = self.raw_iter.next()?;
        let typ = attr.typ().map(u16::of_be)?;
        let len = attr.len().map(u16::of_be)?;
        let params = attr.val()?.get(0..len as usize)?;
        Some(PasswordAlgorithm::from(typ, params))
    }
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
        self.len()
            .map(u16::of_be)
            .map(|len| len + 3 & !3)
            .map(|len| self.buf.get(4..4 + len as usize))
            .flatten()
            .or(self.buf.get(4..))
    }
}

#[derive(Copy, Clone)]
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

    #[test]
    fn read_raw() {
        let msg = RawMsg::from(&MSG);

        assert_eq!(&MSG[0..2], msg.typ().unwrap());
        assert_eq!(&MSG[2..4], msg.len().unwrap());
        assert_eq!(&MSG[4..20], msg.tid().unwrap());
        assert_eq!(&MSG[20..28], msg.attrs().unwrap());
        assert_eq!(1, msg.attrs_iter().count());

        let attr = msg.attrs_iter().next().unwrap();

        assert_eq!(&MSG[20..22], attr.typ().unwrap());
        assert_eq!(&MSG[22..24], attr.len().unwrap());
        assert_eq!(&MSG[24..28], attr.val().unwrap());
    }

    #[test]
    fn read() {
        let msg = Msg::from(&MSG);

        if let MsgType::BindingRequest = msg.typ().unwrap() {} else { assert!(false); }

        assert_eq!(0x2112A442_00000000_00000000_00000001, msg.tid().unwrap());

        assert_eq!(1, msg.attrs_iter().unwrap().count());

        let attr = msg.attrs_iter().unwrap().next().unwrap();

        if let Attr::ChangeRequest { change_ip, change_port } = attr {
            assert_eq!(true, change_ip);
            assert_eq!(true, change_port);
        } else {
            assert!(false);
        }
    }
}
