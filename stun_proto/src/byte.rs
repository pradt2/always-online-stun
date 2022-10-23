use endianeer::prelude::*;
use stun_bytes::{RawAttr, RawMsg, RawIter};

pub struct Msg<'a> {
    reader: RawMsg<'a>,
}

impl<'a> Msg<'a> {
    pub fn from(buf: &'a [u8]) -> Self {
        Self {
            reader: RawMsg::from(buf)
        }
    }

    pub fn typ(&self) -> Option<MsgType> {
        self.reader.typ()
            .map(MsgType::from)
    }

    #[cfg(any(feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
    pub fn cookie(&self) -> Option<u32> {
        self.reader.tid()?
            .get(0..4)
            .map(carve)?
            .map(u32::of_be)
    }

    pub fn tid(&self) -> Option<u128> {
        let tid = self.reader.tid()
            .map(u128::of_be);

        #[cfg(any(feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            let tid = tid.map(|val| val & ((1u128 << 96) - 1));

        tid
    }

    pub fn attrs_iter(&self) -> Option<AttrIter> {
        Some(AttrIter { raw_iter: self.reader.attr_iter(), tid: self.reader.tid()? })
    }
}

#[cfg(feature = "fmt")]
impl<'a> core::fmt::Debug for Msg<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Msg {\n")?;
        f.write_fmt(format_args!("  Type: {:?}\n", self.typ()))?;
        if cfg!(any(feature = "rfc5349", feature = "rfc8489", feature = "iana")) {
            f.write_fmt(format_args!("  Cookie: {:?}\n", self.cookie()))?;
        }
        f.write_fmt(format_args!("  Transaction Id: {:?}\n", self.tid()))?;
        f.write_fmt(format_args!("  Attributes: {:?}\n", self.attrs_iter()))?;
        f.write_str("}")?;
        Ok(())
    }
}

#[cfg_attr(feature = "fmt", derive(core::fmt::Debug))]
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

impl MsgType {
    fn from(val: &[u8; 2]) -> Self {
        use crate::consts::msg_type::*;

        let val = val.to_be();

        match val {
            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            BINDING_REQUEST => MsgType::BindingRequest,

            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            BINDING_RESPONSE => MsgType::BindingResponse,

            #[cfg(any(feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            BINDING_INDICATION => MsgType::BindingIndication,

            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            BINDING_ERROR_RESPONSE => MsgType::BindingErrorResponse,

            #[cfg(feature = "rfc3489")]
            SHARED_SECRET_REQUEST => MsgType::SharedSecretRequest,

            #[cfg(feature = "rfc3489")]
            SHARED_SECRET_RESPONSE => MsgType::SharedSecretResponse,

            #[cfg(feature = "rfc3489")]
            SHARED_SECRET_ERROR_RESPONSE => MsgType::SharedSecretErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            ALLOCATE_REQUEST => MsgType::AllocateRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            ALLOCATE_RESPONSE => MsgType::AllocateResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            ALLOCATE_ERROR_RESPONSE => MsgType::AllocateErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            REFRESH_REQUEST => MsgType::RefreshRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            REFRESH_RESPONSE => MsgType::RefreshResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            REFRESH_ERROR_RESPONSE => MsgType::RefreshErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            SEND_INDICATION => MsgType::SendIndication,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            DATA_INDICATION => MsgType::DataIndication,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            CREATE_PERMISSION_REQUEST => MsgType::CreatePermissionRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            CREATE_PERMISSION_RESPONSE => MsgType::CreatePermissionResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            CREATE_PERMISSION_ERROR_RESPONSE => MsgType::CreatePermissionErrorResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            CHANNEL_BIND_REQUEST => MsgType::ChannelBindRequest,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            CHANNEL_BIND_RESPONSE => MsgType::ChannelBindResponse,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            CHANNEL_BIND_ERROR_RESPONSE => MsgType::ChannelBindErrorResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            CONNECT_REQUEST => MsgType::ConnectRequest,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            CONNECT_RESPONSE => MsgType::ConnectResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            CONNECT_ERROR_RESPONSE => MsgType::ConnectErrorResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            CONNECTION_BIND_REQUEST => MsgType::ConnectionBindRequest,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            CONNECTION_BIND_RESPONSE => MsgType::ConnectionBindResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            CONNECTION_BIND_ERROR_RESPONSE => MsgType::ConnectionBindErrorResponse,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            CONNECTION_ATTEMPT_INDICATION => MsgType::ConnectionAttemptIndication,

            val => MsgType::Other(val),
        }
    }

    fn into_nums(&self) -> [u8; 2] {
        use crate::consts::msg_type::*;

        match self {
            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            Self::BindingRequest => BINDING_REQUEST,

            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            Self::BindingResponse => BINDING_RESPONSE,

            #[cfg(any(feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            Self::BindingIndication => BINDING_INDICATION,

            #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
            Self::BindingErrorResponse => BINDING_ERROR_RESPONSE,

            #[cfg(feature = "rfc3489")]
            Self::SharedSecretRequest => SHARED_SECRET_REQUEST,

            #[cfg(feature = "rfc3489")]
            Self::SharedSecretResponse => SHARED_SECRET_RESPONSE,

            #[cfg(feature = "rfc3489")]
            Self::SharedSecretErrorResponse => SHARED_SECRET_ERROR_RESPONSE,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::AllocateRequest => ALLOCATE_REQUEST,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::AllocateResponse => ALLOCATE_RESPONSE,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::AllocateErrorResponse => ALLOCATE_ERROR_RESPONSE,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::RefreshRequest => REFRESH_REQUEST,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::RefreshResponse => REFRESH_RESPONSE,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::RefreshErrorResponse => REFRESH_ERROR_RESPONSE,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::SendIndication => SEND_INDICATION,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::DataIndication => DATA_INDICATION,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::CreatePermissionRequest => CREATE_PERMISSION_REQUEST,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::CreatePermissionResponse => CREATE_PERMISSION_RESPONSE,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::CreatePermissionErrorResponse => CREATE_PERMISSION_ERROR_RESPONSE,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::ChannelBindRequest => CHANNEL_BIND_REQUEST,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::ChannelBindResponse => CHANNEL_BIND_RESPONSE,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::ChannelBindErrorResponse => CHANNEL_BIND_ERROR_RESPONSE,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            Self::ConnectRequest => CONNECT_REQUEST,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            Self::ConnectResponse => CONNECT_RESPONSE,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            Self::ConnectErrorResponse => CONNECT_ERROR_RESPONSE,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            Self::ConnectionBindRequest => CONNECTION_BIND_REQUEST,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            Self::ConnectionBindResponse => CONNECTION_BIND_RESPONSE,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            Self::ConnectionBindErrorResponse => CONNECTION_BIND_ERROR_RESPONSE,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            Self::ConnectionAttemptIndication => CONNECTION_ATTEMPT_INDICATION,

            Self::Other(val) => *val,
        }.to_be_bytes()
    }
}

#[cfg_attr(feature = "fmt", derive(core::fmt::Debug))]
#[derive(Copy, Clone)]
pub enum SocketAddr {
    V4([u8; 4], u16),
    V6([u8; 16], u16),
}

#[cfg_attr(feature = "fmt", derive(core::fmt::Debug))]
#[derive(Copy, Clone)]
pub enum AddressFamily {
    IPv4,
    IPv6,
    Other(u8),
}

impl AddressFamily {
    fn from_nums(fam: &u8) -> Self {
        match fam {
            1 => Self::IPv4,
            2 => Self::IPv6,
            fam => Self::Other(*fam),
        }
    }

    fn into_nums(&self) -> u8 {
        match self {
            Self::IPv4 => 1,
            Self::IPv6 => 2,
            Self::Other(fam) => *fam, // TODO move to consts
        }
    }
}

#[cfg_attr(feature = "fmt", derive(core::fmt::Debug))]
#[derive(Copy, Clone)]
pub enum TransportProtocol {
    UDP,
    Other(u8),
}

impl TransportProtocol {
    fn from_nums(proto: &u8) -> Self {
        match proto {
            17 => Self::UDP,
            proto => Self::Other(*proto),
        }
    }

    fn into_nums(&self) -> u8 {
        match self {
            Self::UDP => 17,
            Self::Other(proto) => *proto, // TODO move to consts
        }
    }
}

#[cfg_attr(feature = "fmt", derive(core::fmt::Debug))]
#[derive(Copy, Clone)]
pub enum ErrorCode {
    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    TryAlternate,

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    BadRequest,

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    Unauthorised,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    Forbidden,

    #[cfg(any(feature = "rfc8016", feature = "iana"))]
    MobilityForbidden,

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    UnknownAttribute,

    #[cfg(any(feature = "rfc3489"))]
    StaleCredentials,

    #[cfg(any(feature = "rfc3489"))]
    IntegrityCheckFailure,

    #[cfg(any(feature = "rfc3489"))]
    MissingUsername,

    #[cfg(any(feature = "rfc3489"))]
    UseTls,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    AllocationMismatch,

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    StaleNonce,

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    AddressFamilyNotSupported,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    WrongCredentials,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    UnsupportedTransportProtocol,

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    PeerAddressFamilyMismatch,

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectionAlreadyExists,

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectionTimeoutOrFailure,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    AllocationQuotaReached,

    #[cfg(any(feature = "rfc5245", feature = "rfc8445", feature = "iana"))]
    RoleConflict,

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    ServerError,

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    InsufficientCapacity,

    #[cfg(any(feature = "rfc3489"))]
    GlobalFailure,

    Other(u16),
}

impl ErrorCode {
    fn from_nums(buf: &[u8; 2]) -> Self {
        use crate::consts::error_code::*;

        let class = buf[0] as u16 >> 5; // we only care about 3 MSB
        let num = buf[1] as u16;

        let code = class * 100 + num;

        match code {
            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            TRY_ALTERNATE => Self::TryAlternate,

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            BAD_REQUEST => Self::BadRequest,

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            UNAUTHORISED => Self::Unauthorised,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            FORBIDDEN => Self::Forbidden,

            #[cfg(any(feature = "rfc8016", feature = "iana"))]
            MOBILITY_FORBIDDEN => Self::MobilityForbidden,

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            UNKNOWN_ATTRIBUTE => Self::UnknownAttribute,

            #[cfg(any(feature = "rfc3489"))]
            STALE_CREDENTIALS => Self::StaleCredentials,

            #[cfg(any(feature = "rfc3489"))]
            INTEGRITY_CHECK_FAILURE => Self::IntegrityCheckFailure,

            #[cfg(any(feature = "rfc3489"))]
            MISSING_USERNAME => Self::MissingUsername,

            #[cfg(any(feature = "rfc3489"))]
            USE_TLS => Self::UseTls,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            ALLOCATION_MISMATCH => Self::AllocationMismatch,

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            STALE_NONCE => Self::StaleNonce,

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            ADDRESS_FAMILY_NOT_SUPPORTED => Self::AddressFamilyNotSupported,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            WRONG_CREDENTIALS => Self::WrongCredentials,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            UNSUPPORTED_TRANSPORT_PROTOCOL => Self::UnsupportedTransportProtocol,

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            PEER_ADDRESS_FAMILY_MISMATCH => Self::PeerAddressFamilyMismatch,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            CONNECTION_ALREADY_EXISTS => Self::ConnectionAlreadyExists,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            CONNECTION_TIMEOUT_OR_FAILURE => Self::ConnectionTimeoutOrFailure,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            ALLOCATION_QUOTA_REACHED => Self::AllocationQuotaReached,

            #[cfg(any(feature = "rfc5245", feature = "rfc8445", feature = "iana"))]
            ROLE_CONFLICT => Self::RoleConflict,

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            SERVER_ERROR => Self::ServerError,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            INSUFFICIENT_CAPACITY => Self::InsufficientCapacity,

            #[cfg(any(feature = "rfc3489"))]
            GLOBAL_FAILURE => Self::GlobalFailure,

            code => Self::Other(code),
        }
    }

    pub fn into_nums(&self) -> [u8; 2] {
        use crate::consts::error_code::*;

        let code = match self {
            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::TryAlternate => TRY_ALTERNATE,

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::BadRequest => BAD_REQUEST,

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::Unauthorised => UNAUTHORISED,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::Forbidden => FORBIDDEN,

            #[cfg(any(feature = "rfc8016", feature = "iana"))]
            Self::MobilityForbidden => MOBILITY_FORBIDDEN,

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::UnknownAttribute => UNKNOWN_ATTRIBUTE,

            #[cfg(any(feature = "rfc3489"))]
            Self::StaleCredentials => STALE_CREDENTIALS,

            #[cfg(any(feature = "rfc3489"))]
            Self::IntegrityCheckFailure => INTEGRITY_CHECK_FAILURE,

            #[cfg(any(feature = "rfc3489"))]
            Self::MissingUsername => MISSING_USERNAME,

            #[cfg(any(feature = "rfc3489"))]
            Self::UseTls => USE_TLS,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::AllocationMismatch => ALLOCATION_MISMATCH,

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::StaleNonce => STALE_NONCE,

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            Self::AddressFamilyNotSupported => ADDRESS_FAMILY_NOT_SUPPORTED,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::WrongCredentials => WRONG_CREDENTIALS,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::UnsupportedTransportProtocol => UNSUPPORTED_TRANSPORT_PROTOCOL,

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            Self::PeerAddressFamilyMismatch => PEER_ADDRESS_FAMILY_MISMATCH,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            Self::ConnectionAlreadyExists => CONNECTION_ALREADY_EXISTS,

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            Self::ConnectionTimeoutOrFailure => CONNECTION_TIMEOUT_OR_FAILURE,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::AllocationQuotaReached => ALLOCATION_QUOTA_REACHED,

            #[cfg(any(feature = "rfc5245", feature = "rfc8445", feature = "iana"))]
            Self::RoleConflict => ROLE_CONFLICT,

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::ServerError => SERVER_ERROR,

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::InsufficientCapacity => INSUFFICIENT_CAPACITY,

            #[cfg(any(feature = "rfc3489"))]
            Self::GlobalFailure => GLOBAL_FAILURE,

            Self::Other(code) => *code,
        };

        let code_100s = code / 100;
        [(code_100s as u8) << 5, (code - code_100s) as u8]
    }
}

#[cfg_attr(feature = "fmt", derive(core::fmt::Debug))]
#[derive(Copy, Clone)]
pub enum Attr<'a> {
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

    #[cfg(any(feature = "rfc3489"))]
    OptXorMappedAddress(SocketAddr),

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    AlternateServer(SocketAddr),

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    ErrorCode { code: ErrorCode, desc: &'a str },

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
    CacheTimeout(core::time::Duration),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    ChannelNumber(u16),

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    Lifetime(core::time::Duration),

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
    AddressErrorCode { family: AddressFamily, code: ErrorCode, desc: &'a str },

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
    AccessToken { nonce: &'a [u8], mac: &'a [u8], timestamp: core::time::Duration, lifetime: core::time::Duration },

    #[cfg(any(feature = "rfc8016", feature = "iana"))]
    MobilityTicket(&'a [u8]),

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    ConnectionId(u32),

    #[cfg(any(feature = "rfc7982", feature = "iana"))]
    TransactionTransmitCounter { req: u8, res: u8 },

    Other { typ: u16, val: &'a [u8] },
}

impl<'a> Attr<'a> {
    fn from_buf(typ_buf: &'a [u8; 2], len_buf: &'a [u8; 2], val_buf: &'a [u8], tid_buf: &'a [u8; 16]) -> Option<Attr<'a>> {
        let typ = typ_buf.to_be();
        let len: u16 = len_buf.to_be();
        let val = val_buf.get(0..len as usize)?;

        use crate::consts::attr_type::*;

        Some(match typ {
            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            MAPPED_ADDRESS => Self::MappedAddress(Self::read_address(val)?),

            #[cfg(feature = "rfc3489")]
            RESPONSE_ADDRESS => Self::ResponseAddress(Self::read_address(val)?),

            #[cfg(any(feature = "rfc3489", feature = "rfc5780", feature = "iana"))]
            CHANGE_REQUEST => {
                let (change_ip, change_port) = Self::read_change_request(val)?;
                Self::ChangeRequest { change_ip, change_port }
            }

            #[cfg(feature = "rfc3489")]
            SOURCE_ADDRESS => Self::SourceAddress(Self::read_address(val)?),

            #[cfg(feature = "rfc3489")]
            CHANGED_ADDRESS => Self::ChangedAddress(Self::read_address(val)?),

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            USERNAME => Self::Username(Self::read_string(val)?),

            #[cfg(feature = "rfc3489")]
            PASSWORD => Self::Password(Self::read_string(val)?),

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            MESSAGE_INTEGRITY => Self::MessageIntegrity(val.get(0..20).map(carve)??),

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            ERROR_CODE => {
                let (code, desc) = Self::read_error_code(val)?;
                Self::ErrorCode { code, desc }
            }

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            UNKNOWN_ATTRIBUTES => Self::UnknownAttributes(UnknownAttrIter { buf: val }),

            #[cfg(feature = "rfc3489")]
            REFLECTED_FROM => Self::ReflectedFrom(Self::read_address(val)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            CHANNEL_NUMBER => Self::ChannelNumber(val.get(0..2).map(carve)?.map(u16::of_be)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            LIFETIME => Self::Lifetime(core::time::Duration::from_secs(val.get(0..4).map(carve)?.map(u32::of_be)? as u64)),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            XOR_PEER_ADDRESS => Self::XorPeerAddress(Self::read_xor_address(val, tid_buf)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            DATA => Self::Data(val),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            REALM => Self::Realm(Self::read_string(val)?),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            NONCE => Self::Nonce(Self::read_string(val)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            XOR_RELAYED_ADDRESS => Self::XorRelayedAddress(Self::read_xor_address(val, tid_buf)?),

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            REQUESTED_ADDRESS_FAMILY => Self::RequestedAddressFamily(val.get(0).map(AddressFamily::from_nums)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            EVEN_PORT => Self::EvenPort(val.get(0).map(|val| val & 1 == 1)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            REQUESTED_TRANSPORT => Self::RequestedTransport(val.get(0).map(TransportProtocol::from_nums)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            DONT_FRAGMENT => Self::DontFragment,

            #[cfg(any(feature = "rfc7635", feature = "iana"))]
            ACCESS_TOKEN => {
                let (nonce, mac, timestamp, lifetime) = Self::read_access_token(val)?;
                Self::AccessToken {
                    nonce,
                    mac,
                    timestamp,
                    lifetime,
                }
            }

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            MESSAGE_INTEGRITY_SHA256 => Self::MessageIntegritySha256(val.get(0..32).map(carve)??),

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            PASSWORD_ALGORITHM => Self::PasswordAlgorithm(Self::read_password_algorithm(val)?),

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            USERHASH => Self::Userhash(val.get(0..32).map(carve)??),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            XOR_MAPPED_ADDRESS => Self::XorMappedAddress(Self::read_xor_address(val, tid_buf)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            RESERVATION_TOKEN => Self::ReservationToken(val.get(0..8).map(carve)?.map(u64::of_be)?),

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            PRIORITY => Self::Priority(val.get(0..4).map(carve)?.map(u32::of_be)?),

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            USE_CANDIDATE => Self::UseCandidate,

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            PADDING => Self::Padding(val),

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            RESPONSE_PORT => Self::ResponsePort(val.get(0..2).map(carve)?.map(u16::of_be)?),

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            CONNECTION_ID => Self::ConnectionId(val.get(0..4).map(carve)?.map(u32::of_be)?),

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            ADDITIONAL_ADDRESS_FAMILY => Self::AdditionalAddressFamily(val.get(0).map(AddressFamily::from_nums)?),

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            ADDRESS_ERROR_CODE => {
                let (family, code, desc) = Self::read_address_error_code(val)?;
                Self::AddressErrorCode {
                    family,
                    code,
                    desc,
                }
            }

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            PASSWORD_ALGORITHMS => {
                Self::PasswordAlgorithms(PasswordAlgorithmIter {
                    raw_iter: RawIter::from(val),
                })
            }

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            ALTERNATE_DOMAIN => Self::AlternateDomain(Self::read_string(val)?),

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            ICMP => Self::Icmp {
                typ: *val.get(2)?,
                code: *val.get(3)?,
                data: val.get(4..8).map(carve)?.map(u32::of_be)?,
            },

            #[cfg(any(feature = "rfc3489"))]
            OPT_XOR_MAPPED_ADDRESS => Self::OptXorMappedAddress(Self::read_xor_address(val, tid_buf)?), // Vovida.org encodes XorMappedAddress as 0x8020 for backwards compat with RFC3489

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            SOFTWARE => Self::Software(Self::read_string(val)?),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            ALTERNATE_SERVER => Self::AlternateServer(Self::read_address(val)?),

            #[cfg(any(feature = "rfc7982", feature = "iana"))]
            TRANSACTION_TRANSMIT_COUNTER => Self::TransactionTransmitCounter {
                req: *val.get(2)?,
                res: *val.get(3)?,
            },

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            CACHE_TIMEOUT => {
                let timeout = val.get(0..4)
                    .map(carve)?
                    .map(u32::of_be)
                    .map(|val| val as u64)
                    .map(core::time::Duration::from_secs)?;

                Self::CacheTimeout(timeout)
            }

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            FINGERPRINT => Self::Fingerprint(Self::read_fingerprint(val)?),

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            ICE_CONTROLLED => Self::IceControlled(val.get(0..8).map(carve)?.map(u64::of_be)?),

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            ICE_CONTROLLING => Self::IceControlling(val.get(0..8).map(carve)?.map(u64::of_be)?),

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            RESPONSE_ORIGIN => Self::ResponseOrigin(Self::read_address(val)?),

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            OTHER_ADDRESS => Self::OtherAddress(Self::read_address(val)?),

            #[cfg(any(feature = "rfc6679", feature = "iana"))]
            ECN_CHECK => Self::EcnCheck {
                valid: val.get(3).map(|val| val & 128 != 0)?,
                val: val.get(3).map(|val| (val & 96) >> 5)?,
            },

            #[cfg(any(feature = "rfc7635", feature = "iana"))]
            THIRD_PARTY_AUTHORISATION => Self::ThirdPartyAuthorisation(Self::read_string(val)?),

            #[cfg(any(feature = "rfc8016", feature = "iana"))]
            MOBILITY_TICKET => Self::MobilityTicket(val),

            typ => Self::Other { typ, val },
        })
    }

    fn read_address(buf: &[u8]) -> Option<SocketAddr> {
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

    fn read_xor_address(buf: &[u8], tid: &[u8; 16]) -> Option<SocketAddr> {
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

    fn read_string(buf: &[u8]) -> Option<&str> {
        core::str::from_utf8(buf).ok()
    }

    fn read_fingerprint(buf: &[u8]) -> Option<u32> {
        buf.get(0..4)
            .map(carve)?
            .map(u32::of_be)
            .map(|val| val ^ 0x5354554E)
    }

    fn read_error_code(buf: &[u8]) -> Option<(ErrorCode, &str)> {
        let code = ErrorCode::from_nums(buf.get(2..4).map(carve)??);
        let desc = buf.get(4..).map(Self::read_string)??;
        Some((code, desc))
    }

    fn read_change_request(buf: &[u8]) -> Option<(bool, bool)> {
        let change_ip = buf.get(3).map(|b| b & 0x40 != 0)?;
        let change_port = buf.get(3).map(|b| b & 0x20 != 0)?;
        Some((change_ip, change_port))
    }

    fn read_access_token(buf: &[u8]) -> Option<(&[u8], &[u8], core::time::Duration, core::time::Duration)> {
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

        let timestamp = core::time::Duration::from_secs_f64(timestamp_seconds as f64 + timestamp_frac);

        let lifetime_secs = buf.get(cursor..cursor + 4)
            .map(carve)?
            .map(u32::of_be)?;

        let lifetime = core::time::Duration::from_secs(lifetime_secs as u64);

        Some((nonce, mac, timestamp, lifetime))
    }

    fn read_password_algorithm(buf: &[u8]) -> Option<PasswordAlgorithm> {
        PasswordAlgorithmIter { raw_iter: RawIter::from(&buf) }.next()
    }

    fn read_address_error_code(buf: &'a [u8]) -> Option<(AddressFamily, ErrorCode, &'a str)> {
        let address_family = buf.get(0)
            .map(AddressFamily::from_nums)?;

        let error_code = buf.get(2..4)
            .map(carve)?
            .map(ErrorCode::from_nums)?;

        let desc = Self::read_string(buf.get(4..)?)?;

        Some((address_family, error_code, desc))
    }
}

impl<'a> Attr<'a> {
    fn into_buf(&self, typ_buf: &'a mut [u8; 2], len_buf: &'a mut [u8; 2], val_buf: &'a mut [u8], tid_buf: &'a [u8; 16]) -> Option<usize> {
        use crate::consts::attr_type::*;

        match self {
            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::MappedAddress(addr) => {
                typ_buf.set_be(MAPPED_ADDRESS);
                let size = Self::write_address(&addr, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(feature = "rfc3489")]
            Self::ResponseAddress(addr) => {
                typ_buf.set_be(RESPONSE_ADDRESS);
                let size = Self::write_address(&addr, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc3489", feature = "rfc5780", feature = "iana"))]
            Self::ChangeRequest { change_ip, change_port } => {
                typ_buf.set_be(CHANGE_REQUEST);
                let size = Self::write_change_request(*change_ip, *change_port, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(feature = "rfc3489")]
            Self::SourceAddress(addr) => {
                typ_buf.set_be(SOURCE_ADDRESS);
                let size = Self::write_address(&addr, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(feature = "rfc3489")]
            Self::ChangedAddress(addr) => {
                typ_buf.set_be(CHANGED_ADDRESS);
                let size = Self::write_address(&addr, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::Username(uname) => {
                typ_buf.set_be(USERNAME);
                let size = Self::write_string(uname, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(feature = "rfc3489")]
            Self::Password(pwd) => {
                typ_buf.set_be(PASSWORD);
                let size = Self::write_string(pwd, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::MessageIntegrity(digest) => {
                typ_buf.set_be(MESSAGE_INTEGRITY);
                val_buf.get_mut(0..20).map(carve_mut)??.copy_from(digest);
                len_buf.set_be(20 as u16);
                Some(20)
            }

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::ErrorCode { code, desc } => {
                typ_buf.set_be(ERROR_CODE);
                Self::write_error_code(code, desc, val_buf)
            }

            #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::UnknownAttributes(iter) => {
                typ_buf.set_be(UNKNOWN_ATTRIBUTES);
                todo!()
            }

            #[cfg(feature = "rfc3489")]
            Self::ReflectedFrom(addr) => {
                typ_buf.set_be(REFLECTED_FROM);
                let size = Self::write_address(&addr, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::ChannelNumber(num) => {
                typ_buf.set_be(CHANNEL_NUMBER);
                val_buf.get_mut(0..2).map(carve_mut)??.set_be(*num);
                len_buf.set_be(2 as u16);
                Some(2)
            }

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::Lifetime(lifetime) => {
                typ_buf.set_be(LIFETIME);
                val_buf.get_mut(0..4).map(carve_mut)??.copy_from(&(lifetime.as_secs() as u32).to_be_bytes());
                len_buf.set_be(4 as u16);
                Some(4)
            }

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::XorPeerAddress(addr) => {
                typ_buf.set_be(XOR_PEER_ADDRESS);
                let size = Self::write_xor_address(&addr, val_buf, tid_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::Data(data) => {
                typ_buf.set_be(DATA);
                val_buf.get_mut(0..data.len())?.copy_from_slice(data);
                len_buf.set_be(data.len() as u16);
                Some(data.len())
            }

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::Realm(realm) => {
                typ_buf.set_be(REALM);
                let size = Self::write_string(realm, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::Nonce(nonce) => {
                typ_buf.set_be(NONCE);
                let size = Self::write_string(nonce, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::XorRelayedAddress(addr) => {
                typ_buf.set_be(XOR_RELAYED_ADDRESS);
                let size = Self::write_xor_address(addr, val_buf, tid_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            Self::RequestedAddressFamily(fam) => {
                typ_buf.set_be(REQUESTED_ADDRESS_FAMILY);
                *val_buf.get_mut(0)? = fam.into_nums();
                len_buf.set_be(1 as u16);
                Some(1)
            }

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::EvenPort(even_port) => {
                typ_buf.set_be(EVEN_PORT);
                *val_buf.get_mut(0)? = *even_port as u8;
                len_buf.set_be(1 as u16);
                Some(1)
            }

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::RequestedTransport(proto) => {
                typ_buf.set_be(REQUESTED_TRANSPORT);
                *val_buf.get_mut(0)? = proto.into_nums();
                len_buf.set_be(1 as u16);
                Some(1)
            }

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::DontFragment => {
                typ_buf.set_be(DONT_FRAGMENT);
                len_buf.set_be(0 as u16);
                Some(0)
            }

            #[cfg(any(feature = "rfc7635", feature = "iana"))]
            Self::AccessToken { nonce, mac, timestamp, lifetime } => {
                typ_buf.set_be(ACCESS_TOKEN);
                let size = Self::write_access_token(nonce, mac, timestamp, lifetime, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            Self::MessageIntegritySha256(digest) => {
                typ_buf.set_be(MESSAGE_INTEGRITY_SHA256);
                val_buf.get_mut(0..32).map(carve_mut)??.copy_from(digest);
                len_buf.set_be(32 as u16);
                Some(32)
            }

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            Self::PasswordAlgorithm(alg) => {
                typ_buf.set_be(PASSWORD_ALGORITHM);
                let size = Self::write_password_algorithm(alg, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            Self::Userhash(digest) => {
                typ_buf.set_be(USERHASH);
                val_buf.get_mut(0..32).map(carve_mut)??.copy_from(digest);
                len_buf.set_be(32 as u16);
                Some(32)
            }

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::XorMappedAddress(addr) => {
                typ_buf.set_be(XOR_MAPPED_ADDRESS);
                let size = Self::write_xor_address(&addr, val_buf, tid_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            Self::ReservationToken(token) => {
                typ_buf.set_be(RESERVATION_TOKEN);
                val_buf.get_mut(0..8).map(carve_mut)??.set_be(*token);
                len_buf.set_be(8 as u16);
                Some(8)
            }

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            Self::Priority(priority) => {
                typ_buf.set_be(PRIORITY);
                val_buf.get_mut(0..4).map(carve_mut)??.set_be(*priority);
                len_buf.set_be(4 as u16);
                Some(4)
            }

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            Self::UseCandidate => {
                typ_buf.set_be(USE_CANDIDATE);
                len_buf.set_be(0 as u16);
                Some(0)
            }

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            Self::Padding(pad) => {
                typ_buf.set_be(PADDING);
                val_buf.get_mut(0..pad.len())?.copy_from_slice(pad);
                len_buf.set_be(pad.len() as u16);
                Some(pad.len())
            }

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            Self::ResponsePort(port) => {
                typ_buf.set_be(RESPONSE_PORT);
                val_buf.get_mut(0..2).map(carve_mut)??.set_be(*port);
                len_buf.set_be(2 as u16);
                Some(2)
            }

            #[cfg(any(feature = "rfc6062", feature = "iana"))]
            Self::ConnectionId(cid) => {
                typ_buf.set_be(CONNECTION_ID);
                val_buf.get_mut(0..4).map(carve_mut)??.set_be(*cid);
                len_buf.set_be(4 as u16);
                Some(4)
            }

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            Self::AdditionalAddressFamily(fam) => {
                typ_buf.set_be(ADDITIONAL_ADDRESS_FAMILY);
                *val_buf.get_mut(0)? = fam.into_nums();
                len_buf.set_be(1 as u16);
                Some(1)
            }

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            Self::AddressErrorCode { family, code, desc } => {
                typ_buf.set_be(ADDRESS_ERROR_CODE);
                let size = Self::write_address_error_code(family, code, desc, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            Self::PasswordAlgorithms(iter) => {
                typ_buf.set_be(PASSWORD_ALGORITHMS);
                todo!()
            }

            #[cfg(any(feature = "rfc8489", feature = "iana"))]
            Self::AlternateDomain(domain) => {
                typ_buf.set_be(ALTERNATE_DOMAIN);
                let size = Self::write_string(domain, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            Self::Icmp { typ, code, data } => {
                typ_buf.set_be(ICMP);
                *val_buf.get_mut(2)? = *typ;
                *val_buf.get_mut(3)? = *code;
                val_buf.get_mut(4..8).map(carve_mut)??.set_be(*data);
                len_buf.set_be(8 as u16);
                Some(8)
            }

            #[cfg(any(feature = "rfc3489"))]
            Self::OptXorMappedAddress(addr) => {
                typ_buf.set_be(OPT_XOR_MAPPED_ADDRESS);
                let size = Self::write_xor_address(addr, val_buf, tid_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::Software(software) => {
                typ_buf.set_be(SOFTWARE);
                let size = Self::write_string(software, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::AlternateServer(addr) => {
                typ_buf.set_be(ALTERNATE_SERVER);
                let size = Self::write_address(addr, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc7982", feature = "iana"))]
            Self::TransactionTransmitCounter { req, res } => {
                typ_buf.set_be(TRANSACTION_TRANSMIT_COUNTER);
                *val_buf.get_mut(2)? = *req;
                *val_buf.get_mut(3)? = *res;
                len_buf.set_be(4 as u16);
                Some(4)
            }

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            Self::CacheTimeout(timeout) => {
                typ_buf.set_be(CACHE_TIMEOUT);
                val_buf.get_mut(0..4).map(carve_mut)??.set_be(timeout.as_secs() as u32);
                len_buf.set_be(4 as u16);
                Some(4)
            }

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            Self::Fingerprint(digest) => {
                typ_buf.set_be(FINGERPRINT);
                val_buf.get_mut(0..4).map(carve_mut)??.set_be(*digest ^ 0x5354554E);
                len_buf.set_be(4 as u16);
                Some(4)
            }

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            Self::IceControlled(token) => {
                typ_buf.set_be(ICE_CONTROLLED);
                val_buf.get_mut(0..8).map(carve_mut)??.set_be(*token);
                len_buf.set_be(8 as u16);
                Some(8)
            }

            #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
            Self::IceControlling(token) => {
                typ_buf.set_be(ICE_CONTROLLING);
                val_buf.get_mut(0..8).map(carve_mut)??.set_be(*token);
                len_buf.set_be(8 as u16);
                Some(8)
            }

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            Self::ResponseOrigin(addr) => {
                typ_buf.set_be(RESPONSE_ORIGIN);
                let size = Self::write_address(addr, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc5780", feature = "iana"))]
            Self::OtherAddress(addr) => {
                typ_buf.set_be(OTHER_ADDRESS);
                let size = Self::write_address(addr, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc6679", feature = "iana"))]
            Self::EcnCheck { valid, val } => {
                typ_buf.set_be(ECN_CHECK);
                let valid = (*valid as u8) << 7;
                let val = (val & 3) << 5;
                *val_buf.get_mut(3)? = val | valid;
                len_buf.set_be(4 as u16);
                Some(4)
            }

            #[cfg(any(feature = "rfc7635", feature = "iana"))]
            Self::ThirdPartyAuthorisation(token) => {
                typ_buf.set_be(THIRD_PARTY_AUTHORISATION);
                let size = Self::write_string(token, val_buf)?;
                len_buf.set_be(size as u16);
                Some(size)
            }

            #[cfg(any(feature = "rfc8016", feature = "iana"))]
            Self::MobilityTicket(data) => {
                typ_buf.set_be(MOBILITY_TICKET);
                val_buf.get_mut(0..data.len())?.copy_from_slice(data);
                len_buf.set_be(data.len() as u16);
                Some(data.len())
            }

            Self::Other { typ, val } => {
                typ_buf.set_be(*typ);
                val_buf.get_mut(0..val.len())?.copy_from_slice(val);
                len_buf.set_be(val.len() as u16);
                Some(val.len())
            }
        }
    }

    fn write_address(addr: &SocketAddr, buf: &mut [u8]) -> Option<usize> {
        let addr_family = buf.get_mut(0..2)
            .map(carve_mut)??;

        match addr {
            SocketAddr::V4(..) => addr_family.set_be(AddressFamily::IPv4.into_nums() as u16),
            SocketAddr::V6(..) => addr_family.set_be(AddressFamily::IPv6.into_nums() as u16),
        }

        let port = buf.get_mut(2..4)
            .map(carve_mut)??;

        match addr {
            SocketAddr::V4(ip, port_val) => {
                port.set_be(*port_val);
                buf.get_mut(4..8).map(carve_mut)??.copy_from(ip);
                Some(8)
            }
            SocketAddr::V6(ip, port_val) => {
                port.set_be(*port_val);
                buf.get_mut(4..20).map(carve_mut)??.copy_from(ip);
                Some(20)
            }
        }
    }

    fn write_xor_address(addr: &SocketAddr, buf: &mut [u8], tid: &[u8; 16]) -> Option<usize> {
        let port_mask = tid.get(0..2)
            .map(carve)?
            .map(u16::of_be)?;

        let xor_addr = match addr {
            SocketAddr::V4(ip, port) => {
                let port = port ^ port_mask;

                let cookie = tid.get(0..4)
                    .map(carve)?
                    .map(u32::of_be)?;

                let ip: u32 = ip.to_be();
                let ip = (ip ^ cookie).to_be_bytes();

                SocketAddr::V4(ip, port)
            }

            SocketAddr::V6(ip, port) => {
                let port = port ^ port_mask;

                let tid: u128 = tid.to_be();

                let ip: u128 = ip.to_be();
                let ip = (ip ^ tid).to_be_bytes();

                SocketAddr::V6(ip, port)
            }
        };

        Self::write_address(&xor_addr, buf)
    }

    fn write_string(val: &str, buf: &mut [u8]) -> Option<usize> {
        let len = val.len();
        buf.get_mut(0..len)?.copy_from_slice(val.as_bytes());
        Some(len)
    }

    fn write_error_code(code: &ErrorCode, desc: &str, buf: &mut [u8]) -> Option<usize> {
        buf.get_mut(2..4).map(carve_mut)??.copy_from(&code.into_nums());
        Self::write_string(desc, buf.get_mut(4..)?).map(|size| 4 + size) // '4' accounts for error code
    }

    fn write_change_request(change_ip: bool, change_port: bool, buf: &mut [u8]) -> Option<usize> {
        let change_ip = if change_ip { 0x40 } else { 0x00 } as u8;
        let change_port = if change_port { 0x20 } else { 0x00 } as u8;

        buf.get_mut(3).map(|b| *b = change_ip | change_port);
        Some(4)
    }

    fn write_access_token(nonce: &[u8], mac: &[u8], timestamp: &core::time::Duration, lifetime: &core::time::Duration, buf: &mut [u8]) -> Option<usize> {
        let mut cursor = 0usize;

        let nonce_len = nonce.len();

        buf.get_mut(cursor..cursor + 2).map(carve_mut)??.copy_from(&(nonce_len as u16).to_be_bytes());

        cursor += 2;

        buf.get_mut(cursor..cursor + nonce_len)?.copy_from_slice(nonce);

        cursor += nonce_len;

        let mac_len = mac.len();

        buf.get_mut(cursor..cursor + 2).map(carve_mut)??.copy_from(&(mac_len as u16).to_be_bytes());

        cursor += 2;

        buf.get_mut(cursor..cursor + mac_len)?.copy_from_slice(mac);

        cursor += mac_len;

        let timestamp_unix = timestamp.as_secs() << 4;
        let timestamp_unix = timestamp_unix | (((timestamp.as_secs_f64() - timestamp.as_secs() as f64) * 64000_f64) as u16) as u64;

        buf.get_mut(cursor..cursor + 8).map(carve_mut)??.copy_from(&timestamp_unix.to_be_bytes());

        cursor += 8;

        buf.get_mut(cursor..cursor + 4).map(carve_mut)??.copy_from(&(lifetime.as_secs() as u32).to_be_bytes());

        cursor += 4;

        Some(cursor)
    }

    fn write_password_algorithm(val: &PasswordAlgorithm, buf: &mut [u8]) -> Option<usize> {
        let (typ, params) = val.into_nums();

        buf.get_mut(0..2).map(carve_mut)??.copy_from(&typ.to_be_bytes());

        let len = params.len();
        buf.get_mut(2..4).map(carve_mut)??.copy_from(&len.to_be_bytes());

        buf.get_mut(4..4 + len)?.copy_from_slice(params);

        Some(4 + len)
    }

    fn write_address_error_code(fam: &AddressFamily, code: &ErrorCode, desc: &str, buf: &mut [u8]) -> Option<usize> {
        *buf.get_mut(0)? = fam.into_nums();

        Self::write_error_code(code, desc, buf)
    }
}

#[derive(Copy, Clone)]
pub struct UnknownAttrIter<'a> {
    buf: &'a [u8],
}

#[cfg(feature = "fmt")]
impl<'a> core::fmt::Debug for UnknownAttrIter<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let iter = UnknownAttrIter { buf: self.buf };
        f.write_str("[\n")?;
        for (idx, attr) in iter.enumerate() {
            f.write_fmt(format_args!("  ({}) {}\n", idx, attr))?;
        }
        f.write_str("]")?;
        Ok(())
    }
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

#[cfg_attr(feature = "fmt", derive(core::fmt::Debug))]
#[cfg(any(feature = "rfc8489", feature = "iana"))]
#[derive(Copy, Clone)]
pub enum PasswordAlgorithm<'a> {
    Md5,
    Sha256,
    Other { typ: u16, params: &'a [u8] },
}

impl<'a> PasswordAlgorithm<'a> {
    fn from_nums(typ: u16, params: &'a [u8]) -> Self {
        match typ {
            1 => PasswordAlgorithm::Md5,
            2 => PasswordAlgorithm::Sha256,
            typ => PasswordAlgorithm::Other { typ, params },
        }
    }

    fn into_nums(&self) -> (u16, &'a [u8]) {
        match self {
            Self::Md5 => (1, &[]),
            Self::Sha256 => (2, &[]),
            Self::Other { typ, params } => (*typ, *params),   // TODO move to consts
        }
    }
}

#[cfg(any(feature = "rfc8489", feature = "iana"))]
#[derive(Copy, Clone)]
pub struct PasswordAlgorithmIter<'a> {
    raw_iter: RawIter<'a>,
}

#[cfg(feature = "fmt")]
impl<'a> core::fmt::Debug for PasswordAlgorithmIter<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let iter = PasswordAlgorithmIter { raw_iter: self.raw_iter };
        f.write_str("[\n")?;
        for (idx, alg) in iter.enumerate() {
            f.write_fmt(format_args!("  ({}) {:?}\n", idx, alg))?;
        }
        f.write_str("]")?;
        Ok(())
    }
}

impl<'a> Iterator for PasswordAlgorithmIter<'a> {
    type Item = PasswordAlgorithm<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let attr = self.raw_iter.next()?;
        let typ = attr.typ().map(u16::of_be)?;
        let len = attr.len().map(u16::of_be)?;
        let params = attr.val()?.get(0..len as usize)?;
        Some(PasswordAlgorithm::from_nums(typ, params))
    }
}

pub struct AttrIter<'a> {
    raw_iter: RawIter<'a>,
    tid: &'a [u8; 16],
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let raw_attr = self.raw_iter.next()?;
        Attr::from_buf(raw_attr.typ()?, raw_attr.len()?, raw_attr.val()?, self.tid)
    }
}

#[cfg(feature = "fmt")]
impl<'a> core::fmt::Debug for AttrIter<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let iter = AttrIter { raw_iter: self.raw_iter.clone(), tid: self.tid };
        f.write_str("[\n")?;
        for (idx, e) in iter.enumerate() {
            f.write_fmt(format_args!("  ({}) {:?}\n", idx, e))?;
        }
        f.write_str("]")?;
        Ok(())
    }
}

#[cfg(test)]
mod head {
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
    fn read() {
        let msg = Msg::from(&MSG);

        if let MsgType::BindingRequest = msg.typ().unwrap() {} else { assert!(false); }

        assert_eq!(0x2112A442, msg.cookie().unwrap());

        assert_eq!(1, msg.tid().unwrap());

        assert_eq!(1, msg.attrs_iter().unwrap().count());

        let attr = msg.attrs_iter().unwrap().next().unwrap();

        if let Attr::ChangeRequest { change_ip, change_port } = attr {
            assert_eq!(true, change_ip);
            assert_eq!(true, change_port);
        } else {
            assert!(false);
        }
    }

    #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn binding_request() {
        let buf = [
            0x00, 0x01,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::BindingRequest) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn binding_response() {
        let buf = [
            0x01, 0x01,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::BindingResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn binding_indication() {
        let buf = [
            0x00, 0x11,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::BindingIndication) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn binding_error_response() {
        let buf = [
            0x01, 0x11,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::BindingErrorResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(feature = "rfc3489")]
    #[test]
    fn shared_secret_request() {
        let buf = [
            0x00, 0x02,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::SharedSecretRequest) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(feature = "rfc3489")]
    #[test]
    fn shared_secret_response() {
        let buf = [
            0x01, 0x02,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::SharedSecretResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(feature = "rfc3489")]
    #[test]
    fn shared_secret_error_response() {
        let buf = [
            0x01, 0x12,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::SharedSecretErrorResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn allocate_request() {
        let buf = [
            0x00, 0x03,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::AllocateRequest) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn allocate_response() {
        let buf = [
            0x01, 0x03,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::AllocateResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn allocate_error_response() {
        let buf = [
            0x01, 0x13,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::AllocateErrorResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn refresh_request() {
        let buf = [
            0x00, 0x04,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::RefreshRequest) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn refresh_response() {
        let buf = [
            0x01, 0x04,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::RefreshResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn refresh_error_response() {
        let buf = [
            0x01, 0x14,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::RefreshErrorResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn send_indication() {
        let buf = [
            0x00, 0x16,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::SendIndication) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn data_indication() {
        let buf = [
            0x00, 0x17,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::DataIndication) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn create_permission_request() {
        let buf = [
            0x00, 0x08,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::CreatePermissionRequest) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn create_permission_response() {
        let buf = [
            0x01, 0x08,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::CreatePermissionResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn create_permission_error_response() {
        let buf = [
            0x01, 0x18,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::CreatePermissionErrorResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn channel_bind_request() {
        let buf = [
            0x00, 0x09,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::ChannelBindRequest) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn channel_bind_response() {
        let buf = [
            0x01, 0x09,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::ChannelBindResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn channel_bind_error_response() {
        let buf = [
            0x01, 0x19,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::ChannelBindErrorResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    #[test]
    fn connect_request() {
        let buf = [
            0x00, 0x0A,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::ConnectRequest) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    #[test]
    fn connect_response() {
        let buf = [
            0x01, 0x0A,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::ConnectResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    #[test]
    fn connect_error_response() {
        let buf = [
            0x01, 0x1A,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::ConnectErrorResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    #[test]
    fn connection_bind_request() {
        let buf = [
            0x00, 0x0B,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::ConnectionBindRequest) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    #[test]
    fn connection_bind_response() {
        let buf = [
            0x01, 0x0B,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::ConnectionBindResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    #[test]
    fn connection_bind_error_response() {
        let buf = [
            0x01, 0x1B,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::ConnectionBindErrorResponse) = msg.typ() {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    #[test]
    fn connection_attempt_indication() {
        let buf = [
            0x0, 0x1C,
        ];

        let msg = Msg::from(&buf);
        if let Some(MsgType::ConnectionAttemptIndication) = msg.typ() {} else { assert!(false); }
    }
}


#[cfg(test)]
mod attr {
    use crate::byte::Attr::EcnCheck;
    use super::*;

    const TID: [u8; 16] = [1u8; 16];

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn mapped_address() {
        let buf = [
            0x00, 0x01,             // type: Mapped Address
            0x00, 0x08,             // len: 8
            0x00, 0x01,             // family: IPv4
            0x01, 0x02,             // port: 0x0102
            0x0A, 0x0B, 0x0C, 0x0D, // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::MappedAddress(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x00, 0x01,             // type: Mapped Address
            0x00, 0x14,             // len: 20
            0x00, 0x02,             // family: IPv6
            0x01, 0x02,             // port: 0x0102
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, // ip: 0123:4567:89AB:CDEF
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::MappedAddress(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(feature = "rfc3489")]
    #[test]
    fn response_address() {
        let buf = [
            0x00, 0x02,             // type: Response Address
            0x00, 0x08,             // len: 8
            0x00, 0x01,             // family: IPv4
            0x01, 0x02,             // port: 0x0102
            0x0A, 0x0B, 0x0C, 0x0D, // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ResponseAddress(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x00, 0x02,             // type: Response Address
            0x00, 0x14,             // len: 20
            0x00, 0x02,             // family: IPv6
            0x01, 0x02,             // port: 0x0102
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, // ip: 0123:4567:89AB:CDEF
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ResponseAddress(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc3489", feature = "rfc5780", feature = "iana"))]
    #[test]
    fn change_request() {
        let buf = [
            0x00, 0x03,              // type: ChangeRequest
            0x00, 0x04,              // length: 4 (only value bytes count)
            0x00, 0x00, 0x00, 0x40,  // change ip
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ChangeRequest { change_ip, change_port }) = attr {
            assert_eq!(true, change_ip);
            assert_eq!(false, change_port);
        } else { assert!(false); }

        let buf = [
            0x00, 0x03,              // type: ChangeRequest
            0x00, 0x04,              // length: 4 (only value bytes count)
            0x00, 0x00, 0x00, 0x20,  // change port
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ChangeRequest { change_ip, change_port }) = attr {
            assert_eq!(false, change_ip);
            assert_eq!(true, change_port);
        } else { assert!(false); }

        let buf = [
            0x00, 0x03,                     // type: ChangeRequest
            0x00, 0x04,                     // length: 4 (only value bytes count)
            0x00, 0x00, 0x00, 0x40 | 0x20,  // change both ip and port
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ChangeRequest { change_ip, change_port }) = attr {
            assert_eq!(true, change_ip);
            assert_eq!(true, change_port);
        } else { assert!(false); }
    }

    #[cfg(feature = "rfc3489")]
    #[test]
    fn source_address() {
        let buf = [
            0x00, 0x04,             // type: Source Address
            0x00, 0x08,             // len: 8
            0x00, 0x01,             // family: IPv4
            0x01, 0x02,             // port: 0x0102
            0x0A, 0x0B, 0x0C, 0x0D, // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::SourceAddress(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x00, 0x04,             // type: Source Address
            0x00, 0x14,             // len: 20
            0x00, 0x02,             // family: IPv6
            0x01, 0x02,             // port: 0x0102
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, // ip: 0123:4567:89AB:CDEF
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::SourceAddress(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(feature = "rfc3489")]
    #[test]
    fn changed_address() {
        let buf = [
            0x00, 0x05,             // type: Changed Address
            0x00, 0x08,             // len: 8
            0x00, 0x01,             // family: IPv4
            0x01, 0x02,             // port: 0x0102
            0x0A, 0x0B, 0x0C, 0x0D, // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ChangedAddress(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x00, 0x05,             // type: Changed Address
            0x00, 0x14,             // len: 20
            0x00, 0x02,             // family: IPv6
            0x01, 0x02,             // port: 0x0102
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, // ip: 0123:4567:89AB:CDEF
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ChangedAddress(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn username() {
        let buf = [
            0x00, 0x06,                         // type: Username
            0x00, 0x06,                         // len: 6
            0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // 'string'
            0x00, 0x00,                         // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::Username(val)) = attr {
            assert_eq!("string", val);
        } else { assert!(false); }
    }

    #[cfg(feature = "rfc3489")]
    #[test]
    fn password() {
        let buf = [
            0x00, 0x07,                         // type: Username
            0x00, 0x06,                         // len: 6
            0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // 'string'
            0x00, 0x00,                         // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::Password(val)) = attr {
            assert_eq!("string", val);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn message_integrity() {
        let buf = [
            0x00, 0x08,             // type: Message Integrity
            0x00, 0x14,             // len: 20
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, // value
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::MessageIntegrity(val)) = attr {
            assert_eq!(&buf[4..24], val.as_slice());
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn error_code() {
        let buf = [
            0x00, 0x09,                         // type: Error Code
            0x00, 0x0A,                         // len: 10
            0x00, 0x00, 0x06 << 5, 0x10,        // code: 616
            0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // desc: 'string'
            0x00, 0x00,                         // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ErrorCode { code: ErrorCode::Other(code), desc: desc }) = attr {
            assert_eq!(616, code);
            assert_eq!("string", desc);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn unknown_attrs() {
        let buf = [
            0x00, 0x0A, // type: Unknown Attributes
            0x00, 0x02, // len: 2
            0x01, 0x02, // unknown attr: 0x0102
            0x00, 0x00, // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::UnknownAttributes(mut iter)) = attr {
            if let Some(unknown_attr) = iter.next() {
                assert_eq!(0x0102, unknown_attr);
            } else { assert!(false); }

            assert!(iter.next().is_none());
        } else { assert!(false); }
    }

    #[cfg(feature = "rfc3489")]
    #[test]
    fn reflected_from() {
        let buf = [
            0x00, 0x0B,             // type: Reflected From
            0x00, 0x08,             // len: 8
            0x00, 0x01,             // family: IPv4
            0x01, 0x02,             // port: 0x0102
            0x0A, 0x0B, 0x0C, 0x0D, // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ReflectedFrom(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x00, 0x0B,             // type: Reflected From
            0x00, 0x14,             // len: 20
            0x00, 0x02,             // family: IPv6
            0x01, 0x02,             // port: 0x0102
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, // ip: 0123:4567:89AB:CDEF
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ReflectedFrom(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn channel_number() {
        let buf = [
            0x00, 0x0C, // type: Channel Number
            0x00, 0x02, // len: 2
            0x01, 0x02, // channel num: 0x0102
            0x00, 0x00, // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ChannelNumber(num)) = attr {
            assert_eq!(0x0102, num);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn lifetime() {
        let buf = [
            0x00, 0x0D,             // type: Lifetime
            0x00, 0x04,             // len: 2
            0x01, 0x02, 0x03, 0x04  // secs: 0x01020304
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::Lifetime(lifetime)) = attr {
            assert_eq!(0x01020304, lifetime.as_secs());
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn xor_peer_address() {
        let buf = [
            0x00, 0x12,                                                 // type: Xor Peer Address
            0x00, 0x08,                                                 // len: 8
            0x00, 0x01,                                                 // family: IPv4
            0x01 ^ TID[0], 0x02 ^ TID[1],                               // port: 0x0102
            0x0A ^ TID[0], 0x0B ^ TID[1], 0x0C ^ TID[2], 0x0D ^ TID[3], // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::XorPeerAddress(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x00, 0x12,                                                     // type: Xor Peer Address
            0x00, 0x14,                                                     // len: 20
            0x00, 0x02,                                                     // family: IPv6
            0x01 ^ TID[0], 0x02 ^ TID[1],                                   // port: 0x0102
            0x00 ^ TID[0], 0x01 ^ TID[1], 0x02 ^ TID[2], 0x03 ^ TID[3],
            0x04 ^ TID[4], 0x05 ^ TID[5], 0x06 ^ TID[6], 0x07 ^ TID[7],
            0x08 ^ TID[8], 0x09 ^ TID[9], 0x0A ^ TID[10], 0x0B ^ TID[11],
            0x0C ^ TID[12], 0x0D ^ TID[13], 0x0E ^ TID[14], 0x0F ^ TID[15], // ip: 0123:4567:89AB:CDEF
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::XorPeerAddress(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn data() {
        let buf = [
            0x00, 0x13,             // type: Data
            0x00, 0x04,             // len: 8
            0x01, 0x02, 0x03, 0x04, // data
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::Data(data)) = attr {
            assert_eq!(&[1, 2, 3, 4], data);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn realm() {
        let buf = [
            0x00, 0x14,                         // type: Realm
            0x00, 0x06,                         // len: 6
            0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // 'string'
            0x00, 0x00,                         // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::Realm("string")) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn nonce() {
        let buf = [
            0x00, 0x15,                         // type: Nonce
            0x00, 0x06,                         // len: 6
            0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // 'string'
            0x00, 0x00,                         // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::Nonce("string")) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn xor_relayed_address() {
        let buf = [
            0x00, 0x16,                                                 // type: Xor Relayed Address
            0x00, 0x08,                                                 // len: 8
            0x00, 0x01,                                                 // family: IPv4
            0x01 ^ TID[0], 0x02 ^ TID[1],                               // port: 0x0102
            0x0A ^ TID[0], 0x0B ^ TID[1], 0x0C ^ TID[2], 0x0D ^ TID[3], // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::XorRelayedAddress(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x00, 0x16,                                                     // type: Xor Relayed Address
            0x00, 0x14,                                                     // len: 20
            0x00, 0x02,                                                     // family: IPv6
            0x01 ^ TID[0], 0x02 ^ TID[1],                                   // port: 0x0102
            0x00 ^ TID[0], 0x01 ^ TID[1], 0x02 ^ TID[2], 0x03 ^ TID[3],
            0x04 ^ TID[4], 0x05 ^ TID[5], 0x06 ^ TID[6], 0x07 ^ TID[7],
            0x08 ^ TID[8], 0x09 ^ TID[9], 0x0A ^ TID[10], 0x0B ^ TID[11],
            0x0C ^ TID[12], 0x0D ^ TID[13], 0x0E ^ TID[14], 0x0F ^ TID[15], // ip: 0123:4567:89AB:CDEF
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::XorRelayedAddress(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    #[test]
    fn requested_address_family() {
        let buf = [
            0x00, 0x17,             // type: Requested Address Family
            0x00, 0x04,             // len: 4
            0x01, 0x00, 0x00, 0x00, // family: IPv4
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::RequestedAddressFamily(AddressFamily::IPv4)) = attr {} else { assert!(false); }

        let buf = [
            0x00, 0x17,             // type: Requested Address Family
            0x00, 0x04,             // len: 4
            0x02, 0x00, 0x00, 0x00, // family: IPv4
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::RequestedAddressFamily(AddressFamily::IPv6)) = attr {} else { assert!(false); }

        let buf = [
            0x00, 0x17,             // type: Requested Address Family
            0x00, 0x04,             // len: 4
            0x04, 0x00, 0x00, 0x00, // family: Other(4)
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::RequestedAddressFamily(AddressFamily::Other(4))) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn even_port() {
        let buf = [
            0x00, 0x18,       // type: Even Port
            0x00, 0x01,       // len: 1
            0x00,             // val: false
            0x00, 0x00, 0x00, // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::EvenPort(false)) = attr {} else { assert!(false); }

        let buf = [
            0x00, 0x18,       // type: Even Port
            0x00, 0x01,       // len: 1
            0x01,             // val: true
            0x00, 0x00, 0x00, // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::EvenPort(true)) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn requested_transport() {
        let buf = [
            0x00, 0x19,             // type: Even Port
            0x00, 0x04,             // len: 4
            0x11, 0x00, 0x00, 0x00, // val: UDP
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::RequestedTransport(TransportProtocol::UDP)) = attr {} else { assert!(false); }

        let buf = [
            0x00, 0x19,             // type: Even Port
            0x00, 0x04,             // len: 4
            0x01, 0x00, 0x00, 0x00, // val: Other(1)
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::RequestedTransport(TransportProtocol::Other(1))) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn dont_fragment() {
        let buf = [
            0x00, 0x1A, // type: Dont Fragment
            0x00, 0x00, // len: 0
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::DontFragment) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc7635", feature = "iana"))]
    #[test]
    fn access_token() {
        let buf = [
            0x00, 0x1B,             // type: Access Token
            0x00, 0x18,             // len: X
            0x00, 0x04,             // nonce len: 4
            0x01, 0x02, 0x03, 0x04, // nonce
            0x00, 0x04,             // mac len: 4
            0x04, 0x03, 0x02, 0x01, // mac
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x01, // timestamp: 1 + 1/64000 secs
            0x00, 0x00, 0x00, 0x01, // lifetime: 1 secs
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::AccessToken {
                        nonce: &[0x01, 0x02, 0x03, 0x04],
                        mac: &[0x04, 0x03, 0x02, 0x01],
                        timestamp,
                        lifetime,
                    }) = attr {
            assert_eq!(1.0 + 1.0 / 64000.0, timestamp.as_secs_f64());
            assert_eq!(1, lifetime.as_secs());
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    #[test]
    fn message_integrity_sha256() {
        let buf = [
            0x00, 0x1C,             // type: Message Integrity SHA256
            0x00, 0x20,             // len: 32
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, // digest
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::MessageIntegritySha256(&[
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F,
        ])) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    #[test]
    fn password_algorithm() {
        let buf = [
            0x00, 0x1D, // type: Password Algorithm
            0x00, 0x04, // len: 4
            0x00, 0x01, // typ: MD5
            0x00, 0x00, // param len: 0
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::PasswordAlgorithm(PasswordAlgorithm::Md5)) = attr {} else { assert!(false); }

        let buf = [
            0x00, 0x1D, // type: Password Algorithm
            0x00, 0x04, // len: 4
            0x00, 0x02, // typ: SHA256
            0x00, 0x00, // param len: 0
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::PasswordAlgorithm(PasswordAlgorithm::Sha256)) = attr {} else { assert!(false); }

        let buf = [
            0x00, 0x1D,             // type: Password Algorithm
            0x00, 0x08,             // len: 8
            0x00, 0x04,             // typ: Other(4)
            0x00, 0x04,             // param len: 4
            0x01, 0x02, 0x03, 0x04, // params
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::PasswordAlgorithm(PasswordAlgorithm::Other {
                                                typ: 4,
                                                params: &[0x01, 0x02, 0x03, 0x04]
                                            }
                    )) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    #[test]
    fn userhash() {
        let buf = [
            0x00, 0x1E,             // type: Userhash
            0x00, 0x20,             // len: 32
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, // digest
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::Userhash(&[
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F,
        ])) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn xor_mapped_address() {
        let buf = [
            0x00, 0x20,                                                 // type: Xor Mapped Address
            0x00, 0x08,                                                 // len: 8
            0x00, 0x01,                                                 // family: IPv4
            0x01 ^ TID[0], 0x02 ^ TID[1],                               // port: 0x0102
            0x0A ^ TID[0], 0x0B ^ TID[1], 0x0C ^ TID[2], 0x0D ^ TID[3], // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::XorMappedAddress(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x00, 0x20,                                                     // type: Xor Mapped Address
            0x00, 0x14,                                                     // len: 20
            0x00, 0x02,                                                     // family: IPv6
            0x01 ^ TID[0], 0x02 ^ TID[1],                                   // port: 0x0102
            0x00 ^ TID[0], 0x01 ^ TID[1], 0x02 ^ TID[2], 0x03 ^ TID[3],
            0x04 ^ TID[4], 0x05 ^ TID[5], 0x06 ^ TID[6], 0x07 ^ TID[7],
            0x08 ^ TID[8], 0x09 ^ TID[9], 0x0A ^ TID[10], 0x0B ^ TID[11],
            0x0C ^ TID[12], 0x0D ^ TID[13], 0x0E ^ TID[14], 0x0F ^ TID[15], // ip: 0123:4567:89AB:CDEF
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::XorMappedAddress(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    #[test]
    fn reservation_token() {
        let buf = [
            0x00, 0x22,             // type: Reservation Token
            0x00, 0x08,             // len: 8
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, // token
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ReservationToken(0x0102030405060708)) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    #[test]
    fn priority() {
        let buf = [
            0x00, 0x24,             // type: Priority
            0x00, 0x04,             // len: 4
            0x01, 0x02, 0x03, 0x04, // priority
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::Priority(0x01020304)) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    #[test]
    fn use_candidate() {
        let buf = [
            0x00, 0x25, // type: Use Candidate
            0x00, 0x00, // len: 0
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::UseCandidate) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    #[test]
    fn padding() {
        let buf = [
            0x00, 0x26,             // type: Padding
            0x00, 0x04,             // len: 4
            0x00, 0x00, 0x00, 0x00, // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::Padding(&[0, 0, 0, 0])) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    #[test]
    fn response_port() {
        let buf = [
            0x00, 0x27, // type: Response Port
            0x00, 0x04, // len: 2
            0x01, 0x02, // port: 0x0102
            0x00, 0x00, // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ResponsePort(0x0102)) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    #[test]
    fn connection_id() {
        let buf = [
            0x00, 0x2A,             // type: Connection Id
            0x00, 0x04,             // len: 4
            0x01, 0x02, 0x03, 0x04, // id: 0x01020304
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ConnectionId(0x01020304)) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    #[test]
    fn additional_address_family() {
        let buf = [
            0x80, 0x00,             // type: Additional Address Family
            0x00, 0x04,             // len: 4
            0x01, 0x00, 0x00, 0x00, // family: IPv4
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::AdditionalAddressFamily(AddressFamily::IPv4)) = attr {} else { assert!(false); }

        let buf = [
            0x80, 0x00,             // type: Additional Address Family
            0x00, 0x04,             // len: 4
            0x02, 0x00, 0x00, 0x00, // family: IPv4
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::AdditionalAddressFamily(AddressFamily::IPv6)) = attr {} else { assert!(false); }

        let buf = [
            0x80, 0x00,             // type: Additional Address Family
            0x00, 0x04,             // len: 4
            0x04, 0x00, 0x00, 0x00, // family: Other(4)
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::AdditionalAddressFamily(AddressFamily::Other(4))) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    #[test]
    fn address_error_code() {
        let buf = [
            0x80, 0x01,                         // type: Address Error Code
            0x00, 0x0A,                         // len: 10
            0x01, 0x00,                         // family: IPv4
            0x06 << 5, 0x10,                    // code: 616
            0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // desc: 'string'
            0x00, 0x00,                         // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::AddressErrorCode {
                        family: AddressFamily::IPv4,
                        code: ErrorCode::Other(616),
                        desc: "string"
                    }) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    #[test]
    fn password_algorithms() {
        let buf = [
            0x80, 0x02,             // type: Password Algorithms
            0x00, 0x10,             // len: 16
            0x00, 0x01,             // typ: MD5
            0x00, 0x00,             // param len: 0
            0x00, 0x02,             // typ: SHA256
            0x00, 0x00,             // param len: 0
            0x00, 0x04,             // typ: Other(4)
            0x00, 0x04,             // param len: 4
            0x01, 0x02, 0x03, 0x04  // params
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::PasswordAlgorithms(mut iter)) = attr {
            if let Some(PasswordAlgorithm::Md5) = iter.next() {} else { assert!(false); }
            if let Some(PasswordAlgorithm::Sha256) = iter.next() {} else { assert!(false); }
            if let Some(PasswordAlgorithm::Other { typ: 4, params: &[1, 2, 3, 4] }) = iter.next() {} else { assert!(false); }
            assert!(iter.next().is_none());
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    #[test]
    fn alternate_domain() {
        let buf = [
            0x80, 0x03,                         // type: Alternate Domain
            0x00, 0x06,                         // len: 6
            0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // val: 'string'
            0x00, 0x00,                         // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::AlternateDomain("string")) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    #[test]
    fn icmp() {
        let buf = [
            0x80, 0x04,             // type: Icmp
            0x00, 0x08,             // len: 8
            0x00, 0x00,             // RFFU
            0x01,                   // typ
            0x02,                   // code
            0x01, 0x02, 0x03, 0x04, // data
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::Icmp { typ: 1, code: 2, data: 0x01020304 }) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc3489"))]
    #[test]
    fn opt_xor_mapped_address() {
        let buf = [
            0x80, 0x20,                                                 // type: Opt Xor Mapped Address
            0x00, 0x08,                                                 // len: 8
            0x00, 0x01,                                                 // family: IPv4
            0x01 ^ TID[0], 0x02 ^ TID[1],                               // port: 0x0102
            0x0A ^ TID[0], 0x0B ^ TID[1], 0x0C ^ TID[2], 0x0D ^ TID[3], // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::OptXorMappedAddress(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x80, 0x20,                                                     // type: Opt Xor Mapped Address
            0x00, 0x14,                                                     // len: 20
            0x00, 0x02,                                                     // family: IPv6
            0x01 ^ TID[0], 0x02 ^ TID[1],                                   // port: 0x0102
            0x00 ^ TID[0], 0x01 ^ TID[1], 0x02 ^ TID[2], 0x03 ^ TID[3],
            0x04 ^ TID[4], 0x05 ^ TID[5], 0x06 ^ TID[6], 0x07 ^ TID[7],
            0x08 ^ TID[8], 0x09 ^ TID[9], 0x0A ^ TID[10], 0x0B ^ TID[11],
            0x0C ^ TID[12], 0x0D ^ TID[13], 0x0E ^ TID[14], 0x0F ^ TID[15], // ip: 0123:4567:89AB:CDEF
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::OptXorMappedAddress(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn software() {
        let buf = [
            0x80, 0x22,                         // type: Software
            0x00, 0x06,                         // len: 6
            0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // val: 'string'
            0x00, 0x00,                         // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::Software("string")) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn alternate_server() {
        let buf = [
            0x80, 0x23,             // type: Alternate Server
            0x00, 0x08,             // len: 8
            0x00, 0x01,             // family: IPv4
            0x01, 0x02,             // port: 0x0102
            0x0A, 0x0B, 0x0C, 0x0D, // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::AlternateServer(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x80, 0x23,             // type: Alternate Server
            0x00, 0x14,             // len: 20
            0x00, 0x02,             // family: IPv6
            0x01, 0x02,             // port: 0x0102
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, // ip: 0123:4567:89AB:CDEF
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::AlternateServer(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc7982", feature = "iana"))]
    #[test]
    fn transaction_transmit_counter() {
        let buf = [
            0x80, 0x25, // type: Transaction Transmit Counter
            0x00, 0x04, // len: 4
            0x00, 0x00, // RFFU
            0x01,       // req: 1
            0x02,       // res: 2
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::TransactionTransmitCounter { req: 1, res: 2 }) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    #[test]
    fn cache_timeout() {
        let buf = [
            0x80, 0x27,             // type: Cache Timeout
            0x00, 0x04,             // len: 4
            0x01, 0x02, 0x03, 0x04, // timemout: 0x01020304
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::CacheTimeout(timeout)) = attr {
            assert_eq!(0x01020304, timeout.as_secs());
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    #[test]
    fn fingerprint() {
        let buf = [
            0x80, 0x28,             // type: Fingerprint
            0x00, 0x04,             // len: 4
            0x01, 0x02, 0x03, 0x04, // val: 0x01020304 ^ 0x5354554E
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        const VAL: u32 = 0x01020304 ^ 0x5354554E;

        if let Some(Attr::Fingerprint(VAL)) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    const ICE_CONTROLLED: [u8; 12] = [
        0x80, 0x29,             // type: Ice Controlled
        0x00, 0x08,             // len: 8
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, // val
    ];

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    #[test]
    fn ice_controlled() {
        let attr = AttrIter {
            raw_iter: RawIter::from(&ICE_CONTROLLED),
            tid: &TID,
        }.next();

        if let Some(Attr::IceControlled(0x0102030405060708)) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    const ICE_CONTROLLING: [u8; 12] = [
        0x80, 0x2A,             // type: Ice Controlling
        0x00, 0x08,             // len: 8
        0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, // val
    ];

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    #[test]
    fn ice_controlling() {
        let attr = AttrIter {
            raw_iter: RawIter::from(&ICE_CONTROLLING),
            tid: &TID,
        }.next();

        if let Some(Attr::IceControlling(0x0102030405060708)) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    const RESPONSE_ORIGIN_IPv4: [u8; 12] = [
        0x80, 0x2B,             // type: Response Origin
        0x00, 0x08,             // len: 8
        0x00, 0x01,             // family: IPv4
        0x01, 0x02,             // port: 0x0102
        0x0A, 0x0B, 0x0C, 0x0D, // ip: 10.11.12.13
    ];

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    const RESPONSE_ORIGIN_IPv6: [u8; 24] = [
        0x80, 0x2B,             // type: Response Origin
        0x00, 0x14,             // len: 20
        0x00, 0x02,             // family: IPv6
        0x01, 0x02,             // port: 0x0102
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, // ip: 0123:4567:89AB:CDEF
    ];

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    #[test]
    fn response_origin() {
        let attr = AttrIter {
            raw_iter: RawIter::from(&RESPONSE_ORIGIN_IPv4),
            tid: &TID,
        }.next();

        if let Some(Attr::ResponseOrigin(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let attr = AttrIter {
            raw_iter: RawIter::from(&RESPONSE_ORIGIN_IPv6),
            tid: &TID,
        }.next();

        if let Some(Attr::ResponseOrigin(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    const OTHER_ADDRESS_IPv4: [u8; 12] = [
        0x80, 0x2C,             // type: Other Address
        0x00, 0x08,             // len: 8
        0x00, 0x01,             // family: IPv4
        0x01, 0x02,             // port: 0x0102
        0x0A, 0x0B, 0x0C, 0x0D, // ip: 10.11.12.13
    ];

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    const OTHER_ADDRESS_IPv6: [u8; 24] = [
        0x80, 0x2C,             // type: Other Address
        0x00, 0x14,             // len: 20
        0x00, 0x02,             // family: IPv6
        0x01, 0x02,             // port: 0x0102
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D, 0x0E, 0x0F, // ip: 0123:4567:89AB:CDEF
    ];

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    #[test]
    fn other_address_read() {
        let attr = AttrIter {
            raw_iter: RawIter::from(&OTHER_ADDRESS_IPv4),
            tid: &TID,
        }.next();

        if let Some(Attr::OtherAddress(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let attr = AttrIter {
            raw_iter: RawIter::from(&OTHER_ADDRESS_IPv6),
            tid: &TID,
        }.next();

        if let Some(Attr::OtherAddress(SocketAddr::V6(ip, port))) = attr {
            assert_eq!([
                           0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0x0A, 0x0B,
                           0x0C, 0x0D, 0x0E, 0x0F,
                       ], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    #[test]
    fn other_address_write() {
        let mut buf = [0u8; 12];
        let (typ, len, val) = split_into_tlv(&mut buf);

        Attr::OtherAddress(SocketAddr::V4([10, 11, 12, 13], 0x0102))
            .into_buf(typ, len, val, &TID);

        assert_eq!(&OTHER_ADDRESS_IPv4, &buf);

        let mut buf = [0u8; 24];
        let (typ, len, val) = split_into_tlv(&mut buf);

        Attr::OtherAddress(SocketAddr::V6([
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
        ], 0x0102)).into_buf(typ, len, val, &TID);

        assert_eq!(&OTHER_ADDRESS_IPv6, &buf);
    }

    #[cfg(any(feature = "rfc6679", feature = "iana"))]
    const ECN_CHECK: [u8; 8] = [
        0x80, 0x2D,                             // type: Ecn Check
        0x00, 0x04,                             // len: 4
        0x00, 0x00,                             // RFFU
        0x00, 0x01 << 7 | 0x01 << 6 | 0x01 << 5 // valid: true , val: 3
    ];

    #[cfg(any(feature = "rfc6679", feature = "iana"))]
    #[test]
    fn ecn_check_read() {
        let attr = AttrIter {
            raw_iter: RawIter::from(&ECN_CHECK),
            tid: &TID,
        }.next();

        if let Some(Attr::EcnCheck { valid: true, val: 3 }) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc6679", feature = "iana"))]
    #[test]
    fn ecn_check_write() {
        let mut buf = [0u8; 8];
        let (typ, len, val) = split_into_tlv(&mut buf);

        Attr::EcnCheck { valid: true, val: 3 }.into_buf(typ, len, val, &TID);

        assert_eq!(&ECN_CHECK, &buf);
    }

    #[cfg(any(feature = "rfc7635", feature = "iana"))]
    const THIRD_PARTY_AUTHORISATION: [u8; 12] = [
        0x80, 0x2E,                         // type: Third Party Authorisation
        0x00, 0x06,                         // len: 6
        0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // val: 'string'
        0x00, 0x00,                         // padding
    ];

    #[cfg(any(feature = "rfc7635", feature = "iana"))]
    #[test]
    fn third_party_authorisation_read() {
        let attr = AttrIter {
            raw_iter: RawIter::from(&THIRD_PARTY_AUTHORISATION),
            tid: &TID,
        }.next();

        if let Some(Attr::ThirdPartyAuthorisation("string")) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc7635", feature = "iana"))]
    #[test]
    fn third_party_authorisation_write() {
        let mut buf = [0u8; 12];
        let (typ, len, val) = split_into_tlv(&mut buf);

        Attr::ThirdPartyAuthorisation("string").into_buf(typ, len, val, &TID);

        assert_eq!(&THIRD_PARTY_AUTHORISATION, &buf);
    }

    #[cfg(any(feature = "rfc8016", feature = "iana"))]
    const MOBILITY_TICKET: [u8; 8] = [
        0x80, 0x30,             // type: Mobility Ticket
        0x00, 0x04,             // len: 4
        0x01, 0x02, 0x03, 0x04, // val
    ];

    #[cfg(any(feature = "rfc8016", feature = "iana"))]
    #[test]
    fn mobility_ticket_read() {
        let attr = AttrIter {
            raw_iter: RawIter::from(&MOBILITY_TICKET),
            tid: &TID,
        }.next();

        if let Some(Attr::MobilityTicket(&[1, 2, 3, 4])) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc8016", feature = "iana"))]
    #[test]
    fn mobility_ticket_write() {
        let mut buf = [0u8; 8];
        let (typ, len, val) = split_into_tlv(&mut buf);

        Attr::MobilityTicket(&[1, 2, 3, 4]).into_buf(typ, len, val, &TID);

        assert_eq!(&MOBILITY_TICKET, &buf);
    }

    fn split_into_tlv<const N: usize>(buf: &mut [u8; N]) -> (&mut [u8; 2], &mut [u8; 2], &mut [u8]) {
        let (typ, buf) = buf.split_at_mut(2);
        let (len, buf) = buf.split_at_mut(2);

        (typ.try_into().unwrap(), len.try_into().unwrap(), buf)
    }
}
