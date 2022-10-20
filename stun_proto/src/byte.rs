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
        use consts::msg_type::*;

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

    fn into(&self) -> [u8; 2] {
        use consts::msg_type::*;

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
    fn from(fam: &u8) -> Self {
        match fam {
            1 => Self::IPv4,
            2 => Self::IPv6,
            fam => Self::Other(*fam),
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
    fn from(proto: &u8) -> Self {
        match proto {
            17 => Self::UDP,
            proto => Self::Other(*proto),
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

mod consts {
    pub mod msg_type {
        #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
        pub const BINDING_REQUEST: u16 = 0x0001;

        #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
        pub const BINDING_RESPONSE: u16 = 0x0101;

        #[cfg(any(feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
        pub const BINDING_INDICATION: u16 = 0x0011;

        #[cfg(any(feature = "rfc3489", feature = "rfc5349", feature = "rfc8489", feature = "iana"))]
        pub const BINDING_ERROR_RESPONSE: u16 = 0x0111;

        #[cfg(feature = "rfc3489")]
        pub const SHARED_SECRET_REQUEST: u16 = 0x0002;

        #[cfg(feature = "rfc3489")]
        pub const SHARED_SECRET_RESPONSE: u16 = 0x0102;

        #[cfg(feature = "rfc3489")]
        pub const SHARED_SECRET_ERROR_RESPONSE: u16 = 0x0112;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const ALLOCATE_REQUEST: u16 = 0x0003;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const ALLOCATE_RESPONSE: u16 = 0x0103;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const ALLOCATE_ERROR_RESPONSE: u16 = 0x0113;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const REFRESH_REQUEST: u16 = 0x0004;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const REFRESH_RESPONSE: u16 = 0x0104;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const REFRESH_ERROR_RESPONSE: u16 = 0x0114;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const SEND_INDICATION: u16 = 0x0016;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const DATA_INDICATION: u16 = 0x0017;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const CREATE_PERMISSION_REQUEST: u16 = 0x0008;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const CREATE_PERMISSION_RESPONSE: u16 = 0x0108;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const CREATE_PERMISSION_ERROR_RESPONSE: u16 = 0x0118;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const CHANNEL_BIND_REQUEST: u16 = 0x0009;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const CHANNEL_BIND_RESPONSE: u16 = 0x0109;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const CHANNEL_BIND_ERROR_RESPONSE: u16 = 0x0119;

        #[cfg(any(feature = "rfc6062", feature = "iana"))]
        pub const CONNECT_REQUEST: u16 = 0x000A;

        #[cfg(any(feature = "rfc6062", feature = "iana"))]
        pub const CONNECT_RESPONSE: u16 = 0x010A;

        #[cfg(any(feature = "rfc6062", feature = "iana"))]
        pub const CONNECT_ERROR_RESPONSE: u16 = 0x011A;

        #[cfg(any(feature = "rfc6062", feature = "iana"))]
        pub const CONNECTION_BIND_REQUEST: u16 = 0x000B;

        #[cfg(any(feature = "rfc6062", feature = "iana"))]
        pub const CONNECTION_BIND_RESPONSE: u16 = 0x010B;

        #[cfg(any(feature = "rfc6062", feature = "iana"))]
        pub const CONNECTION_BIND_ERROR_RESPONSE: u16 = 0x011B;

        #[cfg(any(feature = "rfc6062", feature = "iana"))]
        pub const CONNECTION_ATTEMPT_INDICATION: u16 = 0x001C;
    }

    pub mod error_code {
        #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
        pub const TRY_ALTERNATE: u16 = 300;

        #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
        pub const BAD_REQUEST: u16 = 400;

        #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
        pub const UNAUTHORISED: u16 = 401;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const FORBIDDEN: u16 = 403;

        #[cfg(any(feature = "rfc8016", feature = "iana"))]
        pub const MOBILITY_FORBIDDEN: u16 = 405;

        #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
        pub const UNKNOWN_ATTRIBUTE: u16 = 420;

        #[cfg(any(feature = "rfc3489"))]
        pub const STALE_CREDENTIALS: u16 = 430;

        #[cfg(any(feature = "rfc3489"))]
        pub const INTEGRITY_CHECK_FAILURE: u16 = 431;

        #[cfg(any(feature = "rfc3489"))]
        pub const MISSING_USERNAME: u16 = 432;

        #[cfg(any(feature = "rfc3489"))]
        pub const USE_TLS: u16 = 433;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const ALLOCATION_MISMATCH: u16 = 437;

        #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
        pub const STALE_NONCE: u16 = 438;

        #[cfg(any(feature = "rfc8656", feature = "iana"))]
        pub const ADDRESS_FAMILY_NOT_SUPPORTED: u16 = 440;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const WRONG_CREDENTIALS: u16 = 441;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const UNSUPPORTED_TRANSPORT_PROTOCOL: u16 = 442;

        #[cfg(any(feature = "rfc8656", feature = "iana"))]
        pub const PEER_ADDRESS_FAMILY_MISMATCH: u16 = 443;

        #[cfg(any(feature = "rfc6062", feature = "iana"))]
        pub const CONNECTION_ALREADY_EXISTS: u16 = 446;

        #[cfg(any(feature = "rfc6062", feature = "iana"))]
        pub const CONNECTION_TIMEOUT_OR_FAILURE: u16 = 447;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const ALLOCATION_QUOTA_REACHED: u16 = 486;

        #[cfg(any(feature = "rfc5245", feature = "rfc8445", feature = "iana"))]
        pub const ROLE_CONFLICT: u16 = 487;

        #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
        pub const SERVER_ERROR: u16 = 500;

        #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
        pub const INSUFFICIENT_CAPACITY: u16 = 508;

        #[cfg(any(feature = "rfc3489"))]
        pub const GLOBAL_FAILURE: u16 = 600;
    }
}

impl ErrorCode {
    fn from(buf: &[u8; 2]) -> Self {
        use consts::error_code::*;

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

    pub fn into(&self) -> [u8; 2] {
        use consts::error_code::*;

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
            0x0008 => Self::MessageIntegrity(val.get(0..20).map(carve)??),

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
            0x000D => Self::Lifetime(core::time::Duration::from_secs(val.get(0..4).map(carve)?.map(u32::of_be)? as u64)),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0012 => Self::XorPeerAddress(Self::parse_xor_address(val, tid)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0013 => Self::Data(val),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0014 => Self::Realm(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
            0x0015 => Self::Nonce(Self::parse_string(val)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0016 => Self::XorRelayedAddress(Self::parse_xor_address(val, tid)?),

            #[cfg(any(feature = "rfc8656", feature = "iana"))]
            0x0017 => Self::RequestedAddressFamily(val.get(0).map(AddressFamily::from)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0018 => Self::EvenPort(val.get(0).map(|val| val & 1 == 1)?),

            #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
            0x0019 => Self::RequestedTransport(val.get(0).map(TransportProtocol::from)?),

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
                    raw_iter: RawIter::from(val),
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

            #[cfg(any(feature = "rfc3489"))]
            0x8020 => Self::OptXorMappedAddress(Self::parse_xor_address(val, tid)?), // Vovida.org encodes XorMappedAddress as 0x8020 for backwards compat with RFC3489

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
                    .map(core::time::Duration::from_secs)?;

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

    fn parse_fingerprint(buf: &[u8]) -> Option<u32> {
        buf.get(0..4)
            .map(carve)?
            .map(u32::of_be)
            .map(|val| val ^ 0x5354554E)
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

    fn parse_access_token(buf: &[u8]) -> Option<(&[u8], &[u8], core::time::Duration, core::time::Duration)> {
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

    fn parse_password_algorithm(buf: &[u8]) -> Option<PasswordAlgorithm> {
        PasswordAlgorithmIter { raw_iter: RawIter::from(&buf) }.next()
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
        Some(PasswordAlgorithm::from(typ, params))
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
        Attr::from(raw_attr, self.tid)
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
            0x00, 0x00, 0x06 << 5, 0x10,       // code: 616
            0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // reason: 'string'
            0x00, 0x00,                         // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ErrorCode { code: ErrorCode::Other(code), reason }) = attr {
            assert_eq!(616, code);
            assert_eq!("string", reason);
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
            0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // reason: 'string'
            0x00, 0x00,                         // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::AddressErrorCode {
                        family: AddressFamily::IPv4,
                        code: ErrorCode::Other(616),
                        reason: "string"
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

    #[test]
    fn ice_controlled() {
        let buf = [
            0x80, 0x29,             // type: Ice Controlled
            0x00, 0x08,             // len: 8
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, // val
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::IceControlled(0x0102030405060708)) = attr {} else { assert!(false); }
    }

    #[test]
    fn ice_controlling() {
        let buf = [
            0x80, 0x2A,             // type: Ice Controlling
            0x00, 0x08,             // len: 8
            0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, // val
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::IceControlling(0x0102030405060708)) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    #[test]
    fn response_origin() {
        let buf = [
            0x80, 0x2B,             // type: Response Origin
            0x00, 0x08,             // len: 8
            0x00, 0x01,             // family: IPv4
            0x01, 0x02,             // port: 0x0102
            0x0A, 0x0B, 0x0C, 0x0D, // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ResponseOrigin(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x80, 0x2B,             // type: Response Origin
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
    #[test]
    fn other_address() {
        let buf = [
            0x80, 0x2C,             // type: Other Address
            0x00, 0x08,             // len: 8
            0x00, 0x01,             // family: IPv4
            0x01, 0x02,             // port: 0x0102
            0x0A, 0x0B, 0x0C, 0x0D, // ip: 10.11.12.13
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::OtherAddress(SocketAddr::V4(ip, port))) = attr {
            assert_eq!([10, 11, 12, 13], ip);
            assert_eq!(0x0102, port);
        } else { assert!(false); }

        let buf = [
            0x80, 0x2C,             // type: Other Address
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

    #[cfg(any(feature = "rfc6679", feature = "iana"))]
    #[test]
    fn enc_check() {
        let buf = [
            0x80, 0x2D, // type: Ecn Check
            0x00, 0x04, // len: 4
            0x00, 0x00, // RFFU
            0x00, 0x00, // valid: false , val: 0
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::EcnCheck { valid: false, val: 0 }) = attr {} else { assert!(false); }

        let buf = [
            0x80, 0x2D,     // type: Ecn Check
            0x00, 0x04,     // len: 4
            0x00, 0x00,     // RFFU
            0x00, 0x01 << 7 // valid: true , val: 0
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::EcnCheck { valid: true, val: 0 }) = attr {} else { assert!(false); }

        let buf = [
            0x80, 0x2D,                             // type: Ecn Check
            0x00, 0x04,                             // len: 4
            0x00, 0x00,                             // RFFU
            0x00, 0x01 << 7 | 0x01 << 6 | 0x01 << 5 // valid: true , val: 3
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::EcnCheck { valid: true, val: 3 }) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc7635", feature = "iana"))]
    #[test]
    fn third_party_authorisation() {
        let buf = [
            0x80, 0x2E,                         // type: Third Party Authorisation
            0x00, 0x06,                         // len: 6
            0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, // val: 'string'
            0x00, 0x00,                         // padding
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::ThirdPartyAuthorisation("string")) = attr {} else { assert!(false); }
    }

    #[cfg(any(feature = "rfc8016", feature = "iana"))]
    #[test]
    fn mobility_ticket() {
        let buf = [
            0x80, 0x30,             // type: Mobility Ticket
            0x00, 0x04,             // len: 4
            0x01, 0x02, 0x03, 0x04, // val
        ];

        let attr = AttrIter {
            raw_iter: RawIter::from(&buf),
            tid: &TID,
        }.next();

        if let Some(Attr::MobilityTicket(&[1, 2, 3, 4])) = attr {} else { assert!(false); }
    }
}
