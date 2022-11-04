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

pub mod attr_type {
    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    pub const MAPPED_ADDRESS: u16 = 0x0001;

    #[cfg(feature = "rfc3489")]
    pub const RESPONSE_ADDRESS: u16 = 0x0002;

    #[cfg(any(feature = "rfc3489", feature = "rfc5780", feature = "iana"))]
    pub const CHANGE_REQUEST: u16 = 0x0003;

    #[cfg(feature = "rfc3489")]
    pub const SOURCE_ADDRESS: u16 = 0x0004;

    #[cfg(feature = "rfc3489")]
    pub const CHANGED_ADDRESS: u16 = 0x0005;

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    pub const USERNAME: u16 = 0x0006;

    #[cfg(feature = "rfc3489")]
    pub const PASSWORD: u16 = 0x0007;

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    pub const MESSAGE_INTEGRITY: u16 = 0x0008;

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    pub const ERROR_CODE: u16 = 0x0009;

    #[cfg(any(feature = "rfc3489", feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    pub const UNKNOWN_ATTRIBUTES: u16 = 0x000A;

    #[cfg(feature = "rfc3489")]
    pub const REFLECTED_FROM: u16 = 0x000B;

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    pub const CHANNEL_NUMBER: u16 = 0x000C;

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    pub const LIFETIME: u16 = 0x000D;

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    pub const XOR_PEER_ADDRESS: u16 = 0x0012;

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    pub const DATA: u16 = 0x0013;

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    pub const REALM: u16 = 0x0014;

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    pub const NONCE: u16 = 0x0015;

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    pub const REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    pub const EVEN_PORT: u16 = 0x0018;

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    pub const REQUESTED_TRANSPORT: u16 = 0x0019;

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    pub const DONT_FRAGMENT: u16 = 0x001A;

    #[cfg(any(feature = "rfc7635", feature = "iana"))]
    pub const ACCESS_TOKEN: u16 = 0x001B;

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    pub const MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    pub const PASSWORD_ALGORITHM: u16 = 0x001D;

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    pub const USERHASH: u16 = 0x001E;

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;

    #[cfg(any(feature = "rfc5766", feature = "rfc8656", feature = "iana"))]
    pub const RESERVATION_TOKEN: u16 = 0x0022;

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    pub const PRIORITY: u16 = 0x0024;

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    pub const USE_CANDIDATE: u16 = 0x0025;

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    pub const PADDING: u16 = 0x0026;

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    pub const RESPONSE_PORT: u16 = 0x0027;

    #[cfg(any(feature = "rfc6062", feature = "iana"))]
    pub const CONNECTION_ID: u16 = 0x002A;

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    pub const ADDITIONAL_ADDRESS_FAMILY: u16 = 0x8000;

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    pub const ADDRESS_ERROR_CODE: u16 = 0x8001;

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    pub const PASSWORD_ALGORITHMS: u16 = 0x8002;

    #[cfg(any(feature = "rfc8489", feature = "iana"))]
    pub const ALTERNATE_DOMAIN: u16 = 0x8003;

    #[cfg(any(feature = "rfc8656", feature = "iana"))]
    pub const ICMP: u16 = 0x8004;

    #[cfg(any(feature = "rfc3489"))]
    pub const OPT_XOR_MAPPED_ADDRESS: u16 = 0x8020;

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    pub const SOFTWARE: u16 = 0x8022;

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    pub const ALTERNATE_SERVER: u16 = 0x8023;

    #[cfg(any(feature = "rfc7982", feature = "iana"))]
    pub const TRANSACTION_TRANSMIT_COUNTER: u16 = 0x8025;

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    pub const CACHE_TIMEOUT: u16 = 0x8027;

    #[cfg(any(feature = "rfc5389", feature = "rfc8489", feature = "iana"))]
    pub const FINGERPRINT: u16 = 0x8028;

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    pub const ICE_CONTROLLED: u16 = 0x8029;

    #[cfg(any(feature = "rfc5425", feature = "rfc8445", feature = "iana"))]
    pub const ICE_CONTROLLING: u16 = 0x802A;

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    pub const RESPONSE_ORIGIN: u16 = 0x802B;

    #[cfg(any(feature = "rfc5780", feature = "iana"))]
    pub const OTHER_ADDRESS: u16 = 0x802C;

    #[cfg(any(feature = "rfc6679", feature = "iana"))]
    pub const ECN_CHECK: u16 = 0x802D;

    #[cfg(any(feature = "rfc7635", feature = "iana"))]
    pub const THIRD_PARTY_AUTHORISATION: u16 = 0x802E;

    #[cfg(any(feature = "rfc8016", feature = "iana"))]
    pub const MOBILITY_TICKET: u16 = 0x8030;
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

pub mod addr_family {
    pub const IPv4: u8 = 1;
    pub const IPv6: u8 = 2;
}

pub mod transport_proto {
    pub const UDP: u8 = 17;
}