pub type Result<T> = core::result::Result<T, ReaderErr>;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ReaderErr {
    NotEnoughBytes,
    UnexpectedValue,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Method {
    Binding,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Class {
    Request,
    Indirection,
    SuccessResponse,
    ErrorResponse,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SocketAddr {
    V4 { addr: u32, port: u16 },
    V6 { addr: u128, port: u16 },
}

// #[derive(Copy, Clone, Debug, PartialEq)]
// pub enum ErrorCode {
//     TryAlternate,
//     BadRequest,
//     Unauthorized,
//     UnknownAttribute,
//     StaleNonce,
//     InternalServerError,
// }
