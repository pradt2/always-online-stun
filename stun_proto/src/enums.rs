#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MessageClass {
    Request,
    Indirection,
    SuccessResponse,
    ErrorResponse,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Method {
    Binding
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ComprehensionCategory {
    Required,
    Optional,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RfcSpec {
    Rfc3489,
    Rfc5245,
    Rfc5389,
    Rfc5766,
    Rfc5780,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ComplianceError {}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ErrorCode {
    TryAlternate,
    BadRequest,
    Unauthorized,
    UnknownAttribute,
    StaleNonce,
    InternalServerError,
}