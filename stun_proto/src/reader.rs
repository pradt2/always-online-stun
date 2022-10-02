pub type Result<T> = core::result::Result<T, ReaderErr>;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ReaderErr {
    NotEnoughBytes,
    UnexpectedValue,
}
