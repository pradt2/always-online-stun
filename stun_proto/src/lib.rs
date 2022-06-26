#![no_std]

type Result<T> = core::result::Result<T, ReaderErr>;

#[derive(Debug, PartialEq)]
pub enum ReaderErr {
    NotEnoughBytes,
    UnexpectedValue,
}

#[derive(Debug, PartialEq)]
pub enum Method {
    Binding,
}

#[derive(Debug, PartialEq)]
pub enum Class {
    Request,
    Indirection,
    SuccessResponse,
    ErrorResponse,
}

pub struct MsgReader<'a> {
    bytes: &'a [u8],
}

impl MsgReader<'_> {
    pub fn get_message_type_raw(&self) -> Result<&[u8; 2]> {
        self.bytes.get(0..2)
            .map(|b| b.try_into().unwrap())
            .ok_or(ReaderErr::NotEnoughBytes)
    }

    pub fn get_message_length_raw(&self) -> Result<&[u8; 2]> {
        self.bytes.get(2..4)
            .map(|b| b.try_into().unwrap())
            .ok_or(ReaderErr::NotEnoughBytes)
    }

    pub fn get_magic_cookie_raw(&self) -> Result<&[u8; 4]> {
        self.bytes.get(4..8)
            .map(|b| b.try_into().unwrap())
            .ok_or(ReaderErr::NotEnoughBytes)
    }

    pub fn get_transaction_id_raw(&self) -> Result<&[u8; 12]> {
        self.bytes.get(8..20)
            .map(|b| b.try_into().unwrap())
            .ok_or(ReaderErr::NotEnoughBytes)
    }

    pub fn get_attributes_raw(&self) -> Result<&[u8]> {
        self.bytes.get(20..)
            .ok_or(ReaderErr::NotEnoughBytes)
    }
}

impl MsgReader<'_> {
    pub fn new(bytes: &[u8]) -> MsgReader {
        MsgReader {
            bytes
        }
    }

    /// Gets the message method.
    /// <br><br>
    ///
    /// Currently the method `Binding` is the only method in the RFC specs.
    /// <br><br>
    ///
    /// Ignores the first two bits of the message header, as they should always be 0.
    /// <br><br>
    ///
    /// Returns
    /// - `Result::NotEnoughBytes` if the message is not large enough
    /// - `Result::UnexpectedValue` if the value doesn't correspond to a known method
    /// <br><br>
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// use stun_proto::{Method, MsgReader};
    /// let msg = [0x0, 0x1];
    /// let r = MsgReader::new(&msg);
    /// assert_eq!(Method::Binding, r.get_method().unwrap());
    /// ```
    ///
    /// The message is not large enough:
    /// ```
    /// use stun_proto::{MsgReader, ReaderErr};
    /// let msg = [];
    /// let r = MsgReader::new(&msg);
    /// assert_eq!(ReaderErr::NotEnoughBytes, r.get_method().unwrap_err());
    /// ```
    ///
    /// The value does not correspond to a known method:
    /// ```
    /// use stun_proto::{MsgReader, ReaderErr};
    /// let msg = [0x0, 0xF];
    /// let r = MsgReader::new(&msg);
    /// assert_eq!(ReaderErr::UnexpectedValue, r.get_method().unwrap_err());
    /// ```
    pub fn get_method(&self) -> Result<Method> {
        let b = self.get_message_type_raw()?;

        // we ignore the first two bits which should always be zero,
        // as well as the 5th and 9th bit which correspond to message class
        let method_raw = u16::from_be_bytes(*b) & 0b0011111011101111;

        match method_raw {
            1 => Ok(Method::Binding),
            _ => Err(ReaderErr::UnexpectedValue)
        }
    }


    /// Gets the message class.
    /// <br><br>
    ///
    /// Ignores all header bits except the 5th and the 9th bit.
    /// <br><br>
    ///
    /// Returns
    /// - `Result::NotEnoughBytes` if the message is not large enough
    /// <br><br>
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// use stun_proto::{Class, MsgReader};
    /// let msg = [0x0, 0x1];
    /// let r = MsgReader::new(&msg);
    /// assert_eq!(Class::Request, r.get_class().unwrap());
    /// ```
    ///
    /// The message is not large enough:
    /// ```
    /// use stun_proto::{MsgReader, ReaderErr};
    /// let msg = [];
    /// let r = MsgReader::new(&msg);
    /// assert_eq!(ReaderErr::NotEnoughBytes, r.get_class().unwrap_err());
    /// ```
    pub fn get_class(&self) -> Result<Class> {
        let b = self.get_message_type_raw()?;

        // we ignore the first two bits which should always be zero,
        // as well all bits except the 5th and 9th bit since they all
        // correspond to message method
        let class_raw = u16::from_be_bytes(*b) & 0b0000000100010000;

        match class_raw {
            0b000000000 => Ok(Class::Request),
            0b000010000 => Ok(Class::Indirection),
            0b100000000 => Ok(Class::SuccessResponse),
            0b100010000 => Ok(Class::ErrorResponse),
            _ => Err(ReaderErr::UnexpectedValue)
        }
    }

    /// Gets the total length of the message in bits as declared in the message header.
    /// <br><br>
    ///
    /// Returns
    /// - `Result::NotEnoughBytes` if the message is not large enough
    /// <br><br>
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// use stun_proto::{Class, MsgReader};
    /// let msg = [
    ///     0x0, 0x1,   // class-method values
    ///     0x0, 0x7    // total length (in big-endian order)
    /// ];
    /// let r = MsgReader::new(&msg);
    /// assert_eq!(7, r.get_message_length().unwrap());
    /// ```
    ///
    /// The message is not large enough:
    /// ```
    /// use stun_proto::{MsgReader, ReaderErr};
    /// let msg = [];
    /// let r = MsgReader::new(&msg);
    /// assert_eq!(ReaderErr::NotEnoughBytes, r.get_message_length().unwrap_err());
    /// ```
    pub fn get_message_length(&self) -> Result<u16> {
        let b = self.get_message_length_raw()?;
        Ok(u16::from_be_bytes(*b))
    }
}

enum ComprehensionCategory {
    Required,
    Optional,
}

trait GenericAttribute<'a> {
    fn get_type(&'a self) -> Result<u16> {
        self.get_type_raw()
            .map(|b| u16::from_be_bytes(*b))
    }

    fn get_comprehension_category(&'a self) -> Result<ComprehensionCategory> {
        match self.get_type_raw()?[0] {
            0x00..=0x7F => Ok(ComprehensionCategory::Required),
            0x80..=0xFF => Ok(ComprehensionCategory::Optional),
        }
    }

    fn get_value_length(&'a self) -> Result<u16> {
        self.get_value_length_raw()
            .map(|b| u16::from_be_bytes(*b))
    }

    fn get_type_raw(&'a self) -> Result<&'a [u8; 2]> {
        self.get_bytes_raw().get(0..2)
            .map(|b| b.try_into().unwrap())
            .ok_or(ReaderErr::NotEnoughBytes)
    }

    fn get_value_length_raw(&'a self) -> Result<&'a [u8; 2]> {
        self.get_bytes_raw().get(2..4)
            .map(|b| b.try_into().unwrap())
            .ok_or(ReaderErr::NotEnoughBytes)
    }

    fn get_value_raw(&'a self) -> Result<&'a [u8]> {
        let value_length = self.get_value_length()? as usize;
        self.get_bytes_raw().get(4..4 + value_length)
            .ok_or(ReaderErr::NotEnoughBytes)
    }

    fn get_bytes_raw(&'a self) -> &'a [u8];
}

struct RawAttributeIterator<'a> {
    bytes: &'a [u8],
    idx: usize,
}

impl<'a> Iterator for RawAttributeIterator<'a> {
    type Item = Result<(&'a [u8; 2], &'a [u8; 2], &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.bytes.len() {
            None
        } else {
            let typ_raw = self.bytes.get(self.idx .. self.idx + 2)
                .map(|b| b.try_into().unwrap())
                .ok_or(ReaderErr::NotEnoughBytes);

            let typ_raw = match typ_raw {
                Ok(t) => t,
                Err(err) => {
                    self.idx = self.bytes.len();
                    return Some(Err(err))
                }
            };

            let val_len_raw = self.bytes.get(self.idx + 2 .. self.idx + 4)
                .map(|b| b.try_into().unwrap())
                .ok_or(ReaderErr::NotEnoughBytes);

            let val_len_raw: &[u8; 2] = match val_len_raw {
                Ok(t) => t,
                Err(err) => {
                    self.idx = self.bytes.len();
                    return Some(Err(err))
                }
            };

            let val_len = u16::from_be_bytes(*val_len_raw) as usize;

            let val_raw = self.bytes.get(self.idx + 4 .. self.idx + 4 + val_len)
                .ok_or(ReaderErr::NotEnoughBytes);

            let val_raw = match val_raw {
                Ok(val) => val,
                Err(err) => {
                    self.idx = self.bytes.len();
                    return Some(Err(err))
                }
            };

            self.idx += 4 + val_len;

            Some(Ok((typ_raw, val_len_raw, val_raw)))
        }
    }
}

struct AttributeIterator<'a> {
    raw_iter: RawAttributeIterator<'a>
}

impl<'a> Iterator for AttributeIterator<'a> {
    type Item = Result<(u16, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.raw_iter.next() {
            None => None,
            Some(Err(err)) => Some(Err(err)),
            Some(Ok((typ_raw, _, val_raw))) => {
                let typ = u16::from_be_bytes(*typ_raw);
                Some(Ok((typ, val_raw)))
            }
        }
    }
}

impl AttributeIterator<'_> {
    fn new(bytes: &'_ [u8]) -> AttributeIterator {
        AttributeIterator {
            raw_iter: RawAttributeIterator {
                bytes,
                idx: 0
            }
        }
    }
}

struct MappedAddress<'a> {
    bytes: &'a [u8],
}

impl GenericAttribute<'_> for MappedAddress<'_> {
    fn get_bytes_raw(&'_ self) -> &'_ [u8] {
        self.bytes
    }
}

struct XorMappedAddress<'a> {
    bytes: &'a [u8],
}

impl GenericAttribute<'_> for XorMappedAddress<'_> {
    fn get_bytes_raw(&'_ self) -> &'_ [u8] {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_message_header() {
        let msg = [
            0x00, 0x01,             // method: Binding , class: Request
            0x00, 0x14,             // total length: 20
            0x21, 0x12, 0xA4, 0x42, // magic cookie (RFC spec constant)
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, // transaction id (12 bytes total)
        ];

        let r = MsgReader::new(&msg);

        assert_eq!(Method::Binding, r.get_method().unwrap());
        assert_eq!(Class::Request, r.get_class().unwrap());
        assert_eq!(0x2112A442, u32::from_be_bytes(*r.get_magic_cookie_raw().unwrap()));
        assert_eq!(12, r.get_transaction_id_raw().unwrap().len());
        assert_eq!(0, r.get_attributes_raw().unwrap().len());
    }

    #[test]
    fn test_iter_over_attrs() {
        let attr = [
            0x00, 0x01,             // type
            0x00, 0x04,             // value length
            0x01, 0x01, 0x01, 0x01, // value
        ];

        assert_eq!(1, AttributeIterator::new(&attr).count());

        for attr in AttributeIterator::new(&attr) {
            match attr {
                Ok((typ, val)) => {
                    assert_eq!(1u16, typ);
                    assert_eq!([0x01, 0x01, 0x01, 0x01], *val);
                },
                Err(_) => assert!(false, "Test attr should be valid")
            }
        }
    }

    #[test]
    fn test_iter_over_attrs_invalid_attr_missing_byte() {
        let attr = [
            0x00, 0x01,             // type
            0x00, 0x05,             // value length (4+1 because we're simulating a missing byte)
            0x01, 0x01, 0x01, 0x01, // value
        ];

        assert_eq!(1, AttributeIterator::new(&attr).count());

        for attr in AttributeIterator::new(&attr) {
            match attr {
                Ok(_) => assert!(false, "Test attr should be invalid"),
                Err(_) => assert!(true, "Test attr should be valid")
            }
        }
    }

    #[test]
    fn test_iter_over_attrs_invalid_attr_extra_byte() {
        let attr = [
            0x00, 0x01,             // type
            0x00, 0x03,             // value length (4-1 because we're simulating an extra byte)
            0x01, 0x01, 0x01, 0x01, // value
        ];

        assert_eq!(2, AttributeIterator::new(&attr).count());

        let mut iter = AttributeIterator::new(&attr);

        if let Some(Ok((typ, val))) = iter.next() {
            assert_eq!(1u16, typ);
            assert_eq!([0x01, 0x01, 0x01], *val);
        } else {
            assert!(false, "First attr should be valid");
        }

        if let Some(Err(_)) = iter.next() {
            assert!(true);
        } else {
            assert!(false, "Second attr should be an error");
        }
    }
}
