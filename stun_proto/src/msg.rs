use super::{Class, Method, ReaderErr, Result};

pub struct RawMsgHeaderReader<'a> {
    bytes: &'a [u8],
}

impl<'a> RawMsgHeaderReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn get_message_type(&self) -> Result<&[u8; 2]> {
        self.bytes.get(0..2)
            .map(|b| b.try_into().unwrap())
            .ok_or(ReaderErr::NotEnoughBytes)
    }

    pub fn get_message_length(&self) -> Result<&[u8; 2]> {
        self.bytes.get(2..4)
            .map(|b| b.try_into().unwrap())
            .ok_or(ReaderErr::NotEnoughBytes)
    }

    pub fn get_magic_cookie(&self) -> Result<&[u8; 4]> {
        self.bytes.get(4..8)
            .map(|b| b.try_into().unwrap())
            .ok_or(ReaderErr::NotEnoughBytes)
    }

    pub fn get_transaction_id(&self) -> Result<&[u8; 12]> {
        self.bytes.get(8..20)
            .map(|b| b.try_into().unwrap())
            .ok_or(ReaderErr::NotEnoughBytes)
    }

    pub fn get_attributes(&self) -> Result<&[u8]> {
        self.bytes.get(20..)
            .ok_or(ReaderErr::NotEnoughBytes)
    }

}

pub struct MsgHeaderReader<'a> {
    raw_reader: RawMsgHeaderReader<'a>,
}

impl<'a> MsgHeaderReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            raw_reader: RawMsgHeaderReader::new(bytes)
        }
    }

    pub fn get_method(&self) -> Result<Method> {
        let b = self.raw_reader.get_message_type()?;

        // we ignore the first two bits which should always be zero,
        // as well as the 5th and 9th bit which correspond to message class
        let method_raw = u16::from_be_bytes(*b) & 0b0011111011101111;

        match method_raw {
            1 => Ok(Method::Binding),
            _ => Err(ReaderErr::UnexpectedValue)
        }
    }

    pub fn get_class(&self) -> Result<Class> {
        let b = self.raw_reader.get_message_type()?;

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

    pub fn get_message_length(&self) -> Result<u16> {
        let b = self.raw_reader.get_message_length()?;
        Ok(u16::from_be_bytes(*b))
    }

    pub fn get_magic_cookie(&self) -> Result<u32> {
        self.raw_reader.get_magic_cookie()
            .map(|b| u32::from_be_bytes(*b))
    }

    pub fn get_transaction_id(&self) -> Result<u128> {
        let b = if let Ok(b) = self.raw_reader.get_transaction_id() { b } else {
            return Err(ReaderErr::NotEnoughBytes);
        };

        let transaction_id_1 = u64::from_be_bytes(b.get(0..8).unwrap().try_into().unwrap()) as u128;
        let transaction_id_2 = u32::from_be_bytes(b.get(8..12).unwrap().try_into().unwrap()) as u128;
        Ok(transaction_id_1 << 32 | transaction_id_2)
    }

    pub fn get_attributes(&self) -> Result<&[u8]> {
        let message_length = self.get_message_length()? as usize;
        let bytes = if let Ok(b) = self.raw_reader.get_attributes() { b } else {
            return Err(ReaderErr::NotEnoughBytes);
        };

        let bytes = if let Some(bytes) = bytes.get(0..message_length) { bytes } else {
            return Err(ReaderErr::NotEnoughBytes);
        };

        Ok(bytes)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_message_header() {
        let msg = [
            0x00, 0x01,             // method: Binding , class: Request
            0x00, 0x00,             // length: 0 (header does not count)
            0x21, 0x12, 0xA4, 0x42, // magic cookie (RFC spec constant)
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, // transaction id (12 bytes total)
        ];

        let r = MsgHeaderReader::new(&msg);

        assert_eq!(Method::Binding, r.get_method().unwrap());
        assert_eq!(Class::Request, r.get_class().unwrap());
        assert_eq!(0x2112A442, r.get_magic_cookie().unwrap());
        assert_eq!(1u128, r.get_transaction_id().unwrap());
    }
}