pub struct RawMsgHeaderReader<'a> {
    bytes: &'a [u8],
}

impl<'a> RawMsgHeaderReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn get_message_type(&self) -> Option<u16> {
        self.bytes.get(0..2)
            .map(|b| b.try_into().unwrap())
            .map(|b| u16::from_be_bytes(b))
    }

    pub fn get_message_length(&self) -> Option<u16> {
        self.bytes.get(2..4)
            .map(|b| b.try_into().unwrap())
            .map(|b| u16::from_be_bytes(b))
    }

    pub fn get_transaction_id(&self) -> Option<u128> {
        self.bytes.get(4..20)
            .map(|b| b.try_into().unwrap())
            .map(|b| u128::from_be_bytes(b))
    }

}

pub struct RawMsgHeaderWriter<'a> {
    bytes: &'a mut [u8],
}

impl<'a> RawMsgHeaderWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn set_message_type(&mut self, typ: u16) -> Option<()> {
        let typ_bytes = typ.to_be_bytes();
        self.bytes.get_mut(0..2)?.copy_from_slice(&typ_bytes);
        Some(())
    }

    pub fn set_message_length(&mut self, len: u16) -> Option<()> {
        let len_bytes = len.to_be_bytes();
        self.bytes.get_mut(2..4)?.copy_from_slice(&len_bytes);
        Some(())
    }

    pub fn set_transaction_id(&mut self, tid: u128) -> Option<()> {
        let tid_bytes = tid.to_be_bytes();
        self.bytes.get_mut(4..20)?.copy_from_slice(&tid_bytes);
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: [u8; 20] = [
        0x00, 0x01,             // mock type        = 1
        0x00, 0x04,             // length           = 4 (header does not count)
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x03, // transaction id   = 3
    ];

    #[test]
    fn read_raw_message_header() {
        let r = RawMsgHeaderReader::new(&HEADER);

        assert_eq!(1, r.get_message_type().unwrap());
        assert_eq!(4, r.get_message_length().unwrap());
        assert_eq!(3u128, r.get_transaction_id().unwrap());
    }

    #[test]
    fn write_raw_message_header() {
        let mut buffer = [0u8; 20];

        let mut w = RawMsgHeaderWriter::new(&mut buffer);
        w.set_message_type(1).unwrap();
        w.set_message_length(4).unwrap();
        w.set_transaction_id(3).unwrap();

        assert_eq!(HEADER, buffer);
    }
}