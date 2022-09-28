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

    pub fn get_magic_cookie(&self) -> Option<u32> {
        self.bytes.get(4..8)
            .map(|b| b.try_into().unwrap())
            .map(|b| u32::from_be_bytes(b))
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

    pub fn set_magic_cookie(&mut self, magic_cookie: u32) -> Option<()> {
        let cookie_bytes = magic_cookie.to_be_bytes();
        self.bytes.get_mut(4..8)?.copy_from_slice(&cookie_bytes);
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
    use core::any::Any;
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

    struct U16BeBufStruct<'a>(&'a mut [u8; 2]);

    type U16BeBuf<'a> = impl U16BeBufTrait<'a>;
    type U16BeBufMut<'a> = impl U16BeBufTrait<'a> + U16BeBufMutTrait<'a>;

    trait U16BeBufTrait<'a> : Sized {
        fn new(bytes: &'a [u8; 2]) -> U16BeBuf<'a> {
            #[allow(mutable_transmutes)]
            unsafe {
                U16BeBufStruct(core::mem::transmute(bytes))
            }
        }

        fn get(&self) -> u16;
        fn as_slice(&'a self) -> &'a [u8; 2];
    }

    impl<'a> U16BeBufTrait<'a> for U16BeBufStruct<'a> {
        fn get(&self) -> u16 {
            u16::from_be_bytes(*self.0)
        }

        fn as_slice(&'a self) -> &'a [u8; 2] {
            self.0
        }
    }

    trait U16BeBufMutTrait<'a> : Sized {
        fn new(bytes: &'a mut [u8; 2]) -> U16BeBufMut<'a> {
            U16BeBufStruct(bytes)
        }

        fn set(&mut self, val: u16);
        fn as_slice(&'a mut self) -> &'a mut [u8; 2];
    }

    impl<'a> U16BeBufMutTrait<'a> for U16BeBufStruct<'a> {
        fn set(&mut self, val: u16) {
            self.0.copy_from_slice(&val.to_be_bytes())
        }

        fn as_slice(&'a mut self) -> &'a mut [u8; 2] {
            self.0
        }
    }

    struct RawStunBufStruct<'a>(&'a mut [u8]);

    type RawStunBuf<'a> = impl RawStunBufTrait<'a>;
    type RawStunBufMut<'a> = impl RawStunBufMutTrait<'a>;

    trait RawStunBufTrait<'a> : Sized {
        fn new(bytes: &'a [u8]) -> RawStunBuf<'a> {
            #[allow(mutable_transmutes)]
            unsafe {
                RawStunBufStruct(core::mem::transmute(bytes))
            }
        }

        fn typ(&'a self) -> U16BeBuf<'a>;
    }

    impl<'a> RawStunBufTrait<'a> for RawStunBufStruct<'a> {
        fn typ(&'a self) -> U16BeBuf<'a> {
            let ref1 = (&self.0[0..2]).try_into().unwrap();
            U16BeBuf::new(ref1)
        }
    }

    trait RawStunBufMutTrait<'a> : Sized {
        fn new(bytes: &'a mut [u8]) -> RawStunBufMut<'a> {
            RawStunBufStruct(bytes)
        }

        fn typ(&'a mut self) -> U16BeBufMut<'a>;
    }

    impl<'a> RawStunBufMutTrait<'a> for RawStunBufStruct<'a> {
        fn typ(&'a mut self) -> U16BeBufMut<'a> {
            <U16BeBufMut<'_> as U16BeBufMutTrait>::new((&mut self.0[0..2]).try_into().unwrap())
        }
    }

    #[test]
    fn test1() {
        let mut buf = [0u8; 12];

        let r = RawStunBuf::new(&buf);

        r.type_id();

        // let mut r = RawStunBufMut::from(buf.as_mut_slice());
        //
        // r.typ().set(16);

        // let mut r = RawStunBufMutTrait::from(buf.as_mut());

        // r.typ().set(16);
    }
}
