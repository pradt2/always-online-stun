struct U16BeBufStruct<'a>(&'a mut [u8; 2]);

pub type U16BeBuf<'a> = impl U16BeBufTrait<'a> + U16BeBufConstructorTrait<'a>;

pub trait U16BeBufTrait<'a> : Sized {
    fn get(&self) -> u16;
    fn as_slice(&self) -> &[u8; 2];
}

impl<'a> U16BeBufTrait<'a> for U16BeBufStruct<'a> {
    fn get(&self) -> u16 {
        u16::from_be_bytes(*self.0)
    }
    fn as_slice(&self) -> &[u8; 2] {
        self.0
    }
}

pub trait U16BeBufConstructorTrait<'a> : Sized {
    fn new(bytes: &'a [u8; 2]) -> U16BeBuf<'a> {
        #[allow(mutable_transmutes)]
        unsafe {
            U16BeBufStruct(core::mem::transmute(bytes))
        }
    }
}

impl<'a> U16BeBufConstructorTrait<'a> for U16BeBufStruct<'a> {}

type U16BeBufMut<'a> = impl U16BeBufTrait<'a> + U16BeBufMutTrait<'a> + U16BeBufMutConstructorTrait<'a>;

trait U16BeBufMutTrait<'a> : Sized {
    fn set(&mut self, val: u16);
    fn as_slice(&mut self) -> &mut [u8; 2];
    fn release(self) -> &'a mut [u8; 2];
}

impl<'a> U16BeBufMutTrait<'a> for U16BeBufStruct<'a> {
    fn set(&mut self, val: u16) {
        self.0.copy_from_slice(&val.to_be_bytes())
    }
    fn as_slice(&mut self) -> &mut [u8; 2] {
        self.0
    }
    fn release(self) -> &'a mut [u8; 2] { self.0 }
}

trait U16BeBufMutConstructorTrait<'a> : Sized {
    fn new(bytes: &'a mut [u8; 2]) -> U16BeBufMut<'a> {
        U16BeBufStruct(bytes)
    }
}

impl<'a> U16BeBufMutConstructorTrait<'a> for U16BeBufStruct<'a> {}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buf() {
        let bytes = [1u8, 2];
        let buf = U16BeBuf::new(&bytes);

        assert_eq!(0x0102, buf.get());
        assert_eq!(&bytes, buf.as_slice());

        let buf_ref = &buf;

        assert_eq!(0x0102, buf_ref.get());
        assert_eq!(&bytes, buf_ref.as_slice());
    }

    // #[test]
    // fn test_buf_mut() {
    //     let mut bytes = [1u8, 2];
    //     let mut buf = U16BeBufMut::new(&mut bytes);
    //
    //     assert_eq!(0x0102, buf.get());
    //     assert_eq!(&[1u8, 2], buf.as_slice());
    //
    //     buf.set(0x0304);
    //     assert_eq!(0x0304, buf.get());
    //     assert_eq!(&[3u8, 4], buf.as_slice());
    //
    //     let buf_ref = &mut buf;
    //
    //     buf_ref.set(0x0506);
    //     assert_eq!(0x0506, buf_ref.get());
    //     assert_eq!(&[5u8, 6], buf_ref.as_slice());
    //
    //
    //     // let buf_ref_slice = buf_ref.as_slice();
    //     // buf_ref_slice.copy_from_slice(&[7u8, 8]);
    //
    //     // drop(buf);
    //     assert_eq!(&[7u8, 8], &bytes);
    // }


    // struct ImmutHolder<'a> {
    //     bytes: &'a [u8]
    // }
    //
    // type ImmutHolderType<'a> = impl ImmutHolderTrait<'a>;
    //
    // trait ImmutHolderTrait<'a> {
    //     fn new(bytes: &'a [u8]) -> ImmutHolderType<'a> { ImmutHolder{bytes} }
    //     fn get(&self) -> &'a [u8];
    // }
    //
    // impl<'a> ImmutHolderTrait<'a> for ImmutHolder<'a> {
    //     fn get(&self) -> &'a [u8] { self.bytes }
    // }
    //
    // #[test]
    // fn test_immut_holder() {
    //     let b = [0u8; 12].as_slice();
    //
    //     let h = ImmutHolder{bytes: b};
    //     let h = ImmutHolderType::new(b);
    //
    //     let br = h.get();
    //
    //     assert_eq!(0, br[0]);
    // }

    struct MutHolder<'a> {
        bytes: &'a mut [u8]
    }

    type MutHolderType<'a> = impl MutHolderMutTrait<'a>;

    trait MutHolderMutTrait<'a> {
        fn new(bytes: &'a mut [u8]) -> MutHolderType<'a> {
            MutHolder{bytes}
        }
        fn get(&mut self) -> &mut [u8];
        fn release(self) -> &'a mut [u8];
    }

    impl<'a> MutHolderMutTrait<'a> for MutHolder<'a> {
        fn get(&mut self) -> &mut [u8] { self.bytes }
        fn release(self) -> &'a mut [u8] { self.bytes }
    }

    #[test]
    fn test_mut_holder() {
        let mut b = [0u8; 12];
        let b = b.as_mut_slice();

        let mut h = MutHolder{bytes: b};
        // let mut h = MutHolderType::new(b);

        // let br = h.get();
        assert_eq!(0, b[0]);
    }

}
