#![no_std]

mod lib {
    pub trait EndianTo<T> {
        fn to_be(&self) -> T;
        fn to_le(&self) -> T;
        fn set_be(&mut self, val: T);
        fn set_le(&mut self, val: T);
    }

    pub trait EndianOf<T, U> {
        fn of_be(buf: &U) -> T;
        fn of_le(buf: &U) -> T;
    }

    macro_rules! impl_endian_traits {
    ($typ:ty) => {
        impl EndianTo<$typ> for [u8; core::mem::size_of::<$typ>()] {
            fn to_be(&self) -> $typ { <$typ>::from_be_bytes(*self) }
            fn to_le(&self) -> $typ { <$typ>::from_le_bytes(*self) }
            fn set_be(&mut self, val: $typ) { self.copy_from_slice(&val.to_be_bytes()); }
            fn set_le(&mut self, val: $typ) { self.copy_from_slice(&val.to_le_bytes()); }
        }

        impl EndianOf<$typ, [u8; core::mem::size_of::<$typ>()]> for $typ {
            fn of_be(buf: &[u8; core::mem::size_of::<$typ>()]) -> $typ { buf.to_be() }
            fn of_le(buf: &[u8; core::mem::size_of::<$typ>()]) -> $typ { buf.to_le() }
        }
    };
}

    #[cfg(feature = "u16")]
    impl_endian_traits!(u16);

    #[cfg(feature = "u32")]
    impl_endian_traits!(u32);

    #[cfg(feature = "u64")]
    impl_endian_traits!(u64);

    #[cfg(feature = "u128")]
    impl_endian_traits!(u128);

    #[cfg(feature = "i16")]
    impl_endian_traits!(i16);

    #[cfg(feature = "i32")]
    impl_endian_traits!(i32);

    #[cfg(feature = "i64")]
    impl_endian_traits!(i64);

    #[cfg(feature = "i128")]
    impl_endian_traits!(i128);

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn u16() {
            let buf = [1u8, 2];

            assert_eq!(0x0102 as u16, buf.to_be());
            assert_eq!(0x0201 as u16, buf.to_le());

            let mut buf = [0u8, 0];

            buf.set_be(0x0102 as u16);
            assert_eq!(&[1u8, 2], &buf);

            buf.set_le(0x0102 as u16);
            assert_eq!(&[2u8, 1], &buf);

            let buf = [1u8, 2];
            let opt = Some(&buf);
            let val = opt.map(u16::of_be).unwrap();
            assert_eq!(0x0102 as u16, val);
        }

    }
}

mod prelude {
    pub use super::lib::*;
}
