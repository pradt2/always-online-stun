#![no_std]

pub mod prelude {
    pub use super::lib::*;
}

mod lib {
    pub trait EndianTo<T> {
        fn to_be(&self) -> T;
        fn to_le(&self) -> T;
    }

    pub trait EndianSet<T> {
        fn set_be(&mut self, val: T);
        fn set_le(&mut self, val: T);
    }

    pub trait EndianOf<T, U> {
        fn of_be(buf: &U) -> T;
        fn of_be_mut(buf: &mut U) -> T;
        fn of_le(buf: &U) -> T;
        fn of_le_mut(buf: &mut U) -> T;
    }

    macro_rules! impl_endian_traits {
        ($typ:ty) => {
            impl EndianTo<$typ> for [u8; core::mem::size_of::<$typ>()] {
                #[inline]
                fn to_be(&self) -> $typ { <$typ>::from_be_bytes(*self) }

                #[inline]
                fn to_le(&self) -> $typ { <$typ>::from_le_bytes(*self) }
            }

            impl EndianSet<$typ> for [u8; core::mem::size_of::<$typ>()] {
                #[inline]
                fn set_be(&mut self, val: $typ) { self.copy_from_slice(&val.to_be_bytes()); }

                #[inline]
                fn set_le(&mut self, val: $typ) { self.copy_from_slice(&val.to_le_bytes()); }
            }

            impl EndianOf<$typ, [u8; core::mem::size_of::<$typ>()]> for $typ {
                #[inline]
                fn of_be(buf: &[u8; core::mem::size_of::<$typ>()]) -> $typ { <$typ>::from_be_bytes(*buf) }

                #[inline]
                fn of_be_mut(buf: &mut [u8; core::mem::size_of::<$typ>()]) -> $typ { <$typ>::from_be_bytes(*buf) }

                #[inline]
                fn of_le(buf: &[u8; core::mem::size_of::<$typ>()]) -> $typ { <$typ>::from_be_bytes(*buf) }

                #[inline]
                fn of_le_mut(buf: &mut [u8; core::mem::size_of::<$typ>()]) -> $typ { <$typ>::from_be_bytes(*buf) }
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

    #[cfg(feature = "carve")]
    pub trait Carve<T: Sized + Copy> {
        fn carve<const N: usize>(&self, idx: core::ops::Range<usize>) -> Option<&[T; N]>;
        fn carve_mut<const N: usize>(&mut self, idx: core::ops::Range<usize>) -> Option<&mut [T; N]>;
    }

    #[cfg(feature = "carve")]
    impl<T: Sized + Copy> Carve<T> for [T] {
        #[inline]
        fn carve<const N: usize>(&self, idx: core::ops::Range<usize>) -> Option<&[T; N]> {
            self.get(idx)?.try_into().ok()
        }

        #[inline]
        fn carve_mut<const N: usize>(&mut self, idx: core::ops::Range<usize>) -> Option<&mut [T; N]> {
            self.get_mut(idx)?.try_into().ok()
        }
    }

    #[cfg(feature = "carve")]
    pub trait Carved<T: Sized + Copy> {
        fn carved<const N: usize>(&self) -> Option<&[T; N]>;
        fn carved_mut<const N: usize>(&mut self) -> Option<&mut [T; N]>;
    }

    #[cfg(feature = "carve")]
    impl<T: Sized + Copy> Carved<T> for [T] {
        #[inline]
        fn carved<const N: usize>(&self) -> Option<&[T; N]> {
            self.try_into().ok()
        }

        #[inline]
        fn carved_mut<const N: usize>(&mut self) -> Option<&mut [T; N]> {
            self.try_into().ok()
        }
    }

    #[cfg(feature = "splice")]
    pub trait Splice<T: Sized + Copy> {
        fn splice<const N: usize>(&self) -> Option<(&[T; N], &[T])>;
        fn splice_mut<const N: usize>(&mut self) -> Option<(&mut [T; N], &mut [T])>;
    }

    #[cfg(feature = "splice")]
    impl<T: Sized + Copy> Splice<T> for [T] {
        #[inline]
        fn splice<const N: usize>(&self) -> Option<(&[T; N], &[T])> {
            splice(self)
        }

        #[inline]
        fn splice_mut<const N: usize>(&mut self) -> Option<(&mut [T; N], &mut [T])> {
            splice_mut(self)
        }
    }

    #[cfg(feature = "splice")]
    #[inline]
    pub fn splice<T: Sized + Copy, const N : usize>(val: &[T]) -> Option<(&[T; N], &[T])> {
        if val.len() < N { return None; }
        let (head, tail) = val.split_at(N);
        Some((head.try_into().ok()?, tail))
    }

    #[cfg(feature = "splice")]
    #[inline]
    pub fn splice_mut<T: Sized + Copy, const N : usize>(val: &mut [T]) -> Option<(&mut [T; N], &mut [T])> {
        if val.len() < N { return None; }
        let (head, tail) = val.split_at_mut(N);
        Some((head.try_into().ok()?, tail))
    }

    #[cfg(feature = "copy-from")]
    pub trait CopySafe<T: Sized + Copy, const N: usize> {
        fn copy_from(&mut self, src: &[T; N]);
    }

    #[cfg(feature = "copy-from")]
    impl<T: Sized + Copy, const N: usize> CopySafe<T, N> for [T; N] {
        #[inline]
        fn copy_from(&mut self, src: &Self) {
            self.copy_from_slice(src);
        }
    }

    #[cfg(feature = "ref-from")]
    pub trait RefFrom<T>: Sized {
        fn from_ref(_: &T) -> Self;
    }

    #[cfg(feature = "ref-from")]
    impl<T: Clone, U: From<T>> RefFrom<T> for U {
        #[inline]
        fn from_ref(val_ref: &T) -> Self {
            let val = val_ref.clone();
            Self::from(val)
        }
    }

    #[cfg(feature = "ref-from")]
    pub trait RefInto<T: Sized>: Clone {
        fn ref_into(&self) -> T;
    }

    #[cfg(feature = "ref-from")]
    impl<T, U: Into<T> + Clone> RefInto<T> for U {
        #[inline]
        fn ref_into(&self) -> T {
            let val = self.clone();
            val.into()
        }
    }

    #[cfg(feature = "arr-from")]
    pub trait ArrFrom<'a, T: 'a, const N: usize, U: 'a> {
        fn from_arr(_: &'a [T; N]) -> U;
    }

    #[cfg(feature = "arr-from")]
    impl<'a, T: 'a, const N: usize, U: From<&'a [T]> + 'a> ArrFrom<'a, T, N, U> for U {
        #[inline]
        fn from_arr(buf: &'a [T; N]) -> U {
            U::from(buf.as_slice())
        }
    }

    #[cfg(feature = "arr-from")]
    pub trait ArrFromMut<'a, T: 'a, const N: usize, U: 'a> {
        fn from_arr_mut(_: &'a mut [T; N]) -> U;
    }

    #[cfg(feature = "arr-from")]
    impl<'a, T: 'a, const N: usize, U: From<&'a mut [T]> + 'a> ArrFromMut<'a, T, N, U> for U {
        #[inline]
        fn from_arr_mut(buf: &'a mut [T; N]) -> U {
            U::from(buf.as_mut_slice())
        }
    }

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

        #[cfg(feature = "carve")]
        #[test]
        fn carve() {
            let mut buf = [0u8; 4];
            let val1 = [1u8; 4];

            fn copy(src: &[u8; 4], dst: &mut [u8; 4]) {
                dst.copy_from_slice(src);
            }

            copy(&val1, buf.carve_mut(0..4).unwrap());
            assert_eq!(&val1, buf.carve(0..4).unwrap());

            let val1 = [2u8; 4];

            copy(&val1, buf.carved_mut().unwrap());
            assert_eq!(&val1, buf.carved().unwrap());
        }

        #[cfg(feature = "splice")]
        #[test]
        fn splice_t() {
            let mut buf = [0u8; 2];

            let (head, tail) = buf.splice::<0>().unwrap();
            assert_eq!(0, head.len());
            assert_eq!(2, tail.len());

            let (head, tail) = buf.splice::<2>().unwrap();
            assert_eq!(2, head.len());
            assert_eq!(0, tail.len());

            let x = buf.splice::<4>();
            assert_eq!(None, x);

            let (head, tail) = buf.splice_mut::<0>().unwrap();
            assert_eq!(0, head.len());
            assert_eq!(2, tail.len());

            let (head, tail) = buf.splice_mut::<2>().unwrap();
            assert_eq!(2, head.len());
            assert_eq!(0, tail.len());

            if let Some((head, tail)) = Some(buf.as_slice()).map(splice::<_, 2>).unwrap() {
                assert_eq!(2, head.len());
                assert_eq!(0, tail.len());
            } else { assert!(false); }

            let x = buf.splice_mut::<4>();
            assert_eq!(None, x);
        }

        #[cfg(feature = "copy-from")]
        #[test]
        fn copy_from() {
            let mut buf = [0u8; 4];
            let val1 = [1u8; 4];

            buf.copy_from(&val1);
            assert_eq!(&buf, &val1);
        }

        #[cfg(feature = "arr-from")]
        #[test]
        fn arr_from() {
            struct BufRef<'a> {
                #[allow(dead_code)]
                buf: &'a [u8],
            }

            impl<'a> From<&'a [u8]> for BufRef<'a> {
                fn from(buf: &'a [u8]) -> Self {
                    Self {
                        buf
                    }
                }
            }

            let _ = BufRef::from_arr(&[0u8; 2]);

            struct BufRefMut<'a> {
                #[allow(dead_code)]
                buf: &'a mut [u8],
            }

            impl<'a> From<&'a mut [u8]> for BufRefMut<'a> {
                fn from(buf: &'a mut [u8]) -> Self {
                    Self {
                        buf
                    }
                }
            }

            let mut buf = [0u8; 2];
            let _ = BufRefMut::from_arr_mut(&mut buf);
        }
    }
}
