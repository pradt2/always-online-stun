pub trait EndianBuf<T> {
    fn be(&self) -> T;
    fn le(&self) -> T;
    fn be_set(&mut self, val: T);
    fn le_set(&mut self, val: T);
}

macro_rules! impl_endian_buf {
    ($typ:ty) => {
        impl EndianBuf<typ> for [u8; core::mem::size_of::<typ>] {
            fn be(&self) -> typ { typ::from_be_bytes(*self) }
            fn le(&self) -> typ { typ::from_le_bytes(*self) }
            fn be_set(&mut self, val: typ) { self.copy_from_slice(&val.to_be_bytes()); }
            fn le_set(&mut self, val: typ) { self.copy_from_slice(&val.to_le_bytes()); }
        }
    };
}

#[cfg(feature = "u16")]
impl_endian_buf!(u16);

#[cfg(feature = "u32")]
impl_endian_buf!(u32);

#[cfg(feature = "u64")]
impl_endian_buf!(u64);

#[cfg(feature = "u128")]
impl_endian_buf!(u128);

#[cfg(feature = "i16")]
impl_endian_buf!(i16);

#[cfg(feature = "i32")]
impl_endian_buf!(i32);

#[cfg(feature = "i64")]
impl_endian_buf!(i64);

#[cfg(feature = "i128")]
impl_endian_buf!(i128);