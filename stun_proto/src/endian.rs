#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(packed, C)]
pub struct u16be(u16);

impl u16be {
    pub fn from<'a>(bytes: &[u8; core::mem::size_of::<Self>()]) -> &'a Self {
        unsafe {  core::mem::transmute(bytes) }
    }

    pub fn from_slice<'a>(bytes: &'a [u8]) -> Option<&'a Self> {
        bytes.get(0..core::mem::size_of::<Self>())
            .map(|bytes| bytes.try_into().ok())?
            .map(u16be::from)
    }

    pub fn get(&self) -> u16 { self.0.to_be() }
    pub fn set(&mut self, val: u16) { self.0 = val.to_be() }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(packed, C)]
pub struct u128be(u128);

impl u128be {
    pub fn from<'a>(bytes: &[u8; core::mem::size_of::<Self>()]) -> &'a Self {
        unsafe {
            core::mem::transmute(bytes)
        }
    }

    pub fn from_slice<'a>(bytes: &'a [u8]) -> Option<&'a Self> {
        bytes.get(0..core::mem::size_of::<Self>())
            .map(|bytes| bytes.try_into().ok())?
            .map(u128be::from)
    }

    pub fn get(&self) -> u128 { self.0.to_be() }
    pub fn set(&mut self, val: u128) { self.0 = val.to_be() }
}
