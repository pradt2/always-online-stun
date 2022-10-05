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
    pub fn as_slice(&self) -> &[u8; core::mem::size_of::<Self>()] {
        unsafe {
            core::mem::transmute(&self)
        }
    }
    pub fn set(&mut self, val: u16) { self.0 = val.to_be() }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(packed, C)]
pub struct u32be(u32);

impl u32be {
    pub fn from<'a>(bytes: &[u8; core::mem::size_of::<Self>()]) -> &'a Self {
        unsafe {  core::mem::transmute(bytes) }
    }

    pub fn from_slice<'a>(bytes: &'a [u8]) -> Option<&'a Self> {
        bytes.get(0..core::mem::size_of::<Self>())
            .map(|bytes| bytes.try_into().ok())?
            .map(u32be::from)
    }

    pub fn get(&self) -> u32 { self.0.to_be() }
    pub fn as_slice(&self) -> &[u8; core::mem::size_of::<Self>()] {
        unsafe {
            core::mem::transmute(&self)
        }
    }
    pub fn set(&mut self, val: u32) { self.0 = val.to_be() }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(packed, C)]
pub struct u64be(u64);

impl u64be {
    pub const ZERO: u64be = u64be(0);

    pub fn from<'a>(bytes: &[u8; core::mem::size_of::<Self>()]) -> &'a Self {
        unsafe {  core::mem::transmute(bytes) }
    }

    pub fn from_slice<'a>(bytes: &'a [u8]) -> Option<&'a Self> {
        bytes.get(0..core::mem::size_of::<Self>())
            .map(|bytes| bytes.try_into().ok())?
            .map(u64be::from)
    }

    pub fn get(&self) -> u64 { self.0.to_be() }
    pub fn as_slice(&self) -> &[u8; core::mem::size_of::<Self>()] {
        unsafe {
            core::mem::transmute(&self)
        }
    }
    pub fn set(&mut self, val: u64) { self.0 = val.to_be() }
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
    pub fn as_slice(&self) -> &[u8; core::mem::size_of::<Self>()] {
        unsafe {
            core::mem::transmute(&self)
        }
    }
    pub fn set(&mut self, val: u128) { self.0 = val.to_be() }
}
