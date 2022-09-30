#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(packed, C)]
pub struct u16be(u16);

impl u16be {
    fn get(&self) -> u16 { self.0.to_be() }
    fn set(&mut self, val: u16) { self.0 = val.to_be() }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(packed, C)]
pub struct u128be(u128);

impl u128be {
    fn get(&self) -> u128 { self.0.to_be() }
    fn set(&mut self, val: u128) { self.0 = val.to_be() }
}

#[repr(packed, C)]
pub struct Msg {
    pub typ: u16be,
    pub len: u16be,
    pub tid: u128be,
}

impl Msg {
    pub fn new<'a>(bytes: &'a [u8]) -> Result<&'a Msg, ()> {
        Self::assert_mem_safety(bytes).map(|_| unsafe { core::mem::transmute(bytes.as_ptr()) })
    }

    pub fn new_mut<'a>(bytes: &'a mut [u8]) -> Result<&'a mut Msg, ()> {
        Self::assert_mem_safety(bytes).map(|_| unsafe { core::mem::transmute(bytes.as_ptr()) })
    }

    pub fn attrs(&self) -> &[u8] {
        unsafe {
            let data_ptr: *const u8 = core::mem::transmute(self);
            let data_ptr = data_ptr.offset(core::mem::size_of::<Self>() as isize);
            core::slice::from_raw_parts(data_ptr, self.len.get() as usize)
        }
    }

    pub fn attrs_mut(&mut self) -> &mut [u8] {
        unsafe {
            let len = self.len.clone().get() as usize;
            let data_ptr: *mut u8 = core::mem::transmute(self);
            let data_ptr = data_ptr.offset(core::mem::size_of::<Self>() as isize);
            core::slice::from_raw_parts_mut(data_ptr, len)
        }
    }

    pub fn attrs_iter(&self) -> AttrIterator {
        AttrIterator::new(self.attrs())
    }

    pub fn attrs_iter_mut(&mut self) -> AttrMutIterator {
        AttrMutIterator::new(self.attrs_mut())
    }

    fn assert_mem_safety(bytes: &[u8]) -> Result<(), ()> {
        let declared_len = Self::get_padded_value_len(bytes)? as usize;
        if bytes.len() >= declared_len + core::mem::size_of::<Self>() { Ok(()) } else { Err(()) }
    }

    fn get_padded_value_len(bytes: &[u8]) -> Result<u16, ()> {
        let len_bytes: &[u8; 2] = bytes.get(2..4)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        let len = u16::from_be_bytes(*len_bytes); // padding should be included alrady
        Ok(len)
    }
}

#[repr(packed, C)]
pub struct Attr {
    pub typ: u16be,
    pub len: u16be,
}

impl Attr {
    pub fn new<'a>(bytes: &[u8]) -> Option<&'a Attr> {
        Self::assert_mem_safety(bytes).ok()
            .map(|_| unsafe { core::mem::transmute(bytes.as_ptr()) })
    }

    pub fn new_mut<'a>(bytes: &'a mut [u8]) -> Option<&'a mut Attr> {
        Self::assert_mem_safety(bytes).ok()
            .map(|_| unsafe { core::mem::transmute(bytes.as_mut_ptr()) })
    }

    pub fn val(&self) -> &[u8] {
        unsafe {
            let data_ptr: *mut u8 = core::mem::transmute(self);
            let data_ptr = data_ptr.offset(core::mem::size_of::<Self>() as isize);
            core::slice::from_raw_parts(data_ptr, (self.len.get() as usize + 3) & !3)
        }
    }

    pub fn val_mut(&mut self) -> &mut [u8] {
        unsafe {
            let len = self.len.get() as usize;
            let data_ptr: *mut u8 = core::mem::transmute(self);
            let data_ptr = data_ptr.offset(core::mem::size_of::<Self>() as isize);
            core::slice::from_raw_parts_mut(data_ptr, (len + 3) & !3)
        }
    }

    fn assert_mem_safety(bytes: &[u8]) -> Result<(), ()> {
        let declared_len = Self::get_padded_value_len(bytes)? as usize;
        if bytes.len() >= declared_len + core::mem::size_of::<Self>() { Ok(()) } else { Err(()) }
    }

    fn get_padded_value_len(bytes: &[u8]) -> Result<u16, ()> {
        let len_bytes: &[u8; 2] = bytes.get(2..4)
            .ok_or(())?
            .try_into()
            .map_err(|_| ())?;
        let len = (u16::from_be_bytes(*len_bytes) + 3) & !3; // include padding
        Ok(len)
    }
}

pub struct AttrIterator<'a> {
    attr_bytes: &'a [u8],
}

impl<'a> AttrIterator<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            attr_bytes: bytes,
        }
    }
}

impl<'a> Iterator for AttrIterator<'a> {
    type Item = &'a Attr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.attr_bytes.is_empty() { return None; }

        let attr = Attr::new(self.attr_bytes)?;
        let attr_len = 4 + attr.val().len();
        self.attr_bytes = self.attr_bytes.get(attr_len..)?;

        Some(attr)
    }
}

pub struct AttrMutIterator<'a> {
    attr_bytes: &'a mut [u8],
    cursor: usize,
}

impl<'a> AttrMutIterator<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            attr_bytes: bytes,
            cursor: 0,
        }
    }
}

impl<'a> Iterator for AttrMutIterator<'a> {
    type Item = &'a mut Attr;

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.attr_bytes.get_mut(self.cursor..)?;
        if bytes.is_empty() { return None; }

        let next_attr_len = core::mem::size_of::<Attr>() + Attr::get_padded_value_len(bytes).ok()? as usize;
        if next_attr_len > bytes.len() { return None; }

        let attr = Attr::new_mut(bytes)?;
        self.cursor += next_attr_len;

        // I copied this code from Stack Overflow without paying attention to
        // the prose which described why this code is actually safe.
        // https://stackoverflow.com/questions/27118398/simple-as-possible-example-of-returning-a-mutable-reference-from-your-own-iterat
        unsafe { Some(&mut *(attr as *mut Attr)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: [u8; 28] = [
        0x00, 0x01,                     // type: Binding Request
        0x00, 0x08,                     // length: 8 (header does not count)
        0x21, 0x12, 0xA4, 0x42,         // magic cookie
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,         // transaction id (16 bytes total incl. magic cookie)
        0x00, 0x03,                     // type: ChangeRequest
        0x00, 0x04,                     // length: 4 (only value bytes count)
        0x00, 0x00, 0x00, 0x40 | 0x20,  // change both ip and port
    ];

    #[test]
    fn read() {
        let msg = Msg::new(&MSG).unwrap();

        assert_eq!(0x0001, msg.typ.get());
        assert_eq!(0x0008, msg.len.get());
        assert_eq!(0x2112A442_00000000_00000000_00000001, msg.tid.get());
        assert_eq!(&MSG[20..28], msg.attrs());
        assert_eq!(1, msg.attrs_iter().count());

        let attr = msg.attrs_iter().next().unwrap();

        assert_eq!(0x0003, attr.typ.get());
        assert_eq!(0x0004, attr.len.get());
        assert_eq!(&MSG[24..28], attr.val());
    }

    #[test]
    fn read_mut() {
        let mut buf = MSG.clone();
        let msg = Msg::new_mut(&mut buf).unwrap();

        assert_eq!(0x0001, msg.typ.get());
        assert_eq!(0x0008, msg.len.get());
        assert_eq!(0x2112A442_00000000_00000000_00000001, msg.tid.get());
        assert_eq!(&MSG[20..28], msg.attrs());
        assert_eq!(1, msg.attrs_iter().count());

        let attr = msg.attrs_iter().next().unwrap();

        assert_eq!(0x0003, attr.typ.get());
        assert_eq!(0x0004, attr.len.get());
        assert_eq!(&MSG[24..28], attr.val());
    }

    #[test]
    fn write_mut() {
        let mut buf = MSG.clone();
        let msg = Msg::new_mut(&mut buf).unwrap();

        msg.typ.set(0x1000);
        assert_eq!(0x1000, msg.typ.get());

        assert_eq!(0x0008, msg.len.get());

        msg.tid.set(0x2112A442_10000002_30000004_50000006);
        assert_eq!(0x2112A442_10000002_30000004_50000006, msg.tid.get());

        let attr = msg.attrs_iter_mut().next().unwrap();
        attr.val_mut().copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(&[1, 2, 3, 4], attr.val_mut());

        assert_eq!(1, msg.attrs_iter().count());
    }
}