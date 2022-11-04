use endianeer::prelude::*;

pub struct Parser<'a> {
    buf: &'a [u8],
}

impl<'a> Parser<'a> {
    pub fn from(buf: &'a [u8]) -> Self {
        let buf = buf.carve(2..4)
            .map(u16::of_be)
            .map(|len| buf.get(0..(20 + len) as usize))
            .flatten()
            .unwrap_or(buf);
        Self { buf }
    }
    pub fn typ(&self) -> Option<&'a [u8; 2]> { self.buf.carve(0..2) }
    pub fn len(&self) -> Option<&'a [u8; 2]> { self.buf.carve(2..4) }
    pub fn tid(&self) -> Option<&'a [u8; 16]> { self.buf.carve(4..20) }
    pub fn attrs(&self) -> Option<&'a [u8]> { self.buf.get(20..) }
    pub fn attr_iter(&self) -> AttrIter {
        AttrIter { buf: self.attrs().unwrap_or(&[]) }
    }
}

pub struct Attr<'a> {
    buf: &'a [u8],
}

impl<'a> Attr<'a> {
    pub fn from(buf: &'a [u8]) -> Self { Self { buf } }
    pub fn typ(&self) -> Option<&'a [u8; 2]> { self.buf.carve(0..2) }
    pub fn len(&self) -> Option<&'a [u8; 2]> { self.buf.carve(2..4) }
    pub fn val(&self) -> Option<&'a [u8]> {
        self.len()
            .map(u16::of_be)
            .map(|len| len + 3 & !3)
            .map(|len| self.buf.get(4..4 + len as usize))
            .flatten()
            .or(self.buf.get(4..))
    }
}

#[derive(Copy, Clone)]
pub struct AttrIter<'a> {
    buf: &'a [u8],
}

impl<'a> AttrIter<'a> {
    pub fn from(buf: &'a [u8]) -> Self {
        Self {
            buf
        }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() { return None; }
        let attr = Attr::from(self.buf);
        self.buf = attr.val()
            .map(<[u8]>::len)
            .map(|len| 4 + len)
            .map(|len| self.buf.get(len..))
            .flatten()
            .unwrap_or(&[]);
        Some(attr)
    }
}

pub struct ParserMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> ParserMut<'a> {
    pub fn from(buf: &'a mut [u8]) -> Self {
        Self { buf }
    }
    pub fn typ(&mut self) -> Option<&mut [u8; 2]> {
        self.buf.carve_mut(0..2)
    }
    pub fn len(&mut self) -> Option<&mut [u8; 2]> {
        self.buf.carve_mut(2..4)
    }
    pub fn tid(&mut self) -> Option<&mut [u8; 16]> {
        self.buf.carve_mut(4..20)
    }
    pub fn attrs(&mut self) -> Option<&mut [u8]> {
        self.buf.get_mut(20..)
    }
    pub fn attr_iter(&mut self) -> AttrIterMut {
        AttrIterMut::from(self.attrs().unwrap_or(&mut []))
    }
    pub fn add_attr(&mut self, typ: &[u8; 2], len: &[u8; 2], val: &[u8]) -> Option<()> {
        let curr_len = self.len().map(u16::of_be_mut)? as usize;
        let (typ_buf, buf) = self.attrs()?.get_mut(curr_len..)?.splice_mut()?;
        let (len_buf, buf) = buf.splice_mut()?;
        let val_buf = buf.get_mut(..val.len())?;

        typ_buf.copy_from(typ);
        len_buf.copy_from(len);
        val_buf.copy_from_slice(val);

        self.len()?.set_be((curr_len + 4 + (val.len() + 3) & !3) as u16);
        Some(())
    }
}

pub struct AttrMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> AttrMut<'a> {
    pub fn from(buf: &'a mut [u8]) -> Self { Self { buf } }
    pub fn typ(&mut self) -> Option<&mut [u8; 2]> { self.buf.carve_mut(0..2) }
    pub fn len(&mut self) -> Option<&mut [u8; 2]> { self.buf.carve_mut(2..4) }
    pub fn val(&mut self) -> Option<&mut [u8]> {
        let len = (self.len().map(u16::of_be_mut)? + 3) & !3;
        let val = if self.buf.len() > (4 + len) as usize {
            self.buf.get_mut(4..4 + len as usize)
        } else {
            self.buf.get_mut(4..)
        };
        val
    }
}

pub struct AttrIterMut<'a> {
    buf: &'a mut [u8],
}

impl<'a> AttrIterMut<'a> {
    pub fn from(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
        }
    }
}

impl<'a> Iterator for AttrIterMut<'a> {
    type Item = AttrMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() { return None; }
        let mut tmp_attr = AttrMut::from(self.buf);
        let declared_val_size = tmp_attr.len().map(u16::of_be_mut)?;
        let total_attr_size = (4 + declared_val_size + 3) & !3;
        if self.buf.len() > total_attr_size as usize {
            let (head, tail) = self.buf.split_at_mut(total_attr_size as usize);
            self.buf = unsafe { core::mem::transmute(tail) };
            unsafe { core::mem::transmute(Some(AttrMut::from(head))) }
        } else {
            let attr = Some(AttrMut::from(self.buf));
            self.buf = &mut [];
            unsafe { core::mem::transmute(attr) }
        }
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
        let msg = Parser::from(&MSG);

        assert_eq!(&MSG[0..2], msg.typ().unwrap());
        assert_eq!(&MSG[2..4], msg.len().unwrap());
        assert_eq!(&MSG[4..20], msg.tid().unwrap());
        assert_eq!(&MSG[20..28], msg.attrs().unwrap());
        assert_eq!(1, msg.attr_iter().count());

        let attr = msg.attr_iter().next().unwrap();

        assert_eq!(&MSG[20..22], attr.typ().unwrap());
        assert_eq!(&MSG[22..24], attr.len().unwrap());
        assert_eq!(&MSG[24..28], attr.val().unwrap());
    }

    #[test]
    fn read_mut() {
        let mut buf = MSG.clone();
        let mut msg = ParserMut::from(&mut buf);

        assert_eq!(&MSG[0..2], msg.typ().unwrap());
        assert_eq!(&MSG[2..4], msg.len().unwrap());
        assert_eq!(&MSG[4..20], msg.tid().unwrap());
        assert_eq!(&MSG[20..28], msg.attrs().unwrap());
        assert_eq!(1, msg.attr_iter().count());

        let mut attr = msg.attr_iter().next().unwrap();

        assert_eq!(&MSG[20..22], attr.typ().unwrap());
        assert_eq!(&MSG[22..24], attr.len().unwrap());
        assert_eq!(&MSG[24..28], attr.val().unwrap());
    }

    #[test]
    fn write() {
        let mut buf = [0u8; MSG.len()];
        let mut msg = ParserMut::from(&mut buf);

        msg.typ().unwrap().copy_from(MSG.carve(0..2).unwrap());
        // msg.len().unwrap().copy_from(MSG.carve(2..4).unwrap()); // length should be updated automatically
        msg.tid().unwrap().copy_from(MSG.carve(4..20).unwrap());
        msg.add_attr(MSG.carve(20..22).unwrap(), MSG.carve(22..24).unwrap(), MSG.get(24..28).unwrap());

        assert_eq!(&MSG, &buf);
    }
}
