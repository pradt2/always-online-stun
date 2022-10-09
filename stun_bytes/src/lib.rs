use endianeer::prelude::*;

pub struct RawMsg<'a> {
    buf: &'a [u8],
}

impl<'a> RawMsg<'a> {
    fn from(buf: &'a [u8]) -> Self {
        let buf = buf.get(2..4)
            .map(carve)
            .flatten()
            .map(u16::of_be)
            .map(|len| 20 + len)
            .map(|len| buf.get(0..len as usize))
            .flatten()
            .unwrap_or(buf);
        Self { buf }
    }
    fn typ(&self) -> Option<&'a [u8; 2]> { self.buf.get(0..2).map(carve)? }
    fn len(&self) -> Option<&'a [u8; 2]> { self.buf.get(2..4).map(carve)? }
    fn tid(&self) -> Option<&'a [u8; 16]> { self.buf.get(4..20).map(carve)? }
    fn attr(&self) -> Option<&'a [u8]> { self.buf.get(20..) }
    fn attrs_iter(&self) -> RawIter {
        RawIter { buf: self.attr().unwrap_or(&[]) }
    }
}

pub struct RawAttr<'a> {
    buf: &'a [u8],
}

impl<'a> RawAttr<'a> {
    fn from(buf: &'a [u8]) -> Self { Self { buf } }
    fn typ(&self) -> Option<&'a [u8; 2]> { self.buf.get(0..2).map(carve)? }
    fn len(&self) -> Option<&'a [u8; 2]> { self.buf.get(2..4).map(carve)? }
    fn val(&self) -> Option<&'a [u8]> {
        self.len()
            .map(u16::of_be)
            .map(|len| len + 3 & !3)
            .map(|len| self.buf.get(4..4 + len as usize))
            .flatten()
            .or(self.buf.get(4..))
    }
}

#[derive(Copy, Clone)]
pub struct RawIter<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for RawIter<'a> {
    type Item = RawAttr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() { return None; }
        let attr = RawAttr::from(self.buf);
        self.buf = attr.val()
            .map(<[u8]>::len)
            .map(|len| 4 + len)
            .map(|len| self.buf.get(len..))
            .flatten()
            .unwrap_or(&[]);
        Some(attr)
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
        let msg = RawMsg::from(&MSG);

        assert_eq!(&MSG[0..2], msg.typ().unwrap());
        assert_eq!(&MSG[2..4], msg.len().unwrap());
        assert_eq!(&MSG[4..20], msg.tid().unwrap());
        assert_eq!(&MSG[20..28], msg.attr().unwrap());
        assert_eq!(1, msg.attrs_iter().count());

        let attr = msg.attrs_iter().next().unwrap();

        assert_eq!(&MSG[20..22], attr.typ().unwrap());
        assert_eq!(&MSG[22..24], attr.len().unwrap());
        assert_eq!(&MSG[24..28], attr.val().unwrap());
    }
}
