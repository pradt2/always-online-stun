use crate::endian::{u16be, u128be};

struct Msg<'a> {
    typ: &'a u16be,
    len: &'a u16be,
    tid: &'a u128be,
    attrs: &'a [u8],
}

impl<'a> Msg<'a> {
    fn from(bytes: &'a [u8]) -> Option<Self> {
        let len = bytes.get(2..4).map(u16be::from_slice)??;
        Some(Self {
            typ: bytes.get(0..2).map(u16be::from_slice)??,
            len: len,
            tid: bytes.get(4..20).map(u128be::from_slice)??,
            attrs: bytes.get(20..20 + len.get() as usize).or(bytes.get(20..))?, // do not read over what is specified by length
        })
    }

    fn attrs_iter(&self) -> Iter {
        Iter {bytes: self.attrs}
    }
}

struct Attr<'a> {
    typ: &'a u16be,
    len: &'a u16be,
    val: &'a [u8],
}

impl<'a> Attr<'a> {
    fn from(bytes: &'a [u8]) -> Option<Self> {
        let len = bytes.get(2..4).map(u16be::from_slice)??;
        Some(Self {
            typ: bytes.get(0..2).map(u16be::from_slice)??,
            len: len,
            val: bytes.get(4..4 + (len.get() as usize + 3) & !3).or(bytes.get(4..))?, // get val up to and including padding bytes
        })
    }
}

struct Iter<'a> {
    bytes: &'a [u8],
}

impl<'a> Iterator for Iter<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() { return None; }
        if let Some(attr) = Attr::from(self.bytes) {
            self.bytes = self.bytes.get(4 + attr.val.len()..)?;
            Some(attr)
        } else {
            None
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
        let msg = Msg::from(&MSG).unwrap();

        assert_eq!(0x0001, msg.typ.get());
        assert_eq!(0x0008, msg.len.get());
        assert_eq!(0x2112A442_00000000_00000000_00000001, msg.tid.get());
        assert_eq!(&MSG[20..28], msg.attrs);
        assert_eq!(1, msg.attrs_iter().count());

        let attr = msg.attrs_iter().next().unwrap();

        assert_eq!(0x0003, attr.typ.get());
        assert_eq!(0x0004, attr.len.get());
        assert_eq!(&MSG[24..28], attr.val);
    }
}