use endianeer::prelude::*;

pub struct RawMsg<'a> {
    buf: &'a [u8],
}

impl<'a> RawMsg<'a> {
    pub fn from(buf: &'a [u8]) -> Self {
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
    pub fn typ(&self) -> Option<&'a [u8; 2]> { self.buf.get(0..2).map(carve)? }
    pub fn len(&self) -> Option<&'a [u8; 2]> { self.buf.get(2..4).map(carve)? }
    pub fn tid(&self) -> Option<&'a [u8; 16]> { self.buf.get(4..20).map(carve)? }
    pub fn attrs(&self) -> Option<&'a [u8]> { self.buf.get(20..) }
    pub fn attr_iter(&self) -> RawIter {
        RawIter { buf: self.attrs().unwrap_or(&[]) }
    }
}

pub struct RawAttr<'a> {
    buf: &'a [u8],
}

impl<'a> RawAttr<'a> {
    pub fn from(buf: &'a [u8]) -> Self { Self { buf } }
    pub fn typ(&self) -> Option<&'a [u8; 2]> { self.buf.get(0..2).map(carve)? }
    pub fn len(&self) -> Option<&'a [u8; 2]> { self.buf.get(2..4).map(carve)? }
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
pub struct RawIter<'a> {
    buf: &'a [u8],
}

impl<'a> RawIter<'a> {
    pub fn from(buf: &'a [u8]) -> Self {
        Self {
            buf
        }
    }
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

struct RawMsgMut<'a> {
    buf: &'a mut [u8],
    idx: usize,
}

impl<'a> RawMsgMut<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, idx: 20 }
    }

    pub fn typ(&mut self) -> Option<&mut [u8; 2]> {
        self.buf.get_mut(0..2).map(carve_mut)?
    }

    pub fn len(&mut self) -> Option<&mut [u8; 2]> {
        self.buf.get_mut(2..4).map(carve_mut)?
    }

    pub fn tid(&mut self) -> Option<&mut [u8; 16]> {
        self.buf.get_mut(4..20).map(carve_mut)?
    }

    pub fn attrs(&mut self) -> Option<&mut [u8]> {
        self.buf.get_mut(20..)
    }

    pub fn attr_add<T: FnOnce(&mut [u8; 2], &mut [u8; 2], &mut [u8]) -> Option<usize>>(&mut self, f: T) -> Option<()> {
        let (typ, bytes) = split_at_mut(self.buf.get_mut(self.idx..)?);
        let (len, val) = split_at_mut(bytes);

        let used = f(typ?, len?, val)?;

        self.idx += (4 + used + 3) & !3; // include padding

        Some(())
    }

    pub fn size(&self) -> usize { self.idx }
}

fn split_at_mut<const N: usize>(bytes: &mut [u8]) -> (Option<&mut [u8; N]>, &mut [u8]) {
    if N > bytes.len() {
        return (None, bytes);
    }
    let (chunk, rest) = bytes.split_at_mut(N);
    (chunk.try_into().ok(), rest)
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
        assert_eq!(&MSG[20..28], msg.attrs().unwrap());
        assert_eq!(1, msg.attr_iter().count());

        let attr = msg.attr_iter().next().unwrap();

        assert_eq!(&MSG[20..22], attr.typ().unwrap());
        assert_eq!(&MSG[22..24], attr.len().unwrap());
        assert_eq!(&MSG[24..28], attr.val().unwrap());
    }

    #[test]
    fn read_mut() {
        let mut buf = [0u8; 28];
        let mut msg = RawMsgMut::new(&mut buf);

        msg.typ().unwrap().set_be(0x0001);
        msg.len().unwrap().set_be(0x0008);
        msg.tid().unwrap().set_be(0x2112A442u128 << 96 | 0x1u128);
        msg.attr_add(|typ, len, val| {
            typ.set_be(0x0003);
            len.set_be(0x0004);
            val.get_mut(0..4).map(carve_mut)??.set_be(0x40u32 | 0x20u32);
            Some(4)
        }).unwrap();

        assert_eq!(28, msg.size());
        assert_eq!(&MSG[20..], msg.attrs().unwrap());

        assert_eq!(&MSG, &buf);
    }
}
