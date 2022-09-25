pub struct AssertedRawReader<'a> {
    pub typ: &'a [u8; 2],
    pub len: &'a [u8; 2],
    pub tid: &'a [u8; 16],
    pub attrs: &'a [u8],
    attr_iter: AssertedRawAttributesReaderIterator<'a>,
}

impl<'a> AssertedRawReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let reader = RawReader::new(bytes);

        let attr_iter = AssertedRawAttributesReaderIterator::new(reader.attrs?)?;

        Some(Self {
            typ: reader.typ?,
            len: reader.len?,
            tid: reader.tid?,
            attrs: reader.attrs?,
            attr_iter,
        })
    }

    pub fn attrs(&self) -> AssertedRawAttributesReaderIterator {
        self.attr_iter.clone()
    }
}

pub struct AssertedRawAttributeReader<'a> {
    pub typ: &'a [u8; 2],
    pub len: &'a [u8; 2],
    pub val: &'a [u8],
}

impl<'a> AssertedRawAttributeReader<'a> {
    fn new(reader: &RawAttributeReader<'a>) -> Option<Self> {
        let attr_value_with_padding = reader.val?;

        if attr_value_with_padding.len() != get_nearest_greater_multiple_of_4(attr_value_with_padding.len()) {
            return None;
        }

        if u16::from_be_bytes(*reader.len?) as usize > attr_value_with_padding.len() {
            return None;
        }

        Some(Self {
            typ: reader.typ?,
            len: reader.len?,
            val: attr_value_with_padding,
        })
    }
}

#[derive(Clone)]
pub struct AssertedRawAttributesReaderIterator<'a> {
    raw_iter: RawAttributesReaderIterator<'a>,
}

impl<'a> AssertedRawAttributesReaderIterator<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        let raw_reader_count = RawAttributesReaderIterator::new(bytes).count();
        let asserted_reader_count = AssertedRawAttributesReaderIterator { raw_iter: RawAttributesReaderIterator::new(bytes) }.count();
        if raw_reader_count != asserted_reader_count { return None; }

        Some(Self {
            raw_iter: RawAttributesReaderIterator::new(bytes)
        })
    }
}

impl<'a> Iterator for AssertedRawAttributesReaderIterator<'a> {
    type Item = AssertedRawAttributeReader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.raw_iter.next()?.asserted()
    }
}

pub struct RawReader<'a> {
    pub typ: Option<&'a [u8; 2]>,
    pub len: Option<&'a [u8; 2]>,
    pub tid: Option<&'a [u8; 16]>,
    pub attrs: Option<&'a [u8]>,
    attr_iter: RawAttributesReaderIterator<'a>,
}

impl<'a> RawReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            typ: bytes.get(0..2).map(|s| s.try_into().ok()).flatten(),
            len: bytes.get(2..4).map(|s| s.try_into().ok()).flatten(),
            tid: bytes.get(4..20).map(|s| s.try_into().ok()).flatten(),
            attrs: bytes.get(20..),
            attr_iter: RawAttributesReaderIterator::new(bytes.get(20..).unwrap_or(&[])),
        }
    }

    pub fn attrs(&self) -> RawAttributesReaderIterator {
        self.attr_iter.clone()
    }
}

pub struct RawAttributeReader<'a> {
    pub typ: Option<&'a [u8; 2]>,
    pub len: Option<&'a [u8; 2]>,
    pub val: Option<&'a [u8]>,
}

impl<'a> RawAttributeReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            typ: bytes.get(0..2).map(|s| s.try_into().ok()).flatten(),
            len: bytes.get(2..4).map(|s| s.try_into().ok()).flatten(),
            val: bytes.get(4..),
        }
    }

    pub fn asserted(&self) -> Option<AssertedRawAttributeReader<'a>> {
        AssertedRawAttributeReader::new(self)
    }
}

#[derive(Clone)]
pub struct RawAttributesReaderIterator<'a> {
    bytes: &'a [u8],
}

impl<'a> RawAttributesReaderIterator<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    fn asserted(&self) -> Option<AssertedRawAttributesReaderIterator> {
        AssertedRawAttributesReaderIterator::new(self.bytes)
    }
}

impl<'a> Iterator for RawAttributesReaderIterator<'a> {
    type Item = RawAttributeReader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() == 0 { return None; }

        let declared_value_size = read_u16_be(self.bytes, 2);

        match declared_value_size {
            None => {
                let reader = RawAttributeReader::new(self.bytes);
                self.bytes = &[];
                Some(reader)
            }
            Some(declared_value_size) => match self.bytes.get(0..4 + get_nearest_greater_multiple_of_4(declared_value_size as usize)) {
                None => {
                    let reader = RawAttributeReader::new(self.bytes);
                    self.bytes = &[];
                    Some(reader)
                }
                Some(attr_bytes_incl_padding) => {
                    let reader = RawAttributeReader::new(attr_bytes_incl_padding);
                    match self.bytes.get(attr_bytes_incl_padding.len()..) {
                        None => self.bytes = &[],
                        Some(next_argument_bytes) => self.bytes = next_argument_bytes,
                    };
                    Some(reader)
                }
            }
        }
    }
}

pub struct AssertedRawWriter<'a> {
    pub typ: &'a mut [u8; 2],
    pub len: &'a mut [u8; 2],
    pub tid: &'a mut [u8; 16],
    pub attrs: &'a mut [u8],
}

impl<'a> AssertedRawWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Option<Self> {
        let reader = RawWriter::new(bytes);

        Some(Self {
            typ: reader.typ?,
            len: reader.len?,
            tid: reader.tid?,
            attrs: reader.attrs?,
        })
    }
}

pub struct RawWriter<'a> {
    pub typ: Option<&'a mut [u8; 2]>,
    pub len: Option<&'a mut [u8; 2]>,
    pub tid: Option<&'a mut [u8; 16]>,
    pub attrs: Option<&'a mut [u8]>,
    cursor: usize,
}

impl<'a> RawWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        let (typ, bytes) = split_at_mut(bytes);
        let (len, bytes) = split_at_mut(bytes);
        let (tid, bytes) = split_at_mut(bytes);
        let attrs = if tid.is_none() { None } else { Some(bytes) };

        Self {
            typ,
            len,
            tid,
            attrs,
            cursor: 0,
        }
    }

    fn add_attr(&mut self, typ: &[u8; 2], len: &[u8; 2], val: &[u8]) -> Option<()> {
        self.attrs?.get(self.cursor..self.cursor + 4 + val.len())?; // fail early if the entire attr cannot fit

        self.attrs.as_mut()?.get_mut(self.cursor..self.cursor + 2)?.copy_from_slice(typ);
        self.cursor += 2;

        self.attrs.as_mut()?.get_mut(self.cursor..self.cursor + 2)?.copy_from_slice(len);
        self.cursor += 2;

        self.attrs.as_mut()?.get_mut(self.cursor..self.cursor + val.len())?.copy_from_slice(val);
        self.cursor += val.len();

        Some(())
    }

    fn add_attr2<T: FnOnce(&[u8; 2], &[u8; 2], &[u8]) -> u16>(&mut self, f: T) {
        let used = f(self)
    }
}

fn split_at_mut<const N: usize>(bytes: &mut [u8]) -> (Option<&mut [u8; N]>, &mut [u8]) {
    if bytes.len() > N {
        return (None, bytes);
    }
    let (chunk, rest) = bytes.split_at_mut(N);
    (chunk.try_into().ok(), rest)
}

fn read_u16_be(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes.get(offset..offset + 2)
        .map(|b| b.try_into().ok())
        .flatten()
        .map(u16::from_be_bytes)
}

fn get_nearest_greater_multiple_of_4(len: usize) -> usize {
    (len + 3) & !3
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
        0x00, 0x04,                     // value length
        0x00, 0x00, 0x00, 0x40 | 0x20,  // change both ip and port
    ];

    #[test]
    fn read_raw() {
        let reader = RawReader::new(&MSG);
        assert_eq!(&MSG[0..2], reader.typ.unwrap());
        assert_eq!(&MSG[2..4], reader.len.unwrap());
        assert_eq!(&MSG[4..20], reader.tid.unwrap());
        assert_eq!(&MSG[20..], reader.attrs.unwrap());

        assert_eq!(1, reader.attrs().count());
        let attr_reader = reader.attrs().next().unwrap();

        assert_eq!(&MSG[20..22], attr_reader.typ.unwrap());
        assert_eq!(&MSG[22..24], attr_reader.len.unwrap());
        assert_eq!(&MSG[24..28], attr_reader.val.unwrap());
    }

    #[test]
    fn read_asserted() {
        let reader = AssertedRawReader::new(&MSG).unwrap();
        assert_eq!(&MSG[0..2], reader.typ);
        assert_eq!(&MSG[2..4], reader.len);
        assert_eq!(&MSG[4..20], reader.tid);
        assert_eq!(&MSG[20..], reader.attrs);

        assert_eq!(1, reader.attrs().count());
        let attr_reader = reader.attrs().next().unwrap();

        assert_eq!(&MSG[20..22], attr_reader.typ);
        assert_eq!(&MSG[22..24], attr_reader.len);
        assert_eq!(&MSG[24..28], attr_reader.val);
    }

    #[test]
    fn write_raw() {
        let mut buf = [0u8; 28];

        let writer = RawWriter::new(&mut buf);
        writer.typ.unwrap();
    }
}