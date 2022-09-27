use crate::raw;

pub struct AssertedTypedReader<'a> {
    pub typ: u16,
    pub len: u16,
    pub tid: u128,
    pub attrs: &'a [u8],
    attr_iter: AssertedTypedAttributesReaderIterator<'a>,
}

impl<'a> AssertedTypedReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let reader = raw::AssertedRawReader::new(bytes)?;

        let attr_iter = AssertedTypedAttributesReaderIterator::new(reader.attrs)?;

        Some(Self {
            typ: u16::from_be_bytes(*reader.typ),
            len: u16::from_be_bytes(*reader.len),
            tid: u128::from_be_bytes(*reader.tid),
            attrs: reader.attrs,
            attr_iter,
        })
    }

    pub fn attrs(&self) -> AssertedTypedAttributesReaderIterator {
        self.attr_iter.clone()
    }
}

pub struct AssertedTypedAttributeReader<'a> {
    pub typ: u16,
    pub len: u16,
    pub val: &'a [u8],
}

impl<'a> AssertedTypedAttributeReader<'a> {
    fn new(reader: &raw::AssertedRawAttributeReader<'a>) -> Self {
        Self {
            typ: u16::from_be_bytes(*reader.typ),
            len: u16::from_be_bytes(*reader.len),
            val: reader.val,
        }
    }
}

#[derive(Clone)]
pub struct AssertedTypedAttributesReaderIterator<'a> {
    raw_iter: raw::AssertedRawAttributesReaderIterator<'a>,
}

impl<'a> AssertedTypedAttributesReaderIterator<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        let raw_reader_count = raw::AssertedRawAttributesReaderIterator::new(bytes)?.count();
        let asserted_reader_count = raw::AssertedRawAttributesReaderIterator::new(bytes)?.count();
        if raw_reader_count != asserted_reader_count { return None; }

        Some(Self {
            raw_iter: raw::AssertedRawAttributesReaderIterator::new(bytes)?
        })
    }
}

impl<'a> Iterator for AssertedTypedAttributesReaderIterator<'a> {
    type Item = AssertedTypedAttributeReader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(AssertedTypedAttributeReader::new(&self.raw_iter.next()?))
    }
}

pub struct TypedReader<'a> {
    pub typ: Option<u16>,
    pub len: Option<u16>,
    pub tid: Option<u128>,
    pub attrs: Option<&'a [u8]>,
    attr_iter: TypedAttributesReaderIterator<'a>,
}

impl<'a> TypedReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        let reader = raw::RawReader::new(bytes);
        Self {
            typ: reader.typ.map(|typ| u16::from_be_bytes(*typ)),
            len: reader.len.map(|len| u16::from_be_bytes(*len)),
            tid: reader.tid.map(|tid| u128::from_be_bytes(*tid)),
            attrs: reader.attrs,
            attr_iter: TypedAttributesReaderIterator::new(bytes.get(20..).unwrap_or(&[])),
        }
    }

    pub fn attrs(&self) -> TypedAttributesReaderIterator {
        self.attr_iter.clone()
    }
}

pub struct TypedAttributeReader<'a> {
    pub typ: Option<u16>,
    pub len: Option<u16>,
    pub val: Option<&'a [u8]>,
}

impl<'a> TypedAttributeReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        let reader = raw::RawAttributeReader::new(bytes);
        Self {
            typ: reader.typ.map(|typ| u16::from_be_bytes(*typ)),
            len: reader.len.map(|len| u16::from_be_bytes(*len)),
            val: reader.val,
        }
    }
}

#[derive(Clone)]
pub struct TypedAttributesReaderIterator<'a> {
    bytes: &'a [u8],
}

impl<'a> TypedAttributesReaderIterator<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }
}

impl<'a> Iterator for TypedAttributesReaderIterator<'a> {
    type Item = TypedAttributeReader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() == 0 { return None; }

        let declared_value_size = read_u16_be(self.bytes, 2);

        match declared_value_size {
            None => {
                let reader = TypedAttributeReader::new(self.bytes);
                self.bytes = &[];
                Some(reader)
            }
            Some(declared_value_size) => match self.bytes.get(0..4 + get_nearest_greater_multiple_of_4(declared_value_size as usize)) {
                None => {
                    let reader = TypedAttributeReader::new(self.bytes);
                    self.bytes = &[];
                    Some(reader)
                }
                Some(attr_bytes_incl_padding) => {
                    let reader = TypedAttributeReader::new(attr_bytes_incl_padding);
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

pub struct AssertedTypedWriter<'a> {
    raw_writer: raw::AssertedRawWriter<'a>,
}

impl<'a> AssertedTypedWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Option<Self> {
        Some(Self {
            raw_writer: raw::AssertedRawWriter::new(bytes)?
        })
    }

    fn typ(&mut self, typ: u16) {
        self.raw_writer.typ.copy_from_slice(&typ.to_be_bytes());
    }

    fn len(&mut self, len: u16) {
        self.raw_writer.len.copy_from_slice(&len.to_be_bytes());
    }

    fn tid(&mut self, tid: u128) {
        self.raw_writer.tid.copy_from_slice(&tid.to_be_bytes());
    }

    fn add_attr(&mut self, typ: u16, len: u16, val: &[u8]) -> Option<()> {
        self.raw_writer.add_attr(&typ.to_be_bytes(), &len.to_be_bytes(), val)
    }

    fn add_attr2<T: FnOnce(&mut u16, &mut u16, &mut [u8]) -> usize>(&mut self, f: T) -> Option<()> {
        self.raw_writer.add_attr2(|typ, len, val| {
            let mut typ_buf = 0;
            let mut len_buf = 0;
            let used = f(&mut typ_buf, &mut len_buf, val);
            typ.copy_from_slice(&typ_buf.to_be_bytes());
            len.copy_from_slice(&len_buf.to_be_bytes());
            return used;
        })
    }
}

pub struct TypedWriter<'a> {
    raw_writer: raw::RawWriter<'a>,
}

impl<'a> TypedWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            raw_writer: raw::RawWriter::new(bytes)
        }
    }

    fn typ(&mut self, typ: u16) -> Option<()> {
        self.raw_writer.typ.as_mut()?.copy_from_slice(&typ.to_be_bytes());
        Some(())
    }

    fn len(&mut self, len: u16) -> Option<()> {
        self.raw_writer.len.as_mut()?.copy_from_slice(&len.to_be_bytes());
        Some(())
    }

    fn tid(&mut self, tid: u128) -> Option<()> {
        self.raw_writer.tid.as_mut()?.copy_from_slice(&tid.to_be_bytes());
        Some(())
    }

    fn add_attr(&mut self, typ: u16, len: u16, val: &[u8]) -> Option<()> {
        self.raw_writer.add_attr(&typ.to_be_bytes(), &len.to_be_bytes(), val)
    }

    fn add_attr2<T: FnOnce(&mut u16, &mut u16, &mut [u8]) -> usize>(&mut self, f: T) -> Option<()> {
        self.raw_writer.add_attr2(|typ, len, val| {
            let mut typ_buf = 0;
            let mut len_buf = 0;
            let used = f(&mut typ_buf, &mut len_buf, val);
            typ.copy_from_slice(&typ_buf.to_be_bytes());
            len.copy_from_slice(&len_buf.to_be_bytes());
            return used;
        })
    }
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
        0x00, 0x04,                     // length: 4 (only value bytes count)
        0x00, 0x00, 0x00, 0x40 | 0x20,  // change both ip and port
    ];

    #[test]
    fn read_typed() {
        let reader = TypedReader::new(&MSG);
        assert_eq!(u16::from_be_bytes(MSG[0..2].try_into().unwrap()), reader.typ.unwrap());
        assert_eq!(u16::from_be_bytes(MSG[2..4].try_into().unwrap()), reader.len.unwrap());
        assert_eq!(u128::from_be_bytes(MSG[4..20].try_into().unwrap()), reader.tid.unwrap());
        assert_eq!(&MSG[20..28], reader.attrs.unwrap());
    }

    #[test]
    fn read_typed_attr() {
        let reader = TypedReader::new(&MSG);

        assert_eq!(1, reader.attrs().count());
        let attr_reader = reader.attrs().next().unwrap();

        assert_eq!(u16::from_be_bytes(MSG[20..22].try_into().unwrap()), attr_reader.typ.unwrap());
        assert_eq!(u16::from_be_bytes(MSG[22..24].try_into().unwrap()), attr_reader.len.unwrap());
        assert_eq!(&MSG[24..28], attr_reader.val.unwrap());
    }

    #[test]
    fn read_asserted() {
        let reader = AssertedTypedReader::new(&MSG).unwrap();
        assert_eq!(u16::from_be_bytes(MSG[0..2].try_into().unwrap()), reader.typ);
        assert_eq!(u16::from_be_bytes(MSG[2..4].try_into().unwrap()), reader.len);
        assert_eq!(u128::from_be_bytes(MSG[4..20].try_into().unwrap()), reader.tid);
        assert_eq!(&MSG[20..28], reader.attrs);
    }

    #[test]
    fn read_asserted_attr() {
        let reader = AssertedTypedReader::new(&MSG).unwrap();

        assert_eq!(1, reader.attrs().count());
        let attr_reader = reader.attrs().next().unwrap();

        assert_eq!(u16::from_be_bytes(MSG[20..22].try_into().unwrap()), attr_reader.typ);
        assert_eq!(u16::from_be_bytes(MSG[22..24].try_into().unwrap()), attr_reader.len);
        assert_eq!(&MSG[24..28], attr_reader.val);
    }

    #[test]
    fn write_typed() {
        let mut buf = [0u8; 28];

        let mut writer = TypedWriter::new(&mut buf);
        writer.typ(u16::from_be_bytes(MSG[0..2].try_into().unwrap()));
        writer.len(u16::from_be_bytes(MSG[2..4].try_into().unwrap()));
        writer.tid(u128::from_be_bytes(MSG[4..20].try_into().unwrap()));

        assert_eq!(MSG[0..20], buf[0..20]);
    }

    #[test]
    fn write_typed_attr() {
        let mut buf = [0u8; 28];

        let mut writer = TypedWriter::new(&mut buf);
        writer.add_attr(u16::from_be_bytes(MSG[20..22].try_into().unwrap()), u16::from_be_bytes(MSG[22..24].try_into().unwrap()), &MSG[24..28]).unwrap();

        assert_eq!(MSG[20..28], buf[20..28]);
    }

    #[test]
    fn write_typed_attr2() {
        let mut buf = [0u8; 28];

        let mut writer = TypedWriter::new(&mut buf);
        writer.add_attr2(|typ, len, val| {
            *typ = u16::from_be_bytes(MSG[20..22].try_into().unwrap());
            *len = u16::from_be_bytes(MSG[22..24].try_into().unwrap());
            val.copy_from_slice(&MSG[24..28]);
            return 4;
        }).unwrap();

        assert_eq!(MSG[20..28], buf[20..28]);
    }

    #[test]
    fn write_asserted() {
        let mut buf = [0u8; 28];

        let mut writer = AssertedTypedWriter::new(&mut buf).unwrap();
        writer.typ(u16::from_be_bytes(MSG[0..2].try_into().unwrap()));
        writer.len(u16::from_be_bytes(MSG[2..4].try_into().unwrap()));
        writer.tid(u128::from_be_bytes(MSG[4..20].try_into().unwrap()));

        assert_eq!(MSG[0..20], buf[0..20]);
    }

    #[test]
    fn write_asserted_attr() {
        let mut buf = [0u8; 28];

        let mut writer = AssertedTypedWriter::new(&mut buf).unwrap();
        writer.add_attr(u16::from_be_bytes(MSG[20..22].try_into().unwrap()), u16::from_be_bytes(MSG[22..24].try_into().unwrap()), &MSG[24..28]).unwrap();

        assert_eq!(MSG[20..28], buf[20..28]);
    }

    #[test]
    fn write_asserted_attr2() {
        let mut buf = [0u8; 28];

        let mut writer = AssertedTypedWriter::new(&mut buf).unwrap();
        writer.add_attr2(|typ, len, val| {
            *typ = u16::from_be_bytes(MSG[20..22].try_into().unwrap());
            *len = u16::from_be_bytes(MSG[22..24].try_into().unwrap());
            val.copy_from_slice(&MSG[24..28]);
            return 4;
        }).unwrap();

        assert_eq!(MSG[20..28], buf[20..28]);
    }
}