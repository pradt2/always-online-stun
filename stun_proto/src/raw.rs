pub struct AssertedRawReader<'a> {
    message_type: &'a [u8; 2],
    message_length: &'a [u8; 2],
    transaction_id: &'a [u8; 16],
    attribute_bytes: &'a [u8],
    attr_iter: AssertedRawAttributesReaderIterator<'a>
}

impl<'a> AssertedRawReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let message_type = bytes.get(0..2)?.try_into().ok()?;
        let message_length = bytes.get(2..4)?.try_into().ok()?;
        let transaction_id = bytes.get(4..20)?.try_into().ok()?;
        let attribute_bytes = bytes.get(20..)?;
        let attr_iter = AssertedRawAttributesReaderIterator::new(attribute_bytes)?;

        Some(Self {
            message_type,
            message_length,
            transaction_id,
            attribute_bytes,
            attr_iter,
        })
    }

    pub fn get_message_type(&self) -> &[u8; 2] {
        self.message_type
    }

    pub fn get_message_length(&self) -> &[u8; 2] {
        self.message_length
    }

    pub fn get_transaction_id(&self) -> &[u8; 16] {
        self.transaction_id
    }

    pub fn get_attributes(&self) -> AssertedRawAttributesReaderIterator {
        self.attr_iter.copy()
    }
}

pub struct AssertedRawAttributeReader<'a> {
    attr_type: &'a [u8; 2],
    attr_length: &'a [u8; 2],
    attr_value_with_padding: &'a [u8],
}

impl<'a> AssertedRawAttributeReader<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        let attr_type = bytes.get(0..2)?.try_into().ok()?;
        let attr_length: &[u8; 2] = bytes.get(2..4)?.try_into().ok()?;
        let attr_value_with_padding = bytes.get(4..)?;

        if attr_value_with_padding.len() != get_nearest_greater_multiple_of_4(attr_value_with_padding.len()) {
            return None;
        }

        if u16::from_be_bytes(*attr_length) as usize > attr_value_with_padding.len() {
            return None;
        }

        Some(Self {
            attr_type,
            attr_length,
            attr_value_with_padding,
        })
    }

    pub fn get_attribute_type(&self) -> &[u8; 2] {
        self.attr_type
    }

    pub fn get_attribute_length(&self) -> &[u8; 2] {
        self.attr_length
    }

    pub fn get_attribute_value_with_padding(&self) -> &[u8] {
        self.attr_value_with_padding
    }
}

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

    fn copy(&self) -> Self {
        Self {
            raw_iter: self.raw_iter.copy()
        }
    }
}

impl<'a> Iterator for AssertedRawAttributesReaderIterator<'a> {
    type Item = AssertedRawAttributeReader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.raw_iter.next()?.asserted()
    }
}

pub struct RawReader<'a> {
    bytes: &'a [u8],
}

impl<'a> RawReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn get_message_type(&self) -> Option<&[u8; 2]> {
        self.bytes.get(0..2)?.try_into().ok()
    }

    pub fn get_message_length(&self) -> Option<&[u8; 2]> {
        self.bytes.get(2..4)?.try_into().ok()
    }

    pub fn get_transaction_id(&self) -> Option<&[u8; 16]> {
        self.bytes.get(4..20)?.try_into().ok()
    }

    pub fn get_attributes(&self) -> RawAttributesReaderIterator<'a> {
        RawAttributesReaderIterator::new(self.bytes.get(20..).unwrap_or(&[]))
    }
}

pub struct RawAttributeReader<'a> {
    bytes: &'a [u8],
}

impl<'a> RawAttributeReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn get_attribute_type(&self) -> Option<&[u8; 2]> {
        self.bytes.get(0..2)?.try_into().ok()
    }

    pub fn get_attribute_length(&self) -> Option<&[u8; 2]> {
        self.bytes.get(2..4)?.try_into().ok()
    }

    pub fn get_attribute_value_with_padding(&self) -> Option<&[u8]> {
        self.bytes.get(4..)
    }

    pub fn asserted(&self) -> Option<AssertedRawAttributeReader<'a>> {
        AssertedRawAttributeReader::new(self.bytes)
    }
}

pub struct RawAttributesReaderIterator<'a> {
    bytes: &'a [u8],
}

impl<'a> RawAttributesReaderIterator<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    fn copy(&self) -> Self {
        Self {
            bytes: self.bytes
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

pub struct RawWriter<'a> {
    bytes: &'a mut [u8],
    cursor: usize,
}

impl<'a> RawWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    pub fn get_message_type(&mut self) -> Option<&mut [u8; 2]> {
        self.bytes.get_mut(0..2)?.try_into().ok()
    }

    pub fn get_message_length(&mut self) -> Option<&mut [u8; 2]> {
        self.bytes.get_mut(2..4)?.try_into().ok()
    }

    pub fn get_transaction_id(&mut self) -> Option<&mut [u8; 16]> {
        self.bytes.get_mut(4..20)?.try_into().ok()
    }



    pub fn get_attributes(&self) -> RawAttributesWriterIterator<'a> {
        RawAttributesWriterIterator::new(self.bytes.get_mut(20..).unwrap_or(&mut []))
    }
}

pub struct RawAttributeWriter<'a> {
    bytes: &'a mut [u8],
}

impl<'a> RawAttributeWriter<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn get_attribute_type(&mut self) -> Option<&mut [u8; 2]> {
        self.bytes.get_mut(0..2)?.try_into().ok()
    }

    pub fn get_attribute_length(&mut self) -> Option<&[u8; 2]> {
        self.bytes.get_mut(2..4)?.try_into().ok()
    }

    pub fn get_attribute_value_with_padding(&mut self) -> Option<&mut [u8]> {
        self.bytes.get_mut(4..)
    }

    pub fn asserted(&mut self) -> Option<AssertedRawAttributeReader<'a>> {
        AssertedRawAttributeReader::new(self.bytes)
    }
}

pub struct RawAttributesWriterIterator<'a> {
    bytes: &'a mut [u8],
}

impl<'a> RawAttributesWriterIterator<'a> {
    fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes
        }
    }

    fn asserted(&self) -> Option<AssertedRawAttributesReaderIterator> {
        AssertedRawAttributesReaderIterator::new(self.bytes)
    }
}

impl<'a> Iterator for RawAttributesWriterIterator<'a> {
    type Item = RawAttributeWriter<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.len() == 0 { return None; }

        let declared_value_size = read_u16_be(self.bytes, 2);

        match declared_value_size {
            None => {
                let reader = RawAttributeWriter::new(self.bytes);
                self.bytes = &[];
                Some(reader)
            }
            Some(declared_value_size) => match self.bytes.get_mut(0..4 + get_nearest_greater_multiple_of_4(declared_value_size as usize)) {
                None => {
                    let reader = RawAttributeWriter::new(self.bytes);
                    self.bytes = &[];
                    Some(reader)
                }
                Some(attr_bytes_incl_padding) => {
                    let reader = RawAttributeWriter::new(attr_bytes_incl_padding);
                    match self.bytes.get_mut(attr_bytes_incl_padding.len()..) {
                        None => self.bytes = &[],
                        Some(next_argument_bytes) => self.bytes = next_argument_bytes,
                    };
                    Some(reader)
                }
            }
        }
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