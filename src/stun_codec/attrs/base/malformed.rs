use std::cmp::min;
use std::convert::TryInto;

pub struct MalformedAttrReader<'a> {
    bytes: &'a [u8],
}

impl<'a> MalformedAttrReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn get_type_raw(&self) -> u16 {
        match self.bytes.len() {
            0 => 0,
            1 => u8::from_be(self.bytes[0]) as u16,
            _ => u16::from_be_bytes(self.bytes[0..2].try_into().unwrap()),
        }
    }

    pub fn get_value_length_raw(&self) -> u16 {
        match self.bytes.len() {
            0 | 1 | 2 | 3 | 4 => 0,
            _ => u16::from_be_bytes(self.bytes[2..4].try_into().unwrap()),
        }
    }

    pub fn get_value_raw(&self) -> &[u8] {
        match self.bytes.len() {
            0 | 1 | 2 | 3 | 4 => &self.bytes[0..0],
            _ => {
                let length_raw = self.get_value_length_raw() as usize;
                let target_value_size = min(length_raw, self.bytes.len() - 4) / 4;
                &self.bytes[5..target_value_size]
            }
        }
    }
}
