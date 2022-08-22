use crate::{ReaderErr, Result};

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SocketAddr {
    V4(u32, u16),
    V6(u128, u16),
}

pub struct SocketAddrReader<'a> {
    bytes: &'a [u8],
}

impl<'a> SocketAddrReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn get_address(&self) -> Result<SocketAddr> {
        let addr_family = if let Some(val) = self.bytes.get(0..2)
            .map(|b| b.try_into().unwrap())
            .map(|b: &[u8; 2]| u16::from_be_bytes(*b)) { val } else {
            return Err(ReaderErr::NotEnoughBytes);
        };

        let port = if let Some(val) = self.bytes.get(2..4)
            .map(|b| b.try_into().unwrap())
            .map(|b: &[u8; 2]| u16::from_be_bytes(*b)) { val } else {
            return Err(ReaderErr::NotEnoughBytes);
        };

        match addr_family {
            1 => {
                let b = self.bytes.get(4..8)
                    .map(|b| b.try_into().unwrap())
                    .map(|b: &[u8; 4]| u32::from_be_bytes(*b))
                    .ok_or(ReaderErr::NotEnoughBytes);

                let ip = if let Ok(b) = b { b } else {
                    return Err(ReaderErr::NotEnoughBytes);
                };

                Ok(SocketAddr::V4(ip, port))
            }
            2 => {
                let b = self.bytes.get(4..20)
                    .map(|b| b.try_into().unwrap())
                    .map(|b: [u8; 16]| u128::from_be_bytes(b))
                    .ok_or(ReaderErr::NotEnoughBytes);

                let ip = if let Ok(b) = b { b } else {
                    return Err(ReaderErr::NotEnoughBytes);
                };

                Ok(SocketAddr::V6(ip, port))
            }
            _ => Err(ReaderErr::UnexpectedValue)
        }
    }
}

pub struct SocketAddrWriter<'a> {
    bytes: &'a mut [u8],
}

impl<'a> SocketAddrWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn write_ipv4_addr(&mut self, ip: u32, port: u16) -> Result<u16> {
        let addr_family_dest = self.bytes.get_mut(0..2)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        addr_family_dest[0] = 0;
        addr_family_dest[1] = 1;

        let port_dest = self.bytes.get_mut(2..4)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        let port_bytes = port.to_be_bytes();
        port_dest.copy_from_slice(&port_bytes);

        let ipv4_addr_dest = self.bytes.get_mut(4..8)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        let ipv4_addr_bytes = ip.to_be_bytes();
        ipv4_addr_dest.copy_from_slice(&ipv4_addr_bytes);
        Ok(8)
    }

    pub fn write_ipv6_addr(&mut self, ip: u128, port: u16) -> Result<u16> {
        let addr_family_dest = self.bytes.get_mut(0..2)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        addr_family_dest[0] = 0;
        addr_family_dest[1] = 2;

        let port_dest = self.bytes.get_mut(2..4)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        let port_bytes = port.to_be_bytes();
        port_dest.copy_from_slice(&port_bytes);

        let ipv6_addr_dest = self.bytes.get_mut(4..20)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        let ipv6_addr_bytes = ip.to_be_bytes();
        ipv6_addr_dest.copy_from_slice(&ipv6_addr_bytes);
        Ok(20)
    }
}

pub struct XorSocketAddrReader<'a> {
    socket_addr_reader: SocketAddrReader<'a>,
    transaction_id: u128,
}

impl<'a> XorSocketAddrReader<'a> {
    pub fn new(bytes: &'a [u8], transaction_id: u128) -> Self {
        Self {
            socket_addr_reader: SocketAddrReader::new(bytes),
            transaction_id,
        }
    }

    pub fn get_address(&self) -> Result<SocketAddr> {
        match self.socket_addr_reader.get_address() {
            Err(err) => Err(err),
            Ok(SocketAddr::V4(ip, port)) => {
                let mask = 0x2112A442;
                Ok(SocketAddr::V4(ip ^ mask, port))
            }
            Ok(SocketAddr::V6(ip, port)) => {
                let mask = 0x2112A442 << 92 | self.transaction_id;
                Ok(SocketAddr::V6(ip ^ mask, port))
            }
        }
    }
}

pub struct XorSocketAddrWriter<'a> {
    bytes: &'a mut [u8],
}

impl<'a> XorSocketAddrWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn write_ipv4_addr(&mut self, addr: u32, port: u16) -> Result<u16> {
        let addr_family_dest = self.bytes.get_mut(0..2)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        addr_family_dest[0] = 0;
        addr_family_dest[1] = 1;

        let port_dest = self.bytes.get_mut(2..4)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        let port_bytes = port.to_be_bytes();
        port_dest.copy_from_slice(&port_bytes);

        let mask = 0x2112A442;
        let ipv4_addr_dest = self.bytes.get_mut(4..8)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        let ipv4_addr_bytes = (addr ^ mask).to_be_bytes();
        ipv4_addr_dest.copy_from_slice(&ipv4_addr_bytes);
        Ok(8)
    }

    pub fn write_ipv6_addr(&mut self, addr: u128, port: u16, transaction_id: u128) -> Result<u16> {
        let addr_family_dest = self.bytes.get_mut(0..2)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        addr_family_dest[0] = 0;
        addr_family_dest[1] = 2;

        let port_dest = self.bytes.get_mut(2..4)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        let port_bytes = port.to_be_bytes();
        port_dest.copy_from_slice(&port_bytes);

        let mask = 0x2112A442 << 92 | transaction_id;
        let ipv6_addr_dest = self.bytes.get_mut(4..20)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        let ipv6_addr_bytes = (addr ^ mask).to_be_bytes();
        ipv6_addr_dest.copy_from_slice(&ipv6_addr_bytes);
        Ok(20)
    }
}

pub struct MessageIntegrityWriter<'a> {
    bytes: &'a mut [u8],
}

impl<'a> MessageIntegrityWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn write(&mut self, value: &[u8; 20]) -> Result<u16> {
        self.bytes.get_mut(0..20)
            .ok_or(ReaderErr::NotEnoughBytes)?
            .copy_from_slice(value);

        Ok(20)
    }
}

pub struct StringReader<'a> {
    bytes: &'a [u8],
}

impl<'a> StringReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub unsafe fn get_value_unchecked(&self) -> &'a str {
        core::str::from_utf8_unchecked(self.bytes)
    }

    pub fn get_value(&self) -> Result<&'a str> {
        core::str::from_utf8(self.bytes)
            .map_err(|_| ReaderErr::UnexpectedValue)
    }
}

pub struct StringWriter<'a> {
    bytes: &'a mut [u8],
}

impl<'a> StringWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn write(&mut self, value: &str) -> Result<u16> {
        let value_bytes = value.as_bytes();
        let val_len = value_bytes.len();

        self.bytes.get_mut(0..val_len)
            .ok_or(ReaderErr::NotEnoughBytes)?
            .copy_from_slice(value_bytes);

        Ok(val_len as u16)
    }
}

pub struct MessageIntegrityReader<'a> {
    bytes: &'a [u8],
}

impl<'a> MessageIntegrityReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn get_value(&self) -> Result<&[u8; 20]> {
        self.bytes.get(0..20)
            .map(|b| b.try_into().unwrap())
            .ok_or(ReaderErr::NotEnoughBytes)
    }
}

pub struct FingerprintReader<'a> {
    bytes: &'a [u8],
}

impl<'a> FingerprintReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn get_value(&self) -> Result<u32> {
        self.bytes.get(0..4)
            .map(|b| b.try_into().unwrap())
            .map(|b: &[u8; 4]| u32::from_be_bytes(*b) ^ 0x5354554E)
            .ok_or(ReaderErr::NotEnoughBytes)
    }
}

pub struct FingerprintWriter<'a> {
    bytes: &'a mut [u8],
}

impl <'a> FingerprintWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn write(&mut self, value: u32) -> Result<u16> {
        self.bytes.get_mut(0..4)
            .ok_or(ReaderErr::NotEnoughBytes)?
            .copy_from_slice(&(value ^ 0x5354554E).to_be_bytes());
        Ok(4)
    }
}

pub struct UnknownAttrsIterator<'a> {
    bytes: &'a [u8],
    idx: usize,
}

impl<'a> Iterator for UnknownAttrsIterator<'a> {
    type Item = Result<u16>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.bytes.len() {
            None
        } else {
            let code = if let Ok(code) = self.bytes
                .get(self.idx..self.idx + 2)
                .map(|b| b.try_into().unwrap())
                .map(|b: &[u8; 2]| u16::from_be_bytes(*b))
                .ok_or(ReaderErr::NotEnoughBytes) { code } else {
                return Some(Err(ReaderErr::NotEnoughBytes));
            };

            self.idx += 2;
            Some(Ok(code))
        }
    }
}

pub struct UnknownAttrsReader<'a> {
    bytes: &'a [u8],
}

impl<'a> UnknownAttrsReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn unknown_type_codes(&self) -> UnknownAttrsIterator<'a> {
        UnknownAttrsIterator {
            bytes: self.bytes,
            idx: 0,
        }
    }
}

pub struct UnknownAttrsWriter<'a> {
    bytes: &'a mut [u8],
}

impl<'a> UnknownAttrsWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> UnknownAttrsWriter {
        Self {
            bytes
        }
    }

    pub fn write(&'a mut self, attrs: &[u16], padding_val: Option<u16>) -> Result<u16> {
        let attrs_len = attrs.len();

        for idx in 0..attrs_len {
            self.bytes.get_mut(idx * 2..idx * 2 + 2)
                .ok_or(ReaderErr::NotEnoughBytes)?
                .copy_from_slice(&attrs[idx].to_be_bytes());
        }

        let attrs_len_with_padding = if attrs_len & 1 == 0 { attrs_len } else { attrs_len + 1 };
        if attrs_len_with_padding > attrs_len {
            self.bytes.get_mut(attrs_len * 2..attrs_len * 2 + 2)
                .ok_or(ReaderErr::NotEnoughBytes)?
                .copy_from_slice(&padding_val.unwrap_or(0).to_be_bytes());
        }

        Ok((attrs_len_with_padding * 2) as u16)
    }
}

pub struct ErrorCodeReader<'a> {
    bytes: &'a [u8],
}

impl<'a> ErrorCodeReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn get_code(&self) -> Result<u16> {
        let class = if let Ok(class) = self.bytes
            .get(2)
            .map(|b| b >> 5) // we only care about 3 MSB
            .ok_or(ReaderErr::NotEnoughBytes) { class as u16 } else {
            return Err(ReaderErr::NotEnoughBytes);
        };

        let num = if let Ok(num) = self.bytes
            .get(3)
            .map(|b| *b)
            .ok_or(ReaderErr::NotEnoughBytes) { num as u16 } else {
            return Err(ReaderErr::NotEnoughBytes);
        };

        let code = class * 100 + num;
        Ok(code)
    }

    pub fn get_reason(&self) -> Result<&str> {
        let b = if let Ok(b) = self.bytes
            .get(4..)
            .ok_or(ReaderErr::NotEnoughBytes) { b } else {
            return Err(ReaderErr::NotEnoughBytes);
        };
        StringReader::new(b).get_value()
    }

    pub unsafe fn get_reason_unchecked(&self) -> Result<&str> {
        let b = if let Ok(b) = self.bytes
            .get(4..)
            .ok_or(ReaderErr::NotEnoughBytes) { b } else {
            return Err(ReaderErr::NotEnoughBytes);
        };
        Ok(StringReader::new(b).get_value_unchecked())
    }
}

pub struct ErrorCodeWriter<'a> {
    bytes: &'a mut [u8],
}

impl<'a> ErrorCodeWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn write_code(&mut self, code: u16) -> Result<u16> {
        let class = (code / 100) as u8;
        let num= (code - code / 100 * 100) as u8;

        let bytes = [
            class << 5,
            num,
        ];

        self.bytes.get_mut(2..4)
            .ok_or(ReaderErr::NotEnoughBytes)?
            .copy_from_slice(&bytes);

        Ok(4)
    }

    pub fn write_reason(&'a mut self, reason: &str) -> Result<u16> {
        let dest = self.bytes.get_mut(4..)
            .ok_or(ReaderErr::NotEnoughBytes)?;

        StringWriter::new(dest).write(reason)
    }
}

pub struct ChangeRequestReader<'a> {
    bytes: &'a [u8],
}

impl<'a> ChangeRequestReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn get_change_ip(&self) -> Result<bool> {
        Ok(self.bytes.get(3).ok_or(ReaderErr::NotEnoughBytes)? & 0x40 > 0)
    }

    pub fn get_change_port(&self) -> Result<bool> {
        Ok(self.bytes.get(3).ok_or(ReaderErr::NotEnoughBytes)? & 0x20 > 0)
    }
}

pub struct ChangeRequestWriter<'a> {
    bytes: &'a mut [u8],
}

impl<'a> ChangeRequestWriter<'a> {
    pub fn new(bytes: &'a mut [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub fn write(&mut self, change_ip: bool, change_port: bool) -> Result<u16> {
        let bytes = if change_ip { 0x40 } else { 0x00 } | if change_port { 0x20 } else { 0x00 } as u32;

        self.bytes.get_mut(0..4)
            .ok_or(ReaderErr::NotEnoughBytes)?
            .copy_from_slice(&bytes.to_be_bytes());

        Ok(4)
    }
}

struct RawAttributeIterator<'a> {
    bytes: &'a [u8],
    idx: usize,
}

impl<'a> RawAttributeIterator<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            idx: 0,
        }
    }
}

impl<'a> Iterator for RawAttributeIterator<'a> {
    type Item = Result<(&'a [u8; 2], &'a [u8; 2], &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.bytes.len() {
            None
        } else {
            let typ_raw = self.bytes
                .get(self.idx..self.idx + 2)
                .map(|b| b.try_into().unwrap())
                .ok_or(ReaderErr::NotEnoughBytes);

            let typ_raw = match typ_raw {
                Ok(t) => t,
                Err(err) => {
                    self.idx = self.bytes.len();
                    return Some(Err(err));
                }
            };

            let val_len_raw = self.bytes.get(self.idx + 2..self.idx + 4)
                .map(|b| b.try_into().unwrap())
                .ok_or(ReaderErr::NotEnoughBytes);

            let val_len_raw: &[u8; 2] = match val_len_raw {
                Ok(t) => t,
                Err(err) => {
                    self.idx = self.bytes.len();
                    return Some(Err(err));
                }
            };

            let val_len = u16::from_be_bytes(*val_len_raw);

            let val_raw = self.bytes.get(self.idx + 4..self.idx + 4 + val_len as usize)
                .ok_or(ReaderErr::NotEnoughBytes);

            let val_raw = match val_raw {
                Ok(val) => val,
                Err(err) => {
                    self.idx = self.bytes.len();
                    return Some(Err(err));
                }
            };

            // new attributes always start at 4 byte boundary
            // the value length attribute only describes 'useful' bits
            // and excludes any padding bits that are added on top
            let val_len_and_padding = get_nearest_greater_multiple_of_4(val_len);

            self.idx += 4 + val_len_and_padding as usize;

            Some(Ok((typ_raw, val_len_raw, val_raw)))
        }
    }
}

pub struct BaseAttributeIterator<'a> {
    raw_iter: RawAttributeIterator<'a>,
}

impl<'a> BaseAttributeIterator<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            raw_iter: RawAttributeIterator::new(bytes)
        }
    }
}

impl<'a> Iterator for BaseAttributeIterator<'a> {
    type Item = Result<(u16, &'a [u8])>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.raw_iter.next() {
            None => None,
            Some(Err(err)) => Some(Err(err)),
            Some(Ok((typ_raw, _, val_raw))) => {
                let typ = u16::from_be_bytes(*typ_raw);
                Some(Ok((typ, val_raw)))
            }
        }
    }
}

/*
 this bithack gets us the nearest greater multiple of 4
 unless val_len is already a multiple of 4, then it does nothing
*/
pub fn get_nearest_greater_multiple_of_4(len: u16) -> u16 {
    (len + 3) & !3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_boundary_logic() {
        assert_eq!(0, get_nearest_greater_multiple_of_4(0));
        assert_eq!(4, get_nearest_greater_multiple_of_4(1));
        assert_eq!(4, get_nearest_greater_multiple_of_4(2));
        assert_eq!(4, get_nearest_greater_multiple_of_4(3));
        assert_eq!(4, get_nearest_greater_multiple_of_4(4));
        assert_eq!(8, get_nearest_greater_multiple_of_4(5));
        assert_eq!(8, get_nearest_greater_multiple_of_4(6));
        assert_eq!(8, get_nearest_greater_multiple_of_4(7));
        assert_eq!(8, get_nearest_greater_multiple_of_4(8));
    }

    #[test]
    fn socket_addr_ipv4() {
        let attr_val = [
            0x00, 0x01,             // address family
            0x0A, 0x0B,             // port
            0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
        ];

        let mut attr_buf = [0u8; 8];

        let r = SocketAddrReader::new(&attr_val);
        let addr = r.get_address()
            .expect("Address is unreadable");

        if let SocketAddr::V4(ip, port) = addr {

            let mut w = SocketAddrWriter::new(&mut attr_buf);
            let bytes_written = w.write_ipv4_addr(ip, port)
                .expect("Buffer is too small");

            assert_eq!(8, bytes_written);
            assert_eq!(attr_val, attr_buf);

        } else { assert!(false, "Address is not IPv4"); }
    }

    #[test]
    fn socket_addr_ipv6() {
        let attr_val = [
            0x00, 0x02,             // address family
            0x03, 0x04,             // port
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
            0x0D, 0x0E, 0x0F, 0x1A,
            0x1B, 0x1C, 0x1D, 0x1E, // ipv6 address
        ];

        let mut attr_buf = [0u8; 20];

        let r = SocketAddrReader::new(&attr_val);
        let addr = r.get_address()
            .expect("Address is unreadable");

        if let SocketAddr::V6(ip, port) = addr {

            let mut w = SocketAddrWriter::new(&mut attr_buf);
            let bytes_written = w.write_ipv6_addr(ip, port)
                .expect("Buffer is too small");

            assert_eq!(20, bytes_written);
            assert_eq!(attr_val, attr_buf);

        } else { assert!(false, "Address is not IPv6"); }
    }

    #[test]
    fn xor_socket_addr_ipv4() {
        let attr_val = [
            0x00, 0x01,             // address family
            0x0A, 0x0B,             // port
            0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
        ];

        let mut attr_buf = [0u8; 8];

        let transaction_id = 0xFF;

        let r = XorSocketAddrReader::new(&attr_val, transaction_id);
        let addr = r.get_address()
            .expect("Address is unreadable");

        if let SocketAddr::V4(ip, port) = addr {

            let mut w = XorSocketAddrWriter::new(&mut attr_buf);
            let bytes_written = w.write_ipv4_addr(ip, port)
                .expect("Buffer is too small");

            assert_eq!(8, bytes_written);
            assert_eq!(attr_val, attr_buf);

        } else { assert!(false, "Address is not IPv4"); }
    }

    #[test]
    fn xor_socket_addr_ipv6() {
        let attr_val = [
            0x00, 0x02,             // address family
            0x03, 0x04,             // port
            0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C,
            0x0D, 0x0E, 0x0F, 0x1A,
            0x1B, 0x1C, 0x1D, 0x1E, // ipv6 address
        ];

        let mut attr_buf = [0u8; 20];

        let transaction_id = 0xFF;

        let r = XorSocketAddrReader::new(&attr_val, transaction_id);
        let addr = r.get_address()
            .expect("Address is unreadable");

        if let SocketAddr::V6(ip, port) = addr {

            let mut w = XorSocketAddrWriter::new(&mut attr_buf);
            let bytes_written = w.write_ipv6_addr(ip, port, transaction_id)
                .expect("Buffer is too small");

            assert_eq!(20, bytes_written);
            assert_eq!(attr_val, attr_buf);

        } else { assert!(false, "Address is not IPv6"); }
    }

    #[test]
    fn string() {
        let attr_val = [
            0x68, 0x65, 0x6C, 0x6C, 0x6F, // hello
        ];

        let mut attr_buf = [0u8; 5];

        let r = StringReader::new(&attr_val);

        let mut w = StringWriter::new(&mut attr_buf);
        let bytes_written = w.write(r.get_value().expect("String is unreadable"))
            .expect("Buffer is too small");

        assert_eq!(5, bytes_written);
        assert_eq!(attr_val, attr_buf);
    }

    #[test]
    fn fingerprint() {
        let attr_val = [
            0x0A, 0x0B, 0x0C, 0x0D
        ];

        let mut attr_buf = [0u8; 4];

        let r = FingerprintReader::new(&attr_val);

        let mut w = FingerprintWriter::new(&mut attr_buf);
        let bytes_written = w.write(r.get_value().expect("Value is unreadable"))
            .expect("Buffer is too small");

        assert_eq!(4, bytes_written);
        assert_eq!(attr_val, attr_buf);
    }

    #[test]
    fn message_integrity() {
        let attr_val = [
            0x01, 0x02, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
            0x1A, 0x1B, 0x1C, 0x1D,
        ];

        let mut attr_buf = [0u8; 20];

        let r = MessageIntegrityReader::new(&attr_val);

        let mut w = MessageIntegrityWriter::new(&mut attr_buf);
        let bytes_written = w.write(r.get_value().expect("Value is unreadable"))
            .expect("Buffer is too small");

        assert_eq!(20, bytes_written);
        assert_eq!(attr_val, attr_buf);
    }

    #[test]
    fn unknown_attrs() {
        let attr_val = [
            0x01, 0x02, // we give only one value to the reader
            0x01, 0x02, // this value is here to only check that the writer does padding correctly
        ];

        let mut types = [0u16; 1];

        let mut attr_buf = [0u8; 4];

        let r = UnknownAttrsReader::new(&attr_val[0..2]);
        let mut idx = 0;
        for attr in r.unknown_type_codes() {
            let attr = attr.expect("Attribute type is unreadable");
            types[idx] = attr;
            idx += 1;
        }

        let mut w = UnknownAttrsWriter::new(&mut attr_buf);
        let bytes_written = w.write(&types, Some(types[0]))
            .expect("Buffer is too small");

        assert_eq!(4, bytes_written);
        assert_eq!(attr_val, attr_buf);
    }

    #[test]
    fn error_code() {
        let attr_val = [
            0x00, 0x00,                     // mandatory padding
            0x40, 0x16,                     // code 222
            0x68, 0x65, 0x6C, 0x6C, 0x6F,   // reason 'hello'
        ];

        let mut attr_buf = [0u8; 9];

        let r = ErrorCodeReader::new(&attr_val);

        let mut w = ErrorCodeWriter::new(&mut attr_buf);
        let bytes_written_code = w.write_code(r.get_code().expect("Code is unreadable"))
            .expect("Buffer is too small");
        let bytes_written_reason = w.write_reason(r.get_reason().expect("Reason value is unreadable"))
            .expect("Buffer is too small");

        assert_eq!(9, bytes_written_code + bytes_written_reason);
        assert_eq!(attr_val, attr_buf);
    }

    #[test]
    fn change_request() {
        let attr_val = 0b00000000000000000000000000000000i32.reverse_bits().to_ne_bytes();
        let mut attr_buf = [0u8; 4];

        let r = ChangeRequestReader::new(&attr_val);

        let mut w = ChangeRequestWriter::new(&mut attr_buf);
        let bytes_written = w.write(
            r.get_change_ip().expect("Change IP value is unreadable"),
            r.get_change_port().expect("Change port value is unreadable")
        ).expect("Buffer is too small");

        assert_eq!(4, bytes_written);
        assert_eq!(attr_val, attr_buf);

        let attr_val = 0b0000000000000000000000000000010i32.reverse_bits().to_ne_bytes();
        let mut attr_buf = [0u8; 4];

        let r = ChangeRequestReader::new(&attr_val);

        let mut w = ChangeRequestWriter::new(&mut attr_buf);
        let bytes_written = w.write(
            r.get_change_ip().expect("Change IP value is unreadable"),
        r.get_change_port().expect("Change port value is unreadable")
        ).expect("Buffer is too small");

        assert_eq!(4, bytes_written);
        assert_eq!(attr_val, attr_buf);

        let attr_val = 0b0000000000000000000000000000100i32.reverse_bits().to_ne_bytes();
        let mut attr_buf = [0u8; 4];

        let r = ChangeRequestReader::new(&attr_val);

        let mut w = ChangeRequestWriter::new(&mut attr_buf);
        let bytes_written = w.write(
            r.get_change_ip().expect("Change IP value is unreadable"),
            r.get_change_port().expect("Change port value is unreadable")
        ).expect("Buffer is too small");

        assert_eq!(4, bytes_written);
        assert_eq!(attr_val, attr_buf);

        let attr_val = 0b0000000000000000000000000000110i32.reverse_bits().to_ne_bytes();
        let mut attr_buf = [0u8; 4];

        let r = ChangeRequestReader::new(&attr_val);

        let mut w = ChangeRequestWriter::new(&mut attr_buf);
        let bytes_written = w.write(
            r.get_change_ip().expect("Change IP value is unreadable"),
            r.get_change_port().expect("Change port value is unreadable")
        ).expect("Buffer is too small");

        assert_eq!(4, bytes_written);
        assert_eq!(attr_val, attr_buf);
    }

    #[test]
    fn iter_over_attrs() {
        let attr = [
            0x00, 0x01,             // type
            0x00, 0x04,             // value length
            0x01, 0x01, 0x01, 0x01, // value
        ];

        assert_eq!(1, BaseAttributeIterator::new(&attr).count());

        for attr in BaseAttributeIterator::new(&attr) {
            match attr {
                Ok((typ, val)) => {
                    assert_eq!(1u16, typ);
                    assert_eq!([0x01, 0x01, 0x01, 0x01], *val);
                }
                Err(_) => assert!(false, "Test attr should be valid")
            }
        }
    }

    #[test]
    fn iter_over_attrs_invalid_attr_missing_byte() {
        let attr = [
            0x00, 0x01,             // type
            0x00, 0x04,             // value length
            0x01, 0x01, 0x01,       // value
            //  0x01,               // missing byte
        ];

        assert_eq!(1, BaseAttributeIterator::new(&attr).count());

        for attr in BaseAttributeIterator::new(&attr) {
            match attr {
                Ok(_) => assert!(false, "Test attr should be invalid"),
                Err(_) => assert!(true, "Test attr should be valid")
            }
        }
    }

    #[test]
    fn iter_over_attrs_invalid_attr_extra_byte() {
        let attr = [
            0x00, 0xFF,             // type
            0x00, 0x04,             // value length
            0x01, 0x01, 0x01, 0x01, // value
            0x00,                   // extra byte
        ];

        assert_eq!(2, BaseAttributeIterator::new(&attr).count());

        let mut iter = BaseAttributeIterator::new(&attr);

        if let Some(Ok((typ, val))) = iter.next() {
            assert_eq!(0xFF, typ);
            assert_eq!([0x01, 0x01, 0x01, 0x1], *val);
        } else {
            assert!(false, "First attr should be valid");
        }

        if let Some(Err(_)) = iter.next() {
            assert!(true);
        } else {
            assert!(false, "Second attr should be an error");
        }
    }
}
