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
        addr_family_dest[1] = 1;

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
                .copy_from_slice(&attrs[idx].to_be_bytes())
        }

        let attrs_len_with_padding = if attrs_len & 1 == 0 { attrs_len } else { attrs_len + 1 };
        if attrs_len_with_padding > attrs_len {
            self.bytes.get_mut(attrs_len_with_padding * 2..attrs_len_with_padding * 2 + 2) // each attr is 2 bytes long
                .ok_or(ReaderErr::NotEnoughBytes)?
                .copy_from_slice(&padding_val.unwrap_or(0).to_be_bytes());
        }

        Ok(attrs_len_with_padding as u16)
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

    pub fn set_code(&mut self, code: u16) -> Result<u16> {
        let class = code / 100;
        let num = code - class;
        let code = class << 8 | num;

        self.bytes.get_mut(0..2)
            .ok_or(ReaderErr::NotEnoughBytes)?
            .copy_from_slice(&code.to_be_bytes());

        Ok(2)
    }

    pub fn set_reason(&'a mut self, reason: &str) -> Result<u16> {
        let dest = self.bytes.get_mut(2..)
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
        Ok(self.bytes.get(3).ok_or(ReaderErr::NotEnoughBytes)? & 4 > 0)
    }

    pub fn get_change_port(&self) -> Result<bool> {
        Ok(self.bytes.get(3).ok_or(ReaderErr::NotEnoughBytes)? & 2 > 0)
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
        let bytes = if change_ip { 4 } else { 0 } | if change_port { 2 } else { 0 } as u32;

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

        let r = SocketAddrReader::new(&attr_val);
        let addr = if let Ok(addr) = r.get_address() { addr } else {
            assert!(false, "Test address should be a valid address");
            return;
        };

        if let SocketAddr::V4(ip, port) = addr {
            assert_eq!(0x0A0B, port);
            assert_eq!(0x0C0D0E0F, ip);
        } else {
            assert!(false, "Test address should be a V4 address");
        }
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

        let r = SocketAddrReader::new(&attr_val);
        let addr = if let Ok(addr) = r.get_address() { addr } else {
            assert!(false, "Test address should be a valid address");
            return;
        };

        if let SocketAddr::V6(ip, port) = addr {
            assert_eq!(0x0304, port);
            assert_eq!(0x05060708090A0B0C0D0E0F1A1B1C1D1E, ip);
        } else {
            assert!(false, "Test address should be a V6 address");
        }
    }

    #[test]
    fn xor_socket_addr_ipv4() {
        let attr_val = [
            0x00, 0x01,             // address family
            0x0A, 0x0B,             // port
            0x0C, 0x0D, 0x0E, 0x0F, // ipv4 address
        ];

        let transaction_id = 0xFF;

        let r = XorSocketAddrReader::new(&attr_val, transaction_id);
        let addr = if let Ok(addr) = r.get_address() { addr } else {
            assert!(false, "Test address should be a valid address");
            return;
        };

        if let SocketAddr::V4(ip, port) = addr {
            assert_eq!(0x0A0B, port);
            assert_eq!(0x0C0D0E0F ^ 0x2112A442, ip);
        } else {
            assert!(false, "Test address should be a V4 address");
        }
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

        let transaction_id = 0xFF;

        let r = XorSocketAddrReader::new(&attr_val, transaction_id);
        let addr = if let Ok(addr) = r.get_address() { addr } else {
            assert!(false, "Test address should be a valid address");
            return;
        };

        if let SocketAddr::V6(ip, port) = addr {
            assert_eq!(0x0304, port);
            assert_eq!(0x05060708090A0B0C0D0E0F1A1B1C1D1E ^ (0x2112A442 << 92 | transaction_id), ip);
        } else {
            assert!(false, "Test address should be a V6 address");
        }
    }

    #[test]
    fn string() {
        let attr_val = [
            0x68, 0x65, 0x6C, 0x6C, 0x6F, // hello
        ];

        let r = StringReader::new(&attr_val);
        assert_eq!("hello", r.get_value().unwrap());
        unsafe { assert_eq!("hello", r.get_value_unchecked()); }
    }

    #[test]
    fn fingerprint() {
        let attr_val = [
            0x0A, 0x0B, 0x0C, 0x0D
        ];

        let r = FingerprintReader::new(&attr_val);
        assert_eq!(0x0A0B0C0D ^ 0x5354554E, r.get_value().unwrap())
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

        let r = MessageIntegrityReader::new(&attr_val);
        assert_eq!(&attr_val, r.get_value().unwrap())
    }

    #[test]
    fn unknown_attrs() {
        let attr_val = [
            0x01, 0x02,
        ];

        assert_eq!(1, UnknownAttrsReader::new(&attr_val).unknown_type_codes().count());

        let code = UnknownAttrsReader::new(&attr_val).unknown_type_codes().next().unwrap().unwrap();
        assert_eq!(0x0102, code);
    }

    #[test]
    fn error_code() {
        let attr_val = [
            0x00, 0x00,                     // mandatory padding
            0x40, 0x16,                     // code 222
            0x68, 0x65, 0x6C, 0x6C, 0x6F,   // reason 'hello'
        ];

        let r = ErrorCodeReader::new(&attr_val);

        assert_eq!(222, r.get_code().unwrap());
        assert_eq!("hello", r.get_reason().unwrap());
        unsafe { assert_eq!("hello", r.get_reason_unchecked().unwrap()); }
    }

    #[test]
    fn change_request() {
        let change_ip = 0b00000000000000000000000000000100i32.to_be_bytes();
        let r = ChangeRequestReader::new(&change_ip);
        assert!(r.get_change_ip().unwrap());
        assert!(!r.get_change_port().unwrap());

        let change_port = 0b00000000000000000000000000000010i32.to_be_bytes();
        let r = ChangeRequestReader::new(&change_port);
        assert!(!r.get_change_ip().unwrap());
        assert!(r.get_change_port().unwrap());

        let change_both = 0b00000000000000000000000000000110i32.to_be_bytes();
        let r = ChangeRequestReader::new(&change_both);
        assert!(r.get_change_ip().unwrap());
        assert!(r.get_change_port().unwrap());

        let change_none = 0b00000000000000000000000000000000i32.to_be_bytes();
        let r = ChangeRequestReader::new(&change_none);
        assert!(!r.get_change_ip().unwrap());
        assert!(!r.get_change_port().unwrap());
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
