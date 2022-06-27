use crate::{ReaderErr, Result, SocketAddr};

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

                let addr = if let Ok(b) = b { b } else {
                    return Err(ReaderErr::NotEnoughBytes);
                };

                Ok(SocketAddr::V4 { addr, port })
            }
            2 => {
                let b = self.bytes.get(4..20)
                    .map(|b| b.try_into().unwrap())
                    .map(|b: [u8; 16]| u128::from_be_bytes(b))
                    .ok_or(ReaderErr::NotEnoughBytes);

                let addr = if let Ok(b) = b { b } else {
                    return Err(ReaderErr::NotEnoughBytes);
                };

                Ok(SocketAddr::V6 { addr, port })
            }
            _ => Err(ReaderErr::UnexpectedValue)
        }
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
            Ok(SocketAddr::V4 { addr, port }) => {
                let mask = 0x2112A442;
                Ok(SocketAddr::V4 { addr: addr ^ mask, port })
            }
            Ok(SocketAddr::V6 { addr, port }) => {
                let mask = 0x2112A442 << 92 | self.transaction_id;
                Ok(SocketAddr::V6 { addr: addr ^ mask, port })
            }
        }
    }
}

pub struct StringReader<'a> {
    bytes: &'a [u8],
}

impl <'a> StringReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes
        }
    }

    pub unsafe fn get_value_unchecked(&self) -> &str {
        core::str::from_utf8_unchecked(self.bytes)
    }

    pub fn get_value(&self) -> Result<&str> {
        core::str::from_utf8(self.bytes)
            .map_err(|_| ReaderErr::UnexpectedValue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        if let SocketAddr::V4 { addr, port } = addr {
            assert_eq!(0x0A << 8 | 0x0B, port);
            assert_eq!(0x0C0D0E0F, addr);
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

        if let SocketAddr::V6 { addr, port } = addr {
            assert_eq!(0x0304, port);
            assert_eq!(0x05060708090A0B0C0D0E0F1A1B1C1D1E, addr);
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

        if let SocketAddr::V4 { addr, port } = addr {
            assert_eq!(0x0A << 8 | 0x0B, port);
            assert_eq!(0x0C0D0E0F ^ 0x2112A442, addr);
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

        if let SocketAddr::V6 { addr, port } = addr {
            assert_eq!(0x0304, port);
            assert_eq!(0x05060708090A0B0C0D0E0F1A1B1C1D1E ^ (0x2112A442 << 92 | transaction_id), addr);
        } else {
            assert!(false, "Test address should be a V6 address");
        }
    }

    #[test]
    fn string() {
        let attr_val = [
            0x68, 0x65, 0x6C, 0x6C, 0x6F // hello
        ];

        let r = StringReader::new(&attr_val);
        assert_eq!("hello", r.get_value().unwrap());
        unsafe { assert_eq!("hello", r.get_value_unchecked()); }
    }
}
