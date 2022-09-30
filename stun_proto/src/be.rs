/*
  The two bytes 'inside' the u16be are BIG ENDIAN
*/
#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[repr(C)]
struct u16be(u16);

impl From<u16> for u16be {
    fn from(val: u16) -> Self {
        Self(val.to_be())
    }
}

impl<'a> From<&'a u16> for &'a u16be {
    fn from(borrow: &'a u16) -> Self {
        unsafe {
            core::mem::transmute(borrow)
        }
    }
}

impl<'a> From<&'a mut u16> for &'a mut u16be {
    fn from(borrow: &'a mut u16) -> Self {
        unsafe {
            core::mem::transmute(borrow)
        }
    }
}

impl From<[u8; 2]> for u16be {
    fn from(val: [u8; 2]) -> Self {
        Self(u16::from_ne_bytes(val))
    }
}

impl<'a> From<&'a [u8; 2]> for &'a u16be {
    fn from(borrow: &'a [u8; 2]) -> Self {
        unsafe {
            core::mem::transmute(borrow)
        }
    }
}

impl<'a> From<&'a mut [u8; 2]> for &'a mut u16be {
    fn from(borrow: &'a mut [u8; 2]) -> Self {
        unsafe {
            core::mem::transmute(borrow)
        }
    }
}

impl Into<u16> for u16be {
    fn into(self) -> u16 {
        self.0.to_be()
    }
}

impl Into<u16> for &u16be {
    fn into(self) -> u16 {
        self.0.to_be()
    }
}

impl Into<u16> for &mut u16be {
    fn into(self) -> u16 {
        self.0.to_be()
    }
}

impl<'a> TryInto<&'a u16be> for &'a [u8] {
    type Error = ();

    fn try_into(self) -> Result<&'a u16be, Self::Error> {
        let bytes = self.get(0..2).ok_or(())?;
        let bytes: &[u8; 2] = bytes.try_into().map_err(|_| ())?;
        Ok(bytes.into())
    }
}

impl core::ops::Add<u16be> for u16be {
    type Output = Self;

    fn add(self, rhs: u16be) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl core::ops::Add<u16> for u16be {
    type Output = Self;

    fn add(self, rhs: u16) -> Self::Output {
        Self(self.0 + rhs.to_be())
    }
}

impl core::ops::AddAssign<u16be> for u16be {
    fn add_assign(&mut self, rhs: u16be) {
        self.0 += rhs.0;
    }
}

impl core::ops::AddAssign<u16> for u16be {
    fn add_assign(&mut self, rhs: u16) {
        self.0 += rhs.to_be();
    }
}

impl u16be {
    fn set(&mut self, val: u16) { self.0 = val.to_be() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn val() {
        // Take u16 and make it u16be
        let be = u16be::from(0x0102);
        let be = be + 0x0102;

        assert_eq!(0x0204u16, be.into());

        let be = be + be;
        assert_eq!(0x0408u16, be.into());
    }

    #[test]
    fn mutable_ref() {
        let mut buf = [1, 2];
        let be_val = u16be::from(buf);

        let be_ref: &mut u16be = (&mut buf).into();
        *be_ref += be_val;

        assert_eq!(0x0204u16, be_ref.into());
    }

    struct StunMsgRef<'a> {
        typ: &'a u16be,
        len: &'a u16be,
    }

    impl<'a> StunMsgRef<'a> {
        fn new(bytes: &'a [u8]) -> Option<Self> {
            Some(Self {
                typ: bytes.get(0..2)?.try_into().ok()?,
                len: bytes.get(2..4)?.try_into().ok()?,
            })
        }
    }

    #[test]
    fn stun_msg_ref() {
        let buf = [1, 2, 3, 4];

        let stun = StunMsgRef::new(&buf).unwrap();

        assert_eq!(0x0102u16, stun.typ.into());
        assert_eq!(0x0304u16, stun.len.into());
    }

    #[repr(C)]
    struct StunMsg {
        typ: u16be,
        len: u16be,
    }

    impl StunMsg {
        fn new<'a>(bytes: &'a [u8; core::mem::size_of::<StunMsg>()]) -> &'a StunMsg {
            unsafe {
                core::mem::transmute(bytes.as_ptr())
            }
        }

        fn new_mut<'a>(bytes: &'a mut [u8; core::mem::size_of::<StunMsg>()]) -> &'a mut StunMsg {
            unsafe {
                core::mem::transmute(bytes.as_ptr())
            }
        }
    }

    #[test]
    fn stun_msg() {
        let buf = [1, 2, 3, 4];
        let stun = StunMsg::new(&buf);

        assert_eq!(0x0102u16, stun.typ.into());
        assert_eq!(0x0304u16, stun.len.into());
    }

    #[test]
    fn stun_msg_mut() {
        let mut buf = [1, 2, 3, 4];
        let mut stun = StunMsg::new_mut(&mut buf);

        stun.typ += 0x0102;
        stun.len += 0x0304;

        assert_eq!(0x0204u16, stun.typ.into());
        assert_eq!(0x0608u16, stun.len.into());
    }

    fn x(a: &u8) -> bool { true }

    fn y(b: &mut u8) -> bool { x(b) }

}
