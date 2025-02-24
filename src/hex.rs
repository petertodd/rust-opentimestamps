use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hexed<T>(pub T);

impl<T: AsRef<[u8]>> fmt::LowerHex for Hexed<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
        for b in self.0.as_ref() {
            let b = *b as usize;
            write!(f, "{}", char::try_from(HEX_CHARS[b >> 4]).unwrap())?;
            write!(f, "{}", char::try_from(HEX_CHARS[b & 0x0f]).unwrap())?;
        }
        Ok(())
    }
}

impl<T: AsRef<[u8]>> fmt::UpperHex for Hexed<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
        for b in self.0.as_ref() {
            let b = *b as usize;
            write!(f, "{}", char::try_from(HEX_CHARS[b >> 4]).unwrap())?;
            write!(f, "{}", char::try_from(HEX_CHARS[b & 0x0f]).unwrap())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() {
        assert_eq!(format!("{:x}", Hexed(&[0u8; 0])),
                   "");
        assert_eq!(format!("{:X}", Hexed(&[0u8; 0])),
                   "");

        assert_eq!(format!("{:x}", Hexed(&[0x12u8])),
                   "12");
        assert_eq!(format!("{:X}", Hexed(&[0x12u8])),
                   "12");

        assert_eq!(format!("{:x}", Hexed(&[0x12u8, 0xab, 0xcd, 0xef])),
                   "12abcdef");
        assert_eq!(format!("{:X}", Hexed(&[0x12u8, 0xab, 0xcd, 0xef])),
                   "12ABCDEF");
    }
}
