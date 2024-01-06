use std::string::FromUtf16Error;

pub(crate) trait ToUtf16Bytes {
    fn to_utf16_bytes(&self) -> Vec<u8>;
}

impl ToUtf16Bytes for str {
    #[inline]
    fn to_utf16_bytes(&self) -> Vec<u8> {
        self
            .encode_utf16()
            .flat_map(|word| [(word & 0xFF) as u8, (word & 0xFF00) as u8])
            .collect()
    }
}

pub(crate) trait FromUtf16Bytes {
    fn from_utf16_bytes(bytes: &[u8]) -> Result<Self, FromUtf16Error> where Self: Sized;
}

impl FromUtf16Bytes for String {
    #[inline]
    fn from_utf16_bytes(bytes: &[u8]) -> Result<Self, FromUtf16Error> {
        Self::from_utf16(
            unsafe {
                std::slice::from_raw_parts(bytes.as_ptr() as *const u16, bytes.len() / 2)
            }
        )     
    }
}

#[cfg(test)]
mod tests {
    use super::{ToUtf16Bytes, FromUtf16Bytes};

    #[test]
    fn to_utf16_bytes_succeeds() {
        let text = "hello, world!";

        let text_utf16_bytes = text.to_utf16_bytes();

        assert_eq!(vec![104, 0, 101, 0, 108, 0, 108, 0, 111, 0, 44, 0, 32, 0, 119, 0, 111, 0, 114, 0, 108, 0, 100, 0, 33, 0],
            text_utf16_bytes)
    }

    #[test]
    fn from_utf16_bytes_succeeds() {
        let text_utf16 = [104, 0, 101, 0, 108, 0, 108, 0, 111, 0, 44, 0, 32, 0, 119, 0, 111, 0, 114, 0, 108, 0, 100, 0, 33, 0];

        let text = String::from_utf16_bytes(&text_utf16);

        assert!(text.is_ok());
        assert_eq!(String::from("hello, world!"), text.unwrap());
    }

    #[test]
    fn roundtrip_from_utf16_bytes_to_utf16_bytes() {
        let text = "hello, world!";

        let text_utf16_bytes = text.to_utf16_bytes();
        let text_again = String::from_utf16_bytes(&text_utf16_bytes);

        assert!(text_again.is_ok());
        assert_eq!(String::from("hello, world!"), text_again.unwrap());
    }
}