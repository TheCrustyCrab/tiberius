use std::io::{Cursor, Write};
use std::mem;
use byteorder::{WriteBytesExt, LittleEndian};
use bytes::BytesMut;
use super::Encode;

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct FedAuthToken<'a> {
    access_token: &'a str
}

impl<'a> FedAuthToken<'a> {
    #[cfg(feature="aad")]
    pub fn new(access_token: &'a str) -> Self {
        Self {
            access_token
        }
    }
}

impl<'a> Encode<BytesMut> for FedAuthToken<'a> {
    fn encode(self, dst: &mut BytesMut) -> crate::Result<()> {
        let access_token_unicode = self.access_token.encode_utf16().collect::<Vec<_>>();
        let access_token_bytes = unsafe {
            std::slice::from_raw_parts(access_token_unicode.as_ptr() as *const u8, access_token_unicode.len() * 2)
        };
        let token_length = access_token_bytes.len();
        let data_length = token_length + mem::size_of::<u32>(); // include size of token_length
        let mut cursor = Cursor::new(Vec::with_capacity(data_length + mem::size_of::<u32>()));
        cursor.write_u32::<LittleEndian>(data_length as u32)?;
        cursor.write_u32::<LittleEndian>(token_length as u32)?;
        cursor.write(access_token_bytes)?;

        dst.extend(cursor.into_inner());
        Ok(())
    }
}