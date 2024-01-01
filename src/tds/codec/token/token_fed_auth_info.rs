use std::{io::Cursor, mem};
use crate::{error::Error, sql_read_bytes::SqlReadBytes};
use byteorder::{ReadBytesExt, LittleEndian};
use futures_util::AsyncReadExt;

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/0e4486d6-d407-4962-9803-0c1a4d4d87ce
const FED_AUTH_INFOID_STSURL: u8 = 0x01;
const FED_AUTH_INFOID_SPN: u8 = 0x02;

/// Federated authentication information provided by the server.
#[derive(Debug)]
pub struct TokenFedAuthInfo {
    sts_url: String,
    spn: String
}

impl TokenFedAuthInfo {
    pub(crate) fn sts_url(&self) -> &str {
        &self.sts_url
    }

    pub(crate) fn spn(&self) -> &str {
        &self.spn
    }
    
    pub(crate) async fn decode_async<R>(src: &mut R) -> crate::Result<Self>
    where
        R: SqlReadBytes + Unpin,
    {
        let token_length = src.read_u32_le().await? as usize - 4; // skip optionCount
        let option_count = src.read_u32_le().await?; //mandatory, can be 0
        let mut bytes = vec![0; token_length];
        src.read_exact(&mut bytes[0..token_length]).await?;

        // infoId + infoDataLen + infoDataOffset
        const OPTION_SIZE: u32 = (mem::size_of::<u8>() + 2 * mem::size_of::<u32>()) as u32;
        let total_option_size = option_count * OPTION_SIZE;
        
        let mut option_cursor = Cursor::new(&bytes[..total_option_size as usize]);

        let mut sts_url = None;
        let mut spn = None;

        for _ in 0..option_count as usize {
            let info_id = option_cursor.read_u8()?;
            let info_data_len = option_cursor.read_u32::<LittleEndian>()? as usize;
            let info_data_offset = option_cursor.read_u32::<LittleEndian>()? as usize - 4; // from optionCount
            let data = &bytes[info_data_offset..info_data_offset+info_data_len];
            let data_unicode = unsafe { std::slice::from_raw_parts(data.as_ptr() as *const u16, data.len() / 2) };
            let data_text = String::from_utf16_lossy(data_unicode);
            match info_id {
                FED_AUTH_INFOID_STSURL => sts_url = Some(data_text),
                FED_AUTH_INFOID_SPN => spn = Some(data_text),
                _ => {}
            };
        }

        match (sts_url, spn) {
            (Some(sts_url), Some(spn)) => Ok(Self {sts_url, spn}),
            _ => Err(Error::Protocol("Failed to read FedAuthInfo".into()))
        }
    }
}