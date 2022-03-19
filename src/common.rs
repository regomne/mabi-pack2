use crate::encryption;
use anyhow::Error;
use byte_slice_cast::AsSliceOf;
use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const IT_CUSTOM_MAGIC: u32 = 0x3ef613f9;

pub struct FileHeader {
    pub checksum: u32,
    pub version: u8,
    pub file_cnt: u32,
}

impl FileHeader {
    pub fn new<T>(reader: &mut T) -> Result<Self, std::io::Error>
    where
        T: Read,
    {
        Ok(FileHeader {
            checksum: reader.read_u32::<LittleEndian>()?,
            version: reader.read_u8()?,
            file_cnt: reader.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
pub struct FileEntry {
    pub name: String,
    pub checksum: u32,
    pub flags: u32, // 1: compressed; 2: is_encrypted; 4: head_encrypted; 8: ?
    pub offset: u32,
    pub original_size: u32, // decompressed size
    pub raw_size: u32,      // compressed size
    pub key: [u8; 16],
}

pub const FLAG_COMPRESSED: u32 = 1;
pub const FLAG_ALL_ENCRYPTED: u32 = 2;
pub const FLAG_HEAD_ENCRYPTED: u32 = 4;

impl FileEntry {
    pub fn new<T>(reader: &mut T) -> Result<Self, std::io::Error>
    where
        T: Read,
    {
        let str_len = reader.read_u32::<LittleEndian>()?;
        let mut fname = vec![0u8; str_len as usize * 2];
        reader.read_exact(&mut fname)?;
        let fname = String::from_utf16(fname.as_slice_of::<u16>().unwrap())
            .expect("file entry string format error");

        let mut ent = FileEntry {
            name: fname,
            checksum: reader.read_u32::<LittleEndian>()?,
            flags: reader.read_u32::<LittleEndian>()?,
            offset: reader.read_u32::<LittleEndian>()?,
            original_size: reader.read_u32::<LittleEndian>()?,
            raw_size: reader.read_u32::<LittleEndian>()?,
            key: [0; 16],
        };
        reader.read_exact(&mut ent.key)?;
        Ok(ent)
    }
}

pub fn get_final_file_name(fname: &str) -> Result<String, Error> {
    Path::new(fname)
        .file_name()
        .ok_or(Error::msg("not a valid file path"))
        .map(|s| s.to_str().expect("not a valid unicode string").to_owned())
}

pub fn check_additional_data<T>(rd: &mut T, fname: &str) -> Result<bool, Error>
where
    T: Read,
{
    let magic = rd.read_u32::<LittleEndian>()?;
    if magic != IT_CUSTOM_MAGIC {
        return Ok(false);
    }
    let flen = rd.read_u8()? as usize;
    if flen > 25 {
        return Ok(false);
    }
    let mut str_buf = [0u8; 25];
    rd.read_exact(&mut str_buf[..flen])?;

    let origin_fname = String::from_utf8_lossy(&str_buf[..flen]).to_owned();
    if origin_fname != fname {
        return Err(Error::msg(format!(
            "file name not match, which should be {}",
            origin_fname
        )));
    }
    Ok(true)
}

pub fn read_header<T>(fname: &str, rd: &mut T) -> Result<FileHeader, Error>
where
    T: Read + Seek,
{
    let salted_name = fname.to_owned() + encryption::KEY_SALT;
    let key = encryption::gen_header_key(salted_name.as_bytes());
    let offset = encryption::gen_header_offset(fname.as_bytes());
    rd.seek(SeekFrom::Start(offset as u64))?;
    let mut dec_stream = encryption::Snow2Decoder::new(&key, rd);
    Ok(FileHeader::new(&mut dec_stream)?)
}

pub fn validate_header(hdr: &FileHeader) -> Result<(), Error> {
    if hdr.version as u32 + hdr.file_cnt != hdr.checksum {
        Err(Error::msg("header checksum wrong"))
    } else {
        Ok(())
    }
}

pub fn read_entries<T>(
    fname: &str,
    header: &FileHeader,
    rd: &mut T,
) -> Result<Vec<FileEntry>, Error>
where
    T: Read + Seek,
{
    let salted_name = fname.to_owned() + encryption::KEY_SALT;
    let key = encryption::gen_entries_key(salted_name.as_bytes());
    let offset_header = encryption::gen_header_offset(fname.as_bytes());
    let offset_entry = encryption::gen_entries_offset(fname.as_bytes());
    //println!("header offset: {:x}", offset_header);
    //println!("entry offset: {:x}", offset_entry);
    rd.seek(SeekFrom::Start((offset_header + offset_entry) as u64))?;

    let mut dec_stream = encryption::Snow2Decoder::new(&key, rd);
    (0..header.file_cnt)
        .map(|_| FileEntry::new(&mut dec_stream).map_err(Error::new))
        .collect()
}

pub fn validate_entries(entries: &[FileEntry]) -> Result<(), Error> {
    for ent in entries {
        let key_sum = ent.key.iter().fold(0u32, |s, v| s + *v as u32);
        if ent.flags + ent.offset + ent.original_size + ent.raw_size + key_sum != ent.checksum {
            return Err(Error::msg(format!(
                "entry checksum wrong, file name: {}",
                ent.name
            )));
        }
    }
    Ok(())
}
