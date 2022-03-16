use crate::common::{self, FileEntry};
use crate::encryption;
use anyhow::{Context, Error};
use byte_slice_cast::AsByteSlice;
use byteorder::{LittleEndian, WriteBytesExt};
use miniz_oxide::deflate::compress_to_vec_zlib;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use walkdir::WalkDir;

fn get_rel_path(root_dir: &str, full_path: &str) -> Result<String, Error> {
    let rel_name = Path::new(full_path).strip_prefix(root_dir).expect(&format!(
        "strip path error, full:{}, root:{}",
        full_path, root_dir
    ));
    Ok(rel_name.to_string_lossy().into_owned())
}

fn need_compress(fname: &str) -> bool {
    fname.ends_with(".txt")
        || fname.ends_with(".xml")
        || fname.ends_with(".dds")
        || fname.ends_with(".pmg")
        || fname.ends_with(".set")
}

fn pack_file(root_dir: &str, rel_path: &str) -> Result<(FileEntry, Vec<u8>), Error> {
    let mut stm = vec![];
    let mut fp = File::open(Path::new(root_dir).join(rel_path))?;
    fp.read_to_end(&mut stm)?;
    let original_size = stm.len();
    let (raw_stm, flags) = if need_compress(rel_path) {
        (compress_to_vec_zlib(&stm, 5), 1)
    } else {
        (stm, 0)
    };
    Ok((
        FileEntry {
            name: rel_path.to_owned(),
            checksum: 0,
            flags,
            offset: 0,
            original_size: original_size as u32,
            raw_size: raw_stm.len() as u32,
            key: [0; 16],
        },
        raw_stm,
    ))
}

fn write_header<T>(file_cnt: u32, key: &[u8], wr: &mut T) -> Result<(), Error>
where
    T: Write,
{
    const IT_VERSION: u8 = 2;
    let checksum = file_cnt + IT_VERSION as u32;
    let mut enc_stm = encryption::Encoder::new(key, wr);
    enc_stm.write_u32::<LittleEndian>(checksum)?;
    enc_stm.write_u8(IT_VERSION)?;
    enc_stm.write_u32::<LittleEndian>(file_cnt)?;
    Ok(())
}

fn write_entries<T>(entries: &[FileEntry], key: &[u8], wr: &mut T) -> Result<(), Error>
where
    T: Write,
{
    let mut enc_stm = encryption::Encoder::new(key, wr);
    entries
        .iter()
        .map(|ent| -> Result<(), Error> {
            let u16_str: Vec<u16> = ent.name.chars().map(|c| c as u32 as u16).collect();
            enc_stm.write_u32::<LittleEndian>(u16_str.len() as u32)?;
            enc_stm.write_all(u16_str.as_byte_slice())?;
            enc_stm.write_u32::<LittleEndian>(ent.checksum)?;
            enc_stm.write_u32::<LittleEndian>(ent.flags)?;
            enc_stm.write_u32::<LittleEndian>(ent.offset)?;
            enc_stm.write_u32::<LittleEndian>(ent.original_size)?;
            enc_stm.write_u32::<LittleEndian>(ent.raw_size)?;
            enc_stm.write_all(&ent.key)?;
            Ok(())
        })
        .collect()
}

fn ceil_1024(v: u64) -> u64 {
    (v + 1023) & 0u64.wrapping_sub(1024)
}

pub fn run_pack(input_folder: &str, output_fname: &str, add_data: bool) -> Result<(), Error> {
    let file_names: Vec<String> = WalkDir::new(input_folder)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.file_type().is_dir())
        .map(|e| get_rel_path(input_folder, e.into_path().to_str().unwrap()))
        .collect::<Result<Vec<String>, Error>>()
        .context("traversing dir failed")?;

    let entries_size = file_names
        .iter()
        .map(|s| s.chars().count() * 2 + 40)
        .sum::<usize>();

    let final_file_name = common::get_final_file_name(output_fname)?;
    let salted_name = final_file_name.clone() + encryption::KEY_SALT;
    let header_off = encryption::gen_header_offset(final_file_name.as_bytes());
    let entries_off = encryption::gen_entries_offset(final_file_name.as_bytes());
    let header_key = encryption::gen_header_key(salted_name.as_bytes());
    let entries_key = encryption::gen_entries_key(salted_name.as_bytes());

    if add_data && final_file_name.len() > 25 {
        return Err(Error::msg(
            "file name too long when has --aditional-data, max is 25",
        ));
    }

    let fs = OpenOptions::new()
        .create(true)
        .write(true)
        .open(output_fname)?;
    let mut stm = BufWriter::new(fs);

    let start_content_off = ceil_1024((header_off + entries_off + entries_size) as u64);
    let mut content_off = start_content_off;
    let mut entries = Vec::<FileEntry>::with_capacity(file_names.len());
    for name in file_names {
        let (mut ent, content) =
            pack_file(input_folder, &name).context(format!("packing {} failed", name))?;
        stm.seek(SeekFrom::Start(content_off))?;
        stm.write_all(&content)?;
        ent.offset = ((content_off - start_content_off) / 1024) as u32;
        ent.checksum = ent.offset + ent.raw_size + ent.original_size + ent.flags;
        content_off = ceil_1024(content_off + ent.raw_size as u64);
        entries.push(ent);
    }

    stm.seek(SeekFrom::Start((header_off + entries_off) as u64))?;
    write_entries(&entries, &entries_key, &mut stm).context("writing entries failed")?;

    stm.seek(SeekFrom::Start(header_off as u64))?;
    write_header(entries.len() as u32, &header_key, &mut stm).context("writing header failed")?;

    if add_data {
        stm.seek(SeekFrom::Start(0))?;
        stm.write_u32::<LittleEndian>(common::IT_CUSTOM_MAGIC)?;
        stm.write_u8(final_file_name.len() as u8)?;
        stm.write_all(final_file_name.as_bytes())?;
    }

    Ok(())
}
