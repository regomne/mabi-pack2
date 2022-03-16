use crate::common::{self, FileEntry};
use crate::encryption;
use anyhow::{Context, Error};
use miniz_oxide::inflate::decompress_to_vec_zlib;
use regex::Regex;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, MAIN_SEPARATOR};

fn write_file(root_dir: &str, rel_path: &str, content: Vec<u8>) -> Result<(), Error> {
    let fname = Path::new(root_dir).join(rel_path.replace("\\", &MAIN_SEPARATOR.to_string()));
    let par = fname.parent().ok_or(Error::msg(format!(
        "unrecognized path: {}",
        fname.to_string_lossy().to_owned()
    )))?;
    std::fs::create_dir_all(par)?;
    let mut fs = OpenOptions::new().create(true).write(true).open(fname)?;
    fs.write_all(&content)?;
    Ok(())
}

fn extract_file<T>(
    stm: &mut T,
    start_off: u64,
    ent: &FileEntry,
    root_dir: &str,
) -> Result<(), Error>
where
    T: Read + Seek,
{
    stm.seek(SeekFrom::Start(start_off + ent.offset as u64 * 1024))?;
    let mut content = vec![0u8; ent.raw_size as usize];
    let fkey = encryption::gen_file_key(ent.name.as_bytes(), &ent.key);

    if (ent.flags & common::FLAG_ALL_ENCRYPTED) != 0 {
        let mut dec_stm = encryption::Decoder::new(&fkey, stm);
        dec_stm.read_exact(&mut content)?;
    } else {
        stm.read_exact(&mut content)?;
    }

    if (ent.flags & common::FLAG_HEAD_ENCRYPTED) != 0 {
        let mut rd = Cursor::new(&content);
        let mut dec_stm = encryption::Decoder::new(&fkey, &mut rd);
        let mut content2 = [0u8; 1024];
        let dec_len = std::cmp::min(content.len(), 1024);
        dec_stm.read_exact(&mut content2[..dec_len])?;
        content[..dec_len].copy_from_slice(&content2[..dec_len]);
    }

    let content = if (ent.flags & common::FLAG_COMPRESSED) != 0 {
        let v = decompress_to_vec_zlib(&content)
            .map_err(|e| Error::msg(format!("decompress failed: {:?}", e)))?;
        if v.len() != ent.original_size as usize {
            return Err(Error::msg("original size not match"));
        }
        v
    } else {
        content
    };
    write_file(root_dir, &ent.name, content)
}

fn make_regex(strs: Vec<&str>) -> Result<Vec<Regex>, Error> {
    strs.into_iter()
        .map(|s| {
            Regex::new(&s)
                .map_err(|e| Error::msg("Invalid regex:".to_string() + s + ", " + &e.to_string()))
        })
        .collect()
}

pub fn run_extract(
    fname: &str,
    output_folder: &str,
    filters: Vec<&str>,
    skip_validating: bool,
) -> Result<(), Error> {
    let fp = File::open(fname)?;
    let mut rd = BufReader::new(fp);
    let final_file_name = common::get_final_file_name(fname)?;
    let header = common::read_header(&final_file_name, &mut rd).context("reading header failed")?;

    if !skip_validating {
        common::validate_header(&header)?;
    }

    if header.version != 2 {
        return Err(Error::msg(format!(
            "header version {} not supported",
            header.version
        )));
    }

    let entries = common::read_entries(&final_file_name, &header, &mut rd)
        .context("reading entries failed")?;
    if !skip_validating {
        common::validate_entries(&entries)?;
    }

    let cur_pos = rd.seek(SeekFrom::Current(0))?;
    let content_start_off = (cur_pos + 1023) & 0u64.wrapping_sub(1024);

    let filters = make_regex(filters)?;

    for ent in entries {
        if filters.len() == 0 || filters.iter().any(|re| re.find(&ent.name).is_some()) {
            extract_file(&mut rd, content_start_off, &ent, output_folder)
                .context(format!("extracting {} failed", ent.name))?;
        }
    }
    Ok(())
}
