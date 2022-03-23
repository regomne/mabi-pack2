use crate::common;
use anyhow::{Context, Error};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Write};

pub fn run_list(fname: &str, output: Option<&str>) -> Result<(), Error> {
    let fp = File::open(fname)?;
    let mut rd = BufReader::new(fp);
    let final_file_name = common::get_final_file_name(fname)?;
    let header = common::read_header(&final_file_name, &mut rd).context("reading header failed")?;

    common::validate_header(&header)?;
    if header.version != 2 {
        return Err(Error::msg(format!(
            "header version {} not supported",
            header.version
        )));
    }

    let entries = common::read_entries(&final_file_name, &header, &mut rd)
        .context("reading entries failed")?;
    common::validate_entries(&entries)?;

    let output_stream: Result<Box<dyn Write>, Error> =
        output.map_or(Ok(Box::new(io::stdout())), |path| {
            OpenOptions::new()
                .create(true)
                .write(true)
                .open(path)
                .map(|f| Box::new(f) as Box<dyn Write>)
                .map_err(Error::new)
        });
    let mut output_stream = output_stream?;

    entries.iter().for_each(|e| {
        writeln!(output_stream, "{}", e.name).unwrap();
        /*if (e.flags & 0xfffffff8) != 0 {
            println!("err! {:?}", e);
        }*/
    });
    Ok(())
}
