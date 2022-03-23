use clap::{arg, Command};

mod common;
mod encryption;
mod extract;
mod list;
mod pack;

fn main() {
    let args = Command::new("Mabinogi pack utilities 2")
        .version("v1.3.0")
        .author("regomne <fallingsunz@gmail.com>")
        .subcommand(
            Command::new("pack")
                .about("Create a .it pack")
                .arg(arg!(-i --input <FOLDER> "Set the input folder to pack"))
                .arg(arg!(-o --output <PACK_NAME> "Set the output .it file name"))
                .arg(arg!(-a --additional_data "DEPRECATED: Add original filename to package").hide(true))
        )
        .subcommand(
            Command::new("extract")
                .about("Extract a .it pack")
                .arg(arg!(-i --input <PACK_NAME> "Set the input pack name to extract"))
                .arg(arg!(-o --output <FOLDER> "Set the output folder"))
                .arg(
                    arg!(-f --filter <FILTER> ... "Set a filter when extracting, in regexp, multiple occurrences mean OR")
                        .required(false)
                        .number_of_values(1)
                )
                .arg(arg!(-c --check_additional "DEPRECATED: check additional data of filename").hide(true)),
        )
        .subcommand(
            Command::new("list")
                .about("Output the file list of a .it pack")
                .arg(arg!(-i --input <PACK_NAME> "Set the input pack name to extract"))
                .arg(
                    arg!(-o --output <LIST_FILE_NAME> "Set the list file name, output to stdout if not set")
                        .required(false)
                )
                .arg(arg!(-c --check_additional "DEPRECATED: check additional data of filename").hide(true)),
        )
        .get_matches();

    let ret = match if let Some(matches) = args.subcommand_matches("list") {
        if matches.is_present("check_additional") {
            println!("WARNING: --check_additional has been deprecated");
        }
        list::run_list(
            matches.value_of("input").unwrap(),
            matches.value_of("output"),
        )
    } else if let Some(matches) = args.subcommand_matches("extract") {
        if matches.is_present("check_additional") {
            println!("WARNING: --check_additional has been deprecated");
        }
        extract::run_extract(
            matches.value_of("input").unwrap(),
            matches.value_of("output").unwrap(),
            matches
                .values_of("filter")
                .map(|e| e.collect())
                .unwrap_or(vec![]),
        )
    } else if let Some(matches) = args.subcommand_matches("pack") {
        if matches.is_present("additional_data") {
            println!("WARNING: --additional_data has been deprecated");
        }
        pack::run_pack(
            matches.value_of("input").unwrap(),
            matches.value_of("output").unwrap(),
        )
    } else {
        println!("please select a subcommand (type --help to get details)");
        Ok(())
    } {
        Err(e) => {
            println!("Err: {:?}", e);
            1
        }
        _ => 0,
    };
    std::process::exit(ret);
}
