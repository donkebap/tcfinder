#![feature(plugin, test, simd_ffi, repr_simd)]

extern crate crypto;
extern crate docopt;
extern crate num;
extern crate pbr;
extern crate rustc_serialize;
extern crate test;
extern crate threadpool;
extern crate time;
extern crate serde;

mod aes;
mod gf2n;
mod partitioninfo;
mod tcfinder;
mod xts;

use docopt::Docopt;
use tcfinder::TCFinder;
use serde::Deserialize;

const USAGE: &str = "
TrueCrypt Volume Header Finder.

Finds sector of TrueCrypt Volume Header if created with default config.

Run as admin!

Search whole partition with: '\\\\.\\D:' (Windows), '/dev/sdd1' (Linux)
or normal path to a file.


Usage:
tcfinder <path> <password> (<start> <end> | --ranges=<file>)
tcfinder (-h | --help)

Options:
  -h, --help           Show this screen.
  --ranges=<file>      Text file with sector ranges. Format: 'start;end'. Every sector range on new line.
";

#[derive(Debug, Deserialize)]
struct Args {
    arg_path: String,
    arg_password: String,
    arg_start: u64,
    arg_end: u64,
    flag_ranges: String,
}

fn main() {
    let args: Args = Docopt::new(USAGE).and_then(|d| d.deserialize()).unwrap_or_else(|e| e.exit());

    let mut tc = TCFinder::new(&args.arg_path);

    let sector_ranges = if !args.flag_ranges.is_empty() {
        read_sector_ranges(&args.flag_ranges)
    } else {
        vec![(args.arg_start, args.arg_end)]
    };

    let results = tc.scan(&sector_ranges, args.arg_password);

    if !results.is_empty() {
        println!("\x1b\x5b1;32;1mPotential headers: {:?}\x1b\x5b1;0m", results);
    } else {
        println!("\x1b\x5b1;31;1mNo headers found.\x1b\x5b1;0m");
    }
}

fn read_sector_ranges(path: &str) -> Vec<(u64, u64)> {
    use std::io::{BufRead, BufReader};
    use std::str::FromStr;

    let mut sector_ranges: Vec<(u64, u64)> = Vec::new();
    if let Ok(file) = std::fs::File::open(path) {
        for line in BufReader::new(file).lines() {
            let mut line = line.expect("Could not read line.");
            if line.contains('#') {
                line = String::from(line.split('#').collect::<Vec<&str>>()[0].trim());
            }

            if !line.is_empty() {
                let range_str = line.split(';').collect::<Vec<&str>>();
                sector_ranges.push((
                    u64::from_str(range_str[0]).expect("Invalid char in range list."),
                    u64::from_str(range_str[1]).expect("Invalid char in range list."),
                ));
            }
        }
    } else {
        println!("Could not open file for sector ranges.");
    }
    sector_ranges
}
