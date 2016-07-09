use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, SeekFrom};

use crypto::hmac::Hmac;
use crypto::pbkdf2;
use crypto::ripemd160::Ripemd160;

use xts;
use time;

use threadpool::ThreadPool;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;

use pbr::ProgressBar;

const SECTOR_SIZE: u64 = 512;
const BUFFER_SIZE: usize = 1024*128;
const JOB_COUNT: usize = BUFFER_SIZE / SECTOR_SIZE as usize;


pub struct TCFinder {
    file: File
}

impl TCFinder {
    pub fn new(drive_path: &str) -> TCFinder {
        TCFinder {
            file: File::open(&drive_path).expect("Opening file failed!")
        }
    }
    
    pub fn scan(&self, sector_ranges: &[(u64, u64)], password: String) -> Vec<u64> {
        let total_sectors_count = count_total_sectors(sector_ranges);
        let scan_start_time = time::precise_time_ns();

        let mut progressbar = ProgressBar::new(total_sectors_count);
        progressbar.format("╢▌▌░╟");

        // TODO: Fix this..
        let shared_password = Arc::new(password);
        
        let mut buf_reader = BufReader::with_capacity(BUFFER_SIZE, &self.file);
        // Buffer while reading data.
        let mut buf = [0u8; BUFFER_SIZE];

        // Vec of all potential headers.
        let mut found_sectors: Vec<u64> = Vec::new();

        let threadpool = ThreadPool::new(4);
        let (tx, rx) = mpsc::channel();

        for &(start_sector, end_sector) in sector_ranges {

            progressbar.message(&format!("[{}-{}]:  ", start_sector, end_sector));
            
            let start_bytes = start_sector * SECTOR_SIZE;
            buf_reader.seek(SeekFrom::Start(start_bytes)).expect("Seeking to start failed!");
            let mut i = start_sector;
            
            while i <= end_sector {
                {
                    buf_reader.read(&mut buf).expect("Filling buffer failed!");

                    let mut jobs = 0u8;

                    for j in 0..JOB_COUNT {
                        // Sector range might not be multiple of buffer size. Break if over end_sector.
                        if i + j as u64 > end_sector {break;}


                        let pass = shared_password.clone();
                        jobs += 1;
                        let tx = tx.clone();
                        threadpool.execute(move || {
                            // Skip if 00 00 00 00 00 at start, unlikely to be a header.
                            if &buf[j*SECTOR_SIZE as usize..j*SECTOR_SIZE as usize + 5] == [0u8;5] {
                                tx.send(None).unwrap();
                                return;
                            }
                            
                            let mut hmac: Hmac<Ripemd160> = Hmac::new(Ripemd160::new(),
                                                                      pass.as_bytes());
                            // First 64 bytes of header is salt.
                            let salt = &buf[j*SECTOR_SIZE as usize..j*SECTOR_SIZE as usize +64];
                            // Only need first block (16 bytes) to decrypt magic bytes ("TRUE").
                            let header =
                                &buf[j*SECTOR_SIZE as usize + 64..
                                     j*SECTOR_SIZE as usize + 64 + 16];
                            let mut header_keypool = [0u8; 64];
                            pbkdf2::pbkdf2(&mut hmac, salt, 2000, &mut header_keypool);
                            
                            let key1 = &header_keypool[..32];
                            let key2 = &header_keypool[32..];
                            let result = xts::xts_decrypt(key1, key2, 0, header);

                            let found = &result[..4] == [0x54, 0x52, 0x55, 0x45];
                            if found {
                                tx.send(
                                    Some((i*SECTOR_SIZE, i + j as u64, arr_as_hex_str(&result)))
                                ).unwrap();
                                
                            } else {
                                tx.send(None).unwrap();
                            }
                        });

                        if jobs >= 32 {
                            collect_results(&rx, jobs, &mut progressbar, &mut found_sectors);
                            jobs = 0;
                        }
                    }

                    collect_results(&rx, jobs, &mut progressbar, &mut found_sectors);

                    buf_reader.consume(BUFFER_SIZE);
                    i += BUFFER_SIZE as u64 / 512;
                }
            }
        }

        let scan_end_time = time::precise_time_ns();
        println!("\nDone! Time: {}s", (scan_end_time - scan_start_time) / 1000000000);

        found_sectors
    }
}

fn collect_results(rx: &Receiver<Option<(u64,u64,String)>>,
                   job_count: u8,
                   progressbar: &mut ProgressBar,
                   found_sectors: &mut Vec<u64>) {
    for _ in 0..job_count {
        match rx.recv().unwrap() {
            None => {},
            Some((a, b, c)) => {
                found_sectors.push(b);
                println!("\n\x1b\x5b1;32;1mFOUND: {} = {} LBA", a, b);
                println!("Decrypted: {}\x1b\x5b1;0m", c);
            }
        }
        progressbar.inc();
    }
}

fn arr_as_hex_str(arr: &[u8]) -> String {
    arr.iter().map(|b| format!("{:02X} ", b)).collect::<String>()
}

fn count_total_sectors(sector_ranges: &[(u64, u64)]) -> u64 {
    sector_ranges.iter().fold(0, |sum, &range| sum + (range.1 - range.0 + 1))
}


