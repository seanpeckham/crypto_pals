use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

use s1::ch1::*;

static BLOCK_SIZE: usize = 16;

pub fn find_rep_blocks(filename: &str) -> String {
    let f = File::open(filename).unwrap();
    let f = BufReader::new(f);

    for oline in f.lines() {
        let line = oline.unwrap();
        if has_rep_blocks(&hex_to_raw(&line)) {
            return line;
        }
    }
    String::from("Not found")
}

pub fn has_rep_blocks(bytes: &[u8]) -> bool {
    let max_idx = bytes.len() - BLOCK_SIZE;
    let mut left = 0;

    while left < max_idx {
        let mut right = left + BLOCK_SIZE;
        let block1 = &bytes[left..right];

        while right < max_idx {
            let block2 = &bytes[right..(right + BLOCK_SIZE)];
            if block1 == block2 {
                // println!("block1: offset={}, block={}", left, &raw_to_hex(block1));
                // println!("block2: offset={}, block={}", right, &raw_to_hex(block2));
                return true;
            }
            right += BLOCK_SIZE;
        }
        left += BLOCK_SIZE;
    }
    false
}
