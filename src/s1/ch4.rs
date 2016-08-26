
use std::io::prelude::*;
use std::fs::File;
use std::io::BufReader;

use s1::ch1::*;
use s1::ch3::*;

pub fn hex_file_to_raw_lines(fname: &str) -> Vec<Vec<u8>> {
    let f = File::open(fname).unwrap();
    let f = BufReader::new(f);
    let mut v = Vec::new();

    for line in f.lines() {
        v.push(hex_to_raw(&line.unwrap()));
    }
    v
}

pub fn find_str_1byte_xor_detail(strings: &Vec<Vec<u8>>) -> CipherGuessPair {
    let guesses: Vec<Vec<u8>> =
        strings.iter()
        .map(|s| decrypt_cipher_xor_1byte_raw(s)).collect();

    let mut best = CipherGuessPair::new();

    for (cipher, guess) in strings.iter().zip(&guesses) {
        let guess_score = score_text(&guess);
        
        // println!("score: {}", guess_score);
        // println!("guess: {}", String::from_utf8(guess.clone()).unwrap_or(String::new()));

        if guess_score > best.score {
            best.ciphertext = cipher.clone();
            best.guess = guess.clone();
            best.score = guess_score;
        }
    }
    best
}

pub fn find_str_1byte_xor(strings: &Vec<Vec<u8>>) -> String {
    String::from_utf8(find_str_1byte_xor_detail(strings).guess).unwrap_or(String::new())
}
