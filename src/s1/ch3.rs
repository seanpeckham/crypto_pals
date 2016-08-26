#![allow(dead_code)]

use s1::ch2::*;
use std::*;

// https://en.wikipedia.org/wiki/Letter_frequency
static ENGLISH_FREQS: [f32; 26] = [
    8.167, // a
    1.492,
    2.782,
    4.253, // d
    12.702,
    2.228,
    2.015, // g
    6.094,
    6.966,
    0.153, // j
    0.772,
    4.025,
    2.406, // m
    6.749,
    7.507,
    1.929, // p
    0.095,
    5.987,
    6.327, // s
    9.056,
    2.758,
    0.978, // v
    2.361,
    0.150,
    1.974, // y
    0.074
];

static SPACE_FREQ: f32 = 5.1;

pub fn score_text(input: &[u8]) -> f32 {
    let mut text_freqs = [0f32; 26];

    let mut space_count = 0.0;
    let n = input.len() as f32;
    let a = 'a' as usize;
    let z = 'z' as usize;

    for byte in input {
        let ch = *byte as char;

        if *byte >= 127 ||
            (*byte < 32 && !ch.is_whitespace()) {
                return 0.0;
            }
        if ch == ' ' {
            space_count += 1.0;
        }
             
        if let Some(ch) = ch.to_lowercase().next() {
            let val = ch as usize;

            if val >= a && val <= z {
                text_freqs[val - a] += 1.0;
            }
        }
    }

    // https://en.wikipedia.org/wiki/Cosine_similarity#Definition

    let mut dot_product =
        text_freqs.iter()
        .enumerate()
        .map(|(i, f)| f / (n - space_count) * ENGLISH_FREQS[i] / 100.0)
        .fold(0.0, |sum, x| sum + x);

    let space_freq = (space_count / n) * SPACE_FREQ / 100.0;
    dot_product += space_freq;

    let mut guess_mag = 0.0;
    let mut ref_mag = 0.0;
    for i in 0..26 {
        guess_mag += text_freqs[i].powi(2);
        ref_mag += (ENGLISH_FREQS[i] / 100.0).powi(2);
    }
    guess_mag += space_freq.powi(2);
    ref_mag += (SPACE_FREQ / 100.0).powi(2);

    guess_mag = guess_mag.sqrt();
    ref_mag = ref_mag.sqrt();

    let denom = ref_mag * guess_mag;

    if denom == 0.0 {
        return 0.0;
    }

    return dot_product / denom;
}

#[derive(Clone)]
pub struct CipherGuessPair {
    pub ciphertext: Vec<u8>,
    pub guess: Vec<u8>,
    pub score: f32,
}

impl CipherGuessPair {
    pub fn new() -> CipherGuessPair {
        CipherGuessPair { ciphertext:vec![], guess:vec![], score:0.0 }
    }
}

pub fn max_score(left: &CipherGuessPair, right: &CipherGuessPair)
                 -> CipherGuessPair {
    if left.score > right.score {
        left.clone()
    } else {
        right.clone()
    }
}

pub fn decrypt_cipher_xor_1byte_raw(input: &Vec<u8>) -> Vec<u8> {
    (0..256)
        .map(|n| buffer_xor_1byte(&input, n as u8))
        .map(|ref s| CipherGuessPair { ciphertext:vec![], guess:s.clone(), score:score_text(s) })
        // .inspect(|ref gp| println!("score: {}, {}", gp.score,
        //                            String::from_utf8(gp.guess.clone()).unwrap_or(String::new())))
        .fold(CipherGuessPair::new(),
              // |best, cur| better_score(&best, &cur)).guess
              |best, cur| max_score(&best, &cur)).guess
}

pub fn decrypt_cipher_xor_1byte(input: &Vec<u8>) -> String {
    String::from_utf8(decrypt_cipher_xor_1byte_raw(input)).unwrap()
}
