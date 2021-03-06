#![allow(dead_code)]

extern crate num;

use std::cmp::*;
use std::collections::BinaryHeap;
use std::collections::LinkedList;
use std::iter::*;

use util::*;
use s1::ch1::*;
use s1::ch2::*;
use s1::ch3::*;

pub fn hamming_distance(block1: &[u8], block2: &[u8]) -> u32 {
    block1.iter().zip(block2)
        .map(|(byte1, byte2)|
             byte1 ^ byte2)
        .fold(0, |dist, byte|
              dist + byte.count_ones())
}

pub struct RepKeyXor {
    pub max_keysize_guess: usize,
    pub block_pairs_per_guess: usize,
    pub guess_count_retained: usize,
}

struct KeySizeGuess {
    score: f32,
    size: usize,
}

struct AttackResult {
    key: Vec<u8>,
    result: Vec<u8>,
    score: f32,
}

impl AttackResult {
    fn new() -> Self {
        AttackResult { key:vec![], result:vec![], score:0.0 }
    }
}

impl PartialEq for KeySizeGuess {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }
    fn ne(&self, other: &Self) -> bool {
        self.score != other.score
    }
}

impl Ord for KeySizeGuess {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.score == other.score {
            if self.size < other.size {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        } else if self.score < other.score {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    }
}

impl PartialOrd for KeySizeGuess {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(other.cmp(self)) // swapped to make it a min heap
    }
}

impl Eq for KeySizeGuess { }

impl RepKeyXor {

    pub fn guess_keysize(&self, buf: &[u8]) -> Vec<usize> {

        let mut guesses = BinaryHeap::new();
        
        for size in 1..self.max_keysize_guess + 1 {
            if size * self.block_pairs_per_guess * 2 > buf.len() {
                break;
            }
            let score = self.score_keysize(size, buf);
            // println!("size: {}, score: {}", size, score);

            guesses.push(KeySizeGuess { size:size, score:score });
        }

        let n = min(self.guess_count_retained, guesses.len());
        (0..n).map(|_| guesses.pop().unwrap().size).collect()
    }

    fn score_keysize(&self, size: usize, buf: &[u8]) -> f32 {
        let mut scores = vec![];

        let mut off1: usize = 0;
        let mut off2: usize = size;

        for _ in 0..self.block_pairs_per_guess {
            let block1 = &buf[off1..off2];
            let block2 = &buf[off2..off2 + size];

            let hd = hamming_distance(block1, block2) as f32;
            scores.push(hd / size as f32);

            // println!("\thd: {}, score: {}, {} {}",
            //          hd, hd / size as f32, raw_to_hex(block1), raw_to_hex(block2));
            // if size < 5 {
            //     for i in 0..size {
            //         println!(" {:08b}.{:08b}", block1[i], block2[i]);
            //     }
            // }

            off1 += size * 2;
            off2 += size * 2;
        }
        scores.iter().fold(0.0, |sum, score| sum + score) / scores.len() as f32
    }

    fn deinterleave(buf: &[u8], stride: usize, offset: usize) -> Vec<u8> {
        buf.iter()
            .enumerate()
            .filter(|&(x, _b)| x % stride == offset)
            .map(|(_x, b)| *b)
            .collect()
    }
    
    fn decrypt_singlebyte_key(input: Vec<u8>) -> AttackResult {
        let mut best_result = AttackResult::new();

        for k in 0..256u16 {
            let result_buf = buffer_xor_1byte(&input, k as u8);

            let score = score_text(&result_buf);

            // if let Some(s) = String::from_utf8(result_buf.clone()).ok() {
            //     if score > 0.0 {
            //         println!("score = {}", score);
            //         println!("text = {}", s);
            //     }
            // }
            
            if score > best_result.score {
                best_result.key = vec![k as u8];
                best_result.result = result_buf;//s.into_bytes();
                best_result.score = score;
            }
            // }
        }
        best_result
    }

    fn try_keysize(buf: &[u8], keysize: usize) -> AttackResult {
        let single_xor_stripes: Vec<_> =
            (0..keysize)
            .map(|offset| RepKeyXor::deinterleave(buf, keysize, offset))
            // .inspect(|stripe| println!("stripe: {}", raw_to_hex(&stripe)))
            .map(|stripe| RepKeyXor::decrypt_singlebyte_key(stripe))
            // .inspect(|stripe| println!("decrypted stripe({}): {}",
            //                            raw_to_hex(&stripe.key),
            //                            raw_to_hex(&stripe.result)))
            .collect();

        let mut result = AttackResult::new();

        'outer: for offset in 0.. {
            for stripe in &single_xor_stripes {

                if offset >= stripe.result.len() {
                    break 'outer;
                }
                result.result.push(stripe.result[offset]);

                if offset == 0 {
                    result.key.push(stripe.key[0]);
                }
            }
        }
        result
    }

    pub fn decrypt_n(&self, buf: &[u8]) -> LinkedList<String> {
        self.guess_keysize(buf).iter()
            // .inspect(|guess| println!("keysize guess: {}", guess))
            .map(|guess| RepKeyXor::try_keysize(buf, *guess))
            // .inspect(|ar| println!("result({}): {}",
            //                        raw_to_hex(&ar.key),
            //                        String::from_utf8(ar.result.clone()).unwrap_or(raw_to_hex(&ar.result))))
            .map(|attack_result| String::from_utf8(attack_result.result).unwrap_or(String::new()))
            .collect()
    }

    pub fn decrypt(&self, buf: &[u8]) -> String {
        // println!("ciphertext: {}", raw_to_hex(&buf));
        for result in self.decrypt_n(buf).into_iter() {
            if result != "" {
                return result;
            }
        }
        String::new()
    }

    pub fn decrypt_file_base64_n(&self, filename: &str) -> LinkedList<String> {
        self.decrypt_n(&base64_to_raw(&file_concat_lines(filename)))
    }   

    pub fn decrypt_file_base64(&self, filename: &str) -> String {
        for result in self.decrypt_file_base64_n(filename).into_iter() {
            if result != "" {
                return result;
            }
        }
        String::new()
    }   
}

