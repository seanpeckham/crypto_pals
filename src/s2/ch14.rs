#![allow(unused_imports)]

extern crate libc;
extern crate time;

use std::collections::*;

use self::libc::srand;
use self::time::*;

use s2::ch11::{rand_bytes, gen_key};
use s1::ch1::{raw_to_hex, base64_to_raw};
use s1::ch7::*;

pub struct EcbEncryptionOracle2 {
    key: Vec<u8>,
    prefix: Vec<u8>
}

static BLOCK_SIZE: usize = 16;

impl EcbEncryptionOracle2 {

    pub fn new() -> Self {
        unsafe { srand(get_time().nsec as u32); }
        EcbEncryptionOracle2 { key: gen_key(), prefix: rand_bytes((1, 31)) }
    }

    fn gen_unk_str(self: &Self) -> Vec<u8> {
        base64_to_raw("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    }
    
    pub fn gen_ciphertext(self: &Self, data: &[u8]) -> Vec<u8> {
        let mut plaintext = self.prefix.clone();
        plaintext.extend_from_slice(data);
        plaintext.append(&mut self.gen_unk_str());

        encrypt_aes_128_ecb(&self.key, &plaintext).unwrap()
    }
}

pub struct EcbBreaker2 {
    oracle: EcbEncryptionOracle2,
}

pub struct InputPrefix {
    pub prefix: Vec<u8>,
    pub offset: usize
}

impl EcbBreaker2 {
    pub fn new(oracle: EcbEncryptionOracle2) -> Self { EcbBreaker2 { oracle:oracle } }

    fn find_rep_blocks(bytes: &[u8]) -> HashSet<usize> {

        let mut result = HashSet::new();
        let max_idx = bytes.len() - BLOCK_SIZE;
        let mut left = 0;
        
        while left < max_idx {
            let right = left + BLOCK_SIZE;
            let block1 = &bytes[left..right];
            
            if right < max_idx {
                let block2 = &bytes[right..(right + BLOCK_SIZE)];
                if block1 == block2 {
                    result.insert(left);
                }
            }
            left += BLOCK_SIZE;
        }
        result
    }


    pub fn gen_input_prefix(self: &Self) -> Result<InputPrefix, i32> {
        let mut string = vec!['A' as u8; 16];
        let prev = Self::find_rep_blocks(&self.oracle.gen_ciphertext(&string));

        loop {
            string.push('A' as u8);
            let n = string.len();
            let cur = Self::find_rep_blocks(&self.oracle.gen_ciphertext(&string));

            for i in cur.iter() {
                if !prev.contains(i) {
                    string.truncate(n - 32);
                    return Ok(InputPrefix { prefix:string, offset:*i })
                }
            }
        }
    }

    pub fn decrypt(self: &Self) -> Result<Vec<u8>, i32> {
        let input_prefix = try!(self.gen_input_prefix());

        let ciphertext = self.oracle.gen_ciphertext(&input_prefix.prefix);
        if ciphertext.len() % BLOCK_SIZE != 0 {
            return Err(-1)
        }
        let block_count = (ciphertext.len() - input_prefix.offset) / BLOCK_SIZE;

        let mut result = vec![];
        let mut buffer = vec!['A' as u8; BLOCK_SIZE];

        for block_idx in 0..block_count {
            let block = try!(self.decrypt_block(block_idx, buffer, &input_prefix));
            result.extend_from_slice(&block);
            buffer = block;

            if buffer.len() < BLOCK_SIZE { // padding case
                break;
            }
        }
        Ok(result)
    }

    fn decrypt_block(self: &Self, idx: usize, mut buffer: Vec<u8>, prefix_info: &InputPrefix)
                     -> Result<Vec<u8>, i32> {
        let size = buffer.len();

        for byte in 0..size {
            for i in 0..(size - 1) {
                buffer[i] = buffer[i+1];
            }
            if let Ok(byte) = self.decrypt_byte(&mut buffer, size - byte - 1,
                                                idx, prefix_info) {
                buffer[size - 1] = byte;
            } else {
                // assume we've hit padding bytes. this breaks our scheme because as
                // we change the size of the ciphertext, the padding values change
                if byte > 0 {
                    for i in 0..byte - 1 {
                        buffer[i] = buffer[i + (size - byte) - 1];
                    }
                    buffer.resize(byte - 1, 0);
                }
                break;
            }
        }
        Ok(buffer)
    }

    fn inject_buffer(self: &Self, buffer: &[u8], prefix: &Vec<u8>) -> Vec<u8> {
        let mut data = prefix.clone();
        data.extend_from_slice(buffer);
        self.oracle.gen_ciphertext(&data)
    }

    fn decrypt_byte(self: &Self, buffer: &mut [u8], idx: usize,
                    block_idx: usize, prefix_info: &InputPrefix) -> Result<u8, i32> {
        let size = buffer.len();
        let k = prefix_info.offset;
        let ref p = prefix_info.prefix;
        let offset = block_idx * size + k;
        let mut dict = HashMap::with_capacity(256);

        for i in 0..256 {
            buffer[size - 1] = i as u8;
            let block = &self.inject_buffer(buffer, &p)[k..(size + k)];

            let entry: Vec<u8> = block.iter().map(|x| *x).collect();
            dict.insert(entry, i as u8);
        }
        let leak = self.inject_buffer(&vec!['A' as u8; idx], &p);

        dict.remove(&leak[offset..(offset + size)]).ok_or(0)
    }
}
