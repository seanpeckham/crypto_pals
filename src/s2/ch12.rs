use std::collections::*;

use s2::ch11::*;
use s1::ch1::*;
use s1::ch7::*;

pub struct EcbEncryptionOracle {
    key: Vec<u8>
}

impl EcbEncryptionOracle {

    pub fn new() -> Self { EcbEncryptionOracle { key: gen_key() } }

    fn gen_unk_str(self: &Self) -> Vec<u8> {
        base64_to_raw("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    }
    
    pub fn gen_ciphertext(self: &Self, data: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(data);
        plaintext.append(&mut self.gen_unk_str());
        
        encrypt_aes_128_ecb(&self.key, &plaintext).unwrap()
    }
}

pub struct EcbBreaker {
    oracle: EcbEncryptionOracle,
}

impl EcbBreaker {
    pub fn new(oracle: EcbEncryptionOracle) -> Self { EcbBreaker { oracle:oracle } }
    
    fn discover_block_size(self: &Self) -> usize {
        let mut data = Vec::new();
        let mut first_byte = None;
        loop {
            data.push('A' as u8);
            let ciphertext = self.oracle.gen_ciphertext(&data);
            match first_byte {
                Some(byte) => {
                    if byte == ciphertext[data.len() - 1] {
                        break;
                    }
                }
                None => {
                    first_byte = Some(ciphertext[0]);
                }
            }
        }
        data.len() - 1
    }

    pub fn decrypt(self: &Self) -> Option<Vec<u8>> {
        let block_size = self.discover_block_size();

        let ciphertext = self.oracle.gen_ciphertext(&vec![]);
        if ciphertext.len() % block_size != 0 {
            return None
        }
        let block_count = ciphertext.len() / block_size;

        let mut result = vec![];
        let mut buffer = vec!['A' as u8; block_size];

        for block_idx in 0..block_count {
            let block = self.decrypt_block(block_idx, buffer);
            result.extend_from_slice(&block);
            buffer = block;

            if buffer.len() < block_size {
                if block_idx + 1 == block_count {
                    // padding case
                    break
                }
                // something went wrong
                return None
            }
        }
        Some(result)
    }

    fn decrypt_block(self: &Self, idx: usize, mut buffer: Vec<u8>) -> Vec<u8> {
        let size = buffer.len();

        for byte in 0..size {
            for i in 0..(size - 1) {
                buffer[i] = buffer[i+1];
            }
            if let Some(byte) = self.decrypt_byte(&mut buffer, size - byte - 1, idx) {
                buffer[size - 1] = byte;
            } else {
                // assume we've hit padding bytes. this breaks our scheme because as
                // we change the size of the ciphertext, the padding values change
                for i in 0..byte - 1 {
                    buffer[i] = buffer[i + (size - byte) - 1];
                }
                buffer.resize(byte - 1, 0);
                break;
            }
        }
        buffer
    }

    fn decrypt_byte(self: &Self, buffer: &mut [u8], idx: usize,
                        block_idx: usize) -> Option<u8> {
        let size = buffer.len();
        let offset = block_idx * size;
        let mut dict = HashMap::with_capacity(256);

        for i in 0..256 {
            buffer[size - 1] = i as u8;
            let block = &self.oracle.gen_ciphertext(&buffer)[0..size];

            let entry: Vec<u8> = block.iter().map(|x| *x).collect();
            dict.insert(entry, i as u8);
        }
        let leak = self.oracle.gen_ciphertext(&vec!['A' as u8; idx]);

        dict.remove(&leak[offset..(offset + size)])
    }
}
