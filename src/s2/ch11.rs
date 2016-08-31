extern crate libc;
extern crate openssl;

use self::libc::rand;
use self::openssl::crypto::symm::*;

use s2::ch10::*;
use s1::ch7::*;
use s1::ch8::*;

pub fn gen_key() -> Vec<u8> {
    (0..16)
        .map(|_| unsafe { rand() } as u8)
        .collect()
}

fn rand_bytes(range: (i32, i32)) -> Vec<u8> {
    unsafe { (0..(rand() % (range.1 - range.0) + range.0))
              .map(|_| rand() as u8)
              .collect()
    }
}

pub fn encryption_oracle(data: &[u8]) -> Vec<u8> {
    let key = gen_key();

    let mut d = rand_bytes((5, 10));
    d.extend_from_slice(data);
    d.append(&mut rand_bytes((5, 10)));
    
    if unsafe { rand() } % 2 == 0 {

        let mut iv = [0u8; 16];
        for i in iv.iter_mut() {
            *i = unsafe { rand() as u8 };
        }
        Cbc::new(Type::AES_128_ECB, &key, &iv).encrypt(&d).unwrap()
    }
    else {
        encrypt_aes_128_ecb(&key, &d).unwrap()
    }
}

pub enum CipherType {
    Ecb,
    Cbc
}

pub fn detect_cipher_type(ciphertext: &[u8]) -> CipherType {
    if has_rep_blocks(ciphertext) {
        CipherType::Ecb
    } else {
        CipherType::Cbc
    }
}
