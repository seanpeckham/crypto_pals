extern crate openssl;

use self::openssl::crypto::symm::*;
use self::openssl::error::*;
use s2::ch10::*;
use s2::ch11::gen_key;

pub struct CbcServer16 {
    key: Vec<u8>
}

impl CbcServer16 {
    pub fn new() -> CbcServer16 { CbcServer16 { key: gen_key() } }

    fn escape(string: &[u8]) -> Vec<u8> {
        let mut result = vec![];
        for &c in string {
            if c == ';' as u8 {
                result.extend_from_slice(b"%3B");
            }
            else if c == '=' as u8 {
                result.extend_from_slice(b"%3D");
            }
            else {
                result.push(c);
            }
        }
        result
    }

    pub fn serve(self: &Self, string: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let prefix = b"comment1=cooking%20MCs;userdata=";
        let suffix = b";comment2=%20like%20a%20pound%20of%20bacon";
        let mut plaintext = vec![];

        plaintext.extend_from_slice(prefix);
        plaintext.extend_from_slice(&CbcServer16::escape(&string));
        plaintext.extend_from_slice(suffix);

        Cbc::new(Type::AES_128_ECB, &self.key, &[0; 16]).encrypt(&plaintext)
    }

    pub fn ingest(self: &Self, ciphertext: &[u8]) -> bool {
        Cbc::new(Type::AES_128_ECB, &self.key, &[0; 16])
            .decrypt(ciphertext)
            .unwrap()
            .split(|&c| c == ';' as u8)
            .any(|term| term == b"admin=true")
    }
}

pub fn flip_bit<'a>(string: &'a mut [u8], pos: usize, bits: u8) -> &'a mut [u8] {
    {
        let ref mut byte = string[pos];
        *byte ^= bits;
    }
    string
}

pub fn bit_flip_attack() -> bool {
    let server = CbcServer16::new();
    let mut ciphertext = server.serve(b"x:admin<true").unwrap();

    flip_bit(&mut ciphertext, 17, 1);
    flip_bit(&mut ciphertext, 23, 1);

    server.ingest(&ciphertext)
}
