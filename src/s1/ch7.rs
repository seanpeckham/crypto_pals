#![allow(dead_code)]

extern crate openssl;

use self::openssl::crypto::symm::*;
use self::openssl::error::ErrorStack;

pub fn encrypt_aes_128_ecb(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    encrypt(Type::AES_128_ECB, key, None, data)
}

pub fn decrypt_aes_128_ecb(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    decrypt(Type::AES_128_ECB, key, None, data)
}

