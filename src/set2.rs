#![allow(dead_code)]

extern crate openssl;

use self::openssl::crypto::symm::Type;
use std::env;
use std::io::prelude::*;
use std::fs::File;

#[macro_use]
mod util;
use util::*;

use_ch!(s1, ch1);//, ch2, ch3, ch4, ch5, ch6, ch7, ch8);
use_ch!(s2, ch9, ch10, ch11, ch12, ch13, ch14, ch15, ch16);

fn challenge9() {
    let mut plaintext = b"YELLOW_SUBMARINE".to_vec();
    let paddedtext = b"YELLOW_SUBMARINE\x04\x04\x04\x04".to_vec();
    pkcs_7_pad(&mut plaintext, 20);
    assert_eq!(plaintext, paddedtext);
}

fn challenge10() {
    let key = b"YELLOW SUBMARINE";
    let iv = [0; 16];

    let input_str = file_concat_lines("texts/ch10.txt");
    let input = base64_to_raw(&input_str);
    let crypter = Cbc::new(Type::AES_128_ECB, key, &iv);
    let output = crypter.decrypt(&input).unwrap();
    // println!("({}): {}", output.len(), raw_to_hex(&output));
    // print!("{}", String::from_utf8(output).unwrap());
    let mut f = File::open("texts/ch10-solution.txt").unwrap();
    let mut solution = String::new();
    f.read_to_string(&mut solution).ok();
    assert_eq!(output, solution.as_bytes());
    

    let plaintext = b"AAAABBBBCCCCDDDDeeeeffffgggghhhhIIIIJJJJKKKK";
    let cbc = Cbc::new(Type::AES_128_ECB, key, &iv);
    let ciphertext = cbc.encrypt(plaintext).unwrap();
    // println!("ciphertext({}): {}", ciphertext.len(), raw_to_hex(&ciphertext));
    let decrypted = cbc.decrypt(&ciphertext).unwrap();
    // println!("decrypted plaintext, hex: {}", raw_to_hex(&decrypted));
    // println!("original plaintext, hex : {}", raw_to_hex(plaintext));
    assert_eq!(plaintext.to_vec(), decrypted);
    // let pt = String::from_utf8(decrypted).unwrap();
    // println!("plaintext({}): {}", pt.len(), pt);

}

fn challenge11() {
    let plaintext = &['a' as u8; 52]; // 2x16 for repeating blocks plus account for <=10 on each side
    let ct1 = encryption_oracle(plaintext);
    let ct2 = encryption_oracle(plaintext);
    println!("{}", raw_to_hex(&ct1));
    println!("{}", match detect_cipher_type(&ct1) { CipherType::Ecb => "ECB", _ =>"CBC" });
    println!("{}", raw_to_hex(&ct2));
    println!("{}", match detect_cipher_type(&ct2) { CipherType::Ecb => "ECB", _ =>"CBC" });

}

fn challenge12() {
    let oracle = EcbEncryptionOracle::new();
    let breaker = EcbBreaker::new(oracle);

    let mut f = File::open("texts/ch12-solution.txt").unwrap();
    let mut solution = String::new();
    f.read_to_string(&mut solution).ok();
    assert_eq!(solution, String::from_utf8(breaker.decrypt().unwrap()).unwrap());
}

fn challenge13() {
    let server = ProfileServer::new();

    assert_eq!("email=which@foo.bar&uid=11&role=admin",
               encode_profile(&make_admin_profile(&server)));
}

fn challenge14() {
    let oracle = EcbEncryptionOracle2::new();
    let breaker = EcbBreaker2::new(oracle);

    let mut f = File::open("texts/ch12-solution.txt").unwrap();
    let mut solution = String::new();
    f.read_to_string(&mut solution).ok();
    assert_eq!(solution, String::from_utf8(breaker.decrypt().unwrap()).unwrap());
}

fn challenge15() {
    let valid = b"ICE ICE BABY\x04\x04\x04\x04";
    let invalid1 = b"ICE ICE BABY\x05\x05\x05\x05";
    let invalid2 = b"ICE ICE BABY\x01\x02\x03\x04";

    for &string in [valid, invalid1, invalid2].iter() {
        let mut v = vec![];
        v.extend_from_slice(string);
        match pkcs_7_strip(&mut v) {
            Some(x) => println!("{}", String::from_utf8(x.clone()).unwrap()),
            None => println!("invalid")
        }
    }
}

fn challenge16() {
    assert!(bit_flip_attack());
}

fn main() {
    let mut argi = env::args();
    argi.next(); // eat basename

    dispatch_ch!(argi,
                 challenge9,
                 challenge10,
                 challenge11,
                 challenge12,
                 challenge13,
                 challenge14,
                 challenge15,
                 challenge16
    );
}

