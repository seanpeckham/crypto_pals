#![allow(dead_code)]

extern crate openssl;

use self::openssl::crypto::symm::Type;
use std::env;
use std::io::prelude::*;
use std::fs::File;

mod s1;
mod s2;

#[macro_use]
mod util;
use util::*;

use_ch!(s1, ch1, ch2, ch3, ch4, ch5, ch6, ch7, ch8);
use_ch!(s2, ch9, ch10);

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
    f.read_to_string(&mut solution);
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


fn main() {
    let mut argi = env::args();
    argi.next(); // eat basename

    dispatch_ch!(argi,
                 challenge9,
                 challenge10
    );
}
