//#![allow(dead_code)]

extern crate openssl;

use std::env;
use std::io::prelude::*;
use std::fs::File;

mod s1;

macro_rules! use_ch {
    ( $( $x:ident ),* ) => {
        $(
            use s1::$x::*;
        )*
    }
}

use_ch!(ch1, ch2, ch3, ch4, ch5, ch6, ch7, ch8);

macro_rules! get_input {
    ( $name:ident, $x:expr ) => {
        let $name =
            if let Some(arg) = env::args().skip(2 + $x).next() {
                arg
            } else {
                println!("expected arg {}", $x);
                return ()
            }
    }
}

fn challenge1() {
    
    let example_input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let example_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    assert_eq!(example_output,
               raw_to_base64(&hex_to_raw(example_input)));

    assert_eq!(example_input,
               raw_to_hex(&base64_to_raw(example_output)));

    get_input!(input, 0);

    println!("{}", raw_to_base64(&hex_to_raw(&input)));
    // println!("{}", raw_to_hex(&base64_to_raw(&input)));
}

fn challenge2() {
    let example_input_1 = "1c0111001f010100061a024b53535009181c";
    let example_input_2 = "686974207468652062756c6c277320657965";
    let example_output = "746865206b696420646f6e277420706c6179";

    assert_eq!(example_output,
               raw_to_hex(&buffer_xor(&hex_to_raw(example_input_1),
                                      &hex_to_raw(example_input_2))));
    get_input!(input_1, 0);
    get_input!(input_2, 1);

    println!("{}", raw_to_hex(&buffer_xor(&hex_to_raw(&input_1),
                                          &hex_to_raw(&input_2))));

}

fn challenge3() {
    let example_input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let output = "Cooking MC's like a pound of bacon";
    assert_eq!(output, decrypt_cipher_xor_1byte(&hex_to_raw(example_input)));

    get_input!(input, 0);
    println!("{}", decrypt_cipher_xor_1byte(&hex_to_raw(&input)));
}

fn challenge4() {
    let answer = find_str_1byte_xor(&hex_file_to_raw_lines("texts/ch4.txt"));
    let correct_answer = "Now that the party is jumping\n";
    assert_eq!(answer, correct_answer);

    get_input!(filename, 0);
    println!("{}", find_str_1byte_xor(&hex_file_to_raw_lines(&filename)));
}

fn challenge5() {
    let example_input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    assert_eq!(hex_to_raw(output),
               rep_key_xor(&example_input.as_bytes(), "ICE".as_bytes()));

    get_input!(input, 0);
    get_input!(cipher, 1);
    println!("{}", raw_to_hex(&rep_key_xor(&input.as_bytes(),
                                           &cipher.as_bytes())));
}

fn challenge6() {
    let example_input_1 = "this is a test";
    let example_input_2 = "wokka wokka!!!";
    assert_eq!(37, hamming_distance(&example_input_1.as_bytes(),
                                    &example_input_2.as_bytes()));

   let example_input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let key = "ICE";
    let rkx = RepKeyXor { max_keysize_guess:40,
                          block_pairs_per_guess:4,
                          guess_count_retained:3 };
    let ciphertext = rep_key_xor(&example_input.as_bytes(), key.as_bytes());
    assert_eq!(example_input, rkx.decrypt(&ciphertext));

    //let key = "5465726d696e61746f7220583a204272696e6720746865206e6f697365";
    let mut f = File::open("texts/ch6-solution.txt").unwrap();
    let mut solution = String::new();
    f.read_to_string(&mut solution);
    assert_eq!(solution, rkx.decrypt_file_base64("texts/ch6.txt"));

    // get_input!(fname, 0);
    // println!("{}", rkx.decrypt_file_base64(&fname));
}

fn challenge7() {
    let ciphertext = base64_to_raw(&file_concat_lines("texts/ch7.txt"));
    let key = b"YELLOW SUBMARINE";

    let mut f = File::open("texts/ch7-solution.txt").unwrap();
    let mut solution = String::new();
    f.read_to_string(&mut solution);

    match decrypt_aes_128_ecb(key, None, &ciphertext) {
        Ok(result) => {
            let plaintext = String::from_utf8(result).unwrap();
            //println!("{}", plaintext);
            assert_eq!(solution, plaintext);
        },
        Err(e) => { println!("openssl error: {}", e); assert!(false) }
    }
}

fn challenge8() {
    println!("{}", find_rep_blocks("texts/ch8.txt"));
}

macro_rules! dispatch_ch {
    ( $argi:ident, $( $x:ident ),* )
        => {
        if let Some(arg) = $argi.next() {
            match arg.as_str() {
                $( stringify!($x) => $x() ),*,
                _ => ()
            }
        }
    }
}

fn main() {
    let mut argi = env::args();
    argi.next(); // eat basename

    dispatch_ch!(argi,
                 challenge1,
                 challenge2,
                 challenge3,
                 challenge4,
                 challenge5,
                 challenge6,
                 challenge7,
                 challenge8
    );
}

