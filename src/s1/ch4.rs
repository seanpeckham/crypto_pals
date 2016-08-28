
use s1::ch3::*;

pub fn find_str_1byte_xor_detail(strings: &Vec<Vec<u8>>) -> CipherGuessPair {
    let guesses: Vec<Vec<u8>> =
        strings.iter()
        .map(|s| decrypt_cipher_xor_1byte_raw(s)).collect();

    let mut best = CipherGuessPair::new();

    for (cipher, guess) in strings.iter().zip(&guesses) {
        let guess_score = score_text(&guess);
        
        // println!("score: {}", guess_score);
        // println!("guess: {}", String::from_utf8(guess.clone()).unwrap_or(String::new()));

        if guess_score > best.score {
            best.ciphertext = cipher.clone();
            best.guess = guess.clone();
            best.score = guess_score;
        }
    }
    best
}

pub fn find_str_1byte_xor(strings: &Vec<Vec<u8>>) -> String {
    String::from_utf8(find_str_1byte_xor_detail(strings).guess).unwrap_or(String::new())
}
