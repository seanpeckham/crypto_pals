
pub fn rep_key_xor(input: &[u8], cipher: &[u8]) -> Vec<u8> {
    let mut result = vec![];

    let mut ciph_iter = cipher.iter().cycle();

    for b in input {
        result.push(*b ^ ciph_iter.next().unwrap());
    }
     
    result
}
