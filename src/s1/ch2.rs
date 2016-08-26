
pub fn buffer_xor(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
    buf1.iter()
        .zip(buf2)
        .map(|(b1, b2)| b1 ^ b2)
        .collect()
}

pub fn buffer_xor_1byte(buf: &[u8], n: u8) -> Vec<u8> {
    buf.iter()
        .map(|b| b ^ n)
        .collect()
}
