
pub fn pkcs_7_pad(buf: &mut Vec<u8>, len: usize) {
    if len < buf.len() { return }

    let padlen = len - buf.len();
    for _ in 0..padlen {
        buf.push(padlen as u8);
    }
}
