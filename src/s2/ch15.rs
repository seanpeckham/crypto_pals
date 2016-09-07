pub fn pkcs_7_strip<'a>(string: &'a mut Vec<u8>) -> Option<&'a Vec<u8>> {
    if let Some(&last) = string.last() {
        let n = string.len();
        let mut i = n - 1;
        loop {
            if string[i] != last {
                if last as usize == n - i - 1 {
                    string.truncate(i + 1);
                    return Some(string);
                }
                break;
            }
            i -= 1;
        }
    }
    None
}
