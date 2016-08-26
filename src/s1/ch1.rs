#![allow(dead_code)]

fn raw_to_hex_explicit(bytes: &[u8]) -> String {
    let mut res: String = String::new();
    let mut base: u8;
    
    for b in bytes {
        for nib in [(b & 0xf0) >> 4, b & 0x0f ].iter() {
            base = '0' as u8 + (nib/10) * ('a' as u8 - '0' as u8);
            res.push((base + nib % 10) as char);
        }
    }
    res
}

fn raw_to_hex_fmt(bytes: &[u8]) -> String {
    let mut res: String = String::new();
    for b in bytes {
        res.push_str(format!("{:02x}", b).as_str());
    }
    res
}

pub fn raw_to_hex(bytes: &[u8]) -> String {
    raw_to_hex_explicit(bytes)
}

fn nibble_hex_to_raw(nib: u8) -> u8 {
    if nib < 'a' as u8 {
        nib - '0' as u8
    } else {
        nib - 'a' as u8 + 10
    }
}

pub fn hex_to_raw(input: &str) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();
    let chars = input.as_bytes();
    let mut idx = 0;
    
    if chars.len() % 2 == 1 {
        res.push(nibble_hex_to_raw(chars[0]));
        idx = 1;
    }
    
    while idx < chars.len() {
        let mut byte = nibble_hex_to_raw(chars[idx]) << 4;
        byte += nibble_hex_to_raw(chars[idx + 1]);
        res.push(byte);
        idx += 2;
    }
    res
}

static CODES: &'static[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn raw_to_base64(bytes: &[u8]) -> String {
    let mut res = String::new();
    let mut i = 0;
    let n = bytes.len();
    
    while i < n {
        let b1 = bytes[i];
        let b2 = if i + 1 < n { bytes[i+1] } else { 0 };
        let b3 = if i + 2 < n { bytes[i+2] } else { 0 };
        
        // println!("i: {}, n: {}", i, n);
        // println!("{:x} {:x} {:x}", b1, b2, b3);
        // println!("{:08b} {:08b} {:08}", b1, b2, b3);
        
        let idx1 = ((b1 & 0xFC) >> 2) as usize;
        let idx2 = (((b1 & 3) << 4) | ((b2 & 0xF0) >> 4)) as usize;
        let idx3 = (((b2 & 0x0F) << 2) | ((b3 & 0xC0) >> 6)) as usize;
        let idx4 = (b3 & 0x3F) as usize;
        
        // println!("{:06b} {:06b} {:06b} {:06b}",
        //          idx1 as u8,
        //          idx2 as u8,
        //          idx3 as u8,
        //          idx4 as u8);
        
        res.push(CODES[idx1] as char);
        res.push(CODES[idx2] as char);
        res.push(if i + 1 < n { CODES[idx3] as char } else { '=' });
        res.push(if i + 2 < n { CODES[idx4] as char } else { '=' });
        
        i += 3;    
    }
    res
}

fn code_inverse(ch: char) -> u8 {
    if ch.is_uppercase() {
        ch as u8 - 'A' as u8
    } else if ch.is_lowercase() {
        ch as u8 - 'a' as u8 + 26
    } else if ch.is_digit(10) {
        ch as u8 - '0' as u8 + 52
    } else if ch == '+' {
        62
    } else if ch == '/' {
        63
    } else {
        if ch != '=' {
            println!("{}", ch);
        }
        assert_eq!(ch,'=');
        64
    }
}

pub fn base64_to_raw(input: &str) -> Vec<u8> {
    let mut i = input.chars();
    let n = input.len();
    let mut res = Vec::with_capacity(n);
    let mut j = 0;

    while j < n {
        let sextets = (0..4).map(|_| code_inverse(i.next().unwrap()) as u8)
            .collect::<Vec<u8>>();

        res.push( (sextets[0] << 2) | (sextets[1] >> 4) );
        res.push( sextets[1] << 4 );

        if sextets[2] < 64 {
            *res.last_mut().unwrap() |= sextets[2] >> 2;
            res.push( sextets[2] << 6 );

            if sextets[3] < 64 {
                *res.last_mut().unwrap() |= sextets[3];
            }
        }
        j += 4;
    }
    res
}
