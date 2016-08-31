extern crate openssl;

use self::openssl::crypto::symm::*;
use self::openssl::error::ErrorStack;

use s1::ch2::buffer_xor;
use s2::ch9::pkcs_7_pad;

pub struct Cbc<'a, 'b> {
    t: Type,
    key: &'a[u8],
    iv: &'b[u8; 16],
}
    
impl<'a, 'b> Cbc<'a, 'b> {
    pub fn new(t: Type, key: &'a[u8], iv: &'b[u8; 16]) -> Self {
        Cbc { t:t, key:key, iv:iv }
    }

    pub fn encrypt(self: &Self, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let mut result = Vec::new();
        let mut prev = self.iv.to_vec();
        let mut block_idx = 0;

        while block_idx + 16 <= data.len() {
            let cur = &data[block_idx..(block_idx + 16)];
            prev = try!(self.cipher(Mode::Encrypt, &buffer_xor(&prev, cur)));

            result.extend_from_slice(&prev);

            block_idx += 16;
        }

        let mut last_block = Vec::new();
        last_block.extend_from_slice(&data[block_idx..]);
        pkcs_7_pad(&mut last_block, 16);
        
        result.append(&mut try!(self.cipher(Mode::Encrypt, &buffer_xor(&prev, &last_block))));

        Ok(result)
    }

    pub fn decrypt(self: &Self, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        assert!(data.len() % 16 == 0);

        let mut result = Vec::new();
        let mut prev = &self.iv[0..];
        let mut block_idx = 0;

        while block_idx < data.len() {
            let cur = &data[block_idx..(block_idx + 16)];
            result.append(&mut buffer_xor(prev, &try!(self.cipher(Mode::Decrypt, cur))));

            prev = cur;
            block_idx += 16;
        }

        let n = result.len();
        let pad_len = result[n - 1] as usize;
        result.truncate(n - pad_len);

        Ok(result)
    }

    fn cipher(self: &Self, mode: Mode, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        let mut c = try!(Crypter::new(self.t, mode, self.key, None));
        // handling padding ourselves; disable it in OpenSSL
        c.pad(false);
        // Crypter will assert anyway though if we don't make room for padding
        let mut out = vec![0; data.len() + 16];
        let count = try!(c.update(data, &mut out));
        let rest = try!(c.finalize(&mut out[count..]));
        assert!(rest == 0);
        out.truncate(count);
        Ok(out)
    }
}

