extern crate regex;

use self::regex::*;
use std::collections::HashMap;
use std::num::*;

use s2::ch11::*;
use s1::ch1::*;
use s1::ch7::*;

use std::str::FromStr;

pub struct UserProfile {
    email: String,
    uid: u32,
    role: String
}

static mut NEXT_UID: u32 = 10;

fn next_uid() -> u32 {
    unsafe {
        let uid = NEXT_UID;
        NEXT_UID += 1;
        uid
    }
}

fn profile_for(mut email: String) -> String {
    if let Some(pos) = email.find(|c| c == '&' || c == '=') {
        email.truncate(pos);
    }

    encode_profile( &UserProfile { email:email, uid:next_uid(), role:String::from("user") } )
}

pub fn encode_profile(profile: &UserProfile) -> String {
    format!("email={}&uid={}&role={}", profile.email, profile.uid, profile.role)
}

#[derive(Debug)]
pub enum KvParseError {
    RegexError(regex::Error),
    KeyNotFound,
    ValNotFound,
    ValParseErr
}

impl From<regex::Error> for KvParseError {
    fn from(err: regex::Error) -> KvParseError {
        KvParseError::RegexError(err)
    }
}
impl From<ParseIntError> for KvParseError {
    fn from(err: ParseIntError) -> KvParseError {
        KvParseError::ValParseErr
    }
}

fn parse_kvs(src: &str) -> Result<HashMap<String, String>, KvParseError> {
    let mut result = HashMap::new();
    let kv_regex = try!(Regex::new(r"(?:(?P<key>[\w]+)=(?P<val>[\w@\.]+))+&*"));

    for capture in kv_regex.captures_iter(src) {

        let key = try!(capture.name("key").ok_or(KvParseError::KeyNotFound));
        let val = try!(capture.name("val").ok_or(KvParseError::ValNotFound));

        result.insert(String::from(key), String::from(val));
    }
    Ok(result)
}

impl FromStr for UserProfile {
    type Err = KvParseError;

    fn from_str(src: &str) -> Result<UserProfile, KvParseError> {
        let items = try!(parse_kvs(src));
        
        Ok( UserProfile { email:items["email"].clone(),
                          uid:try!(items["uid"].parse()),
                          role:items["role"].clone() } )
    }
}

pub struct ProfileServer {
    key: Vec<u8>
}

impl ProfileServer {
    pub fn new() -> Self { ProfileServer { key: gen_key() } }

    pub fn serve(self: &Self, email: &str) -> Vec<u8> {
        encrypt_aes_128_ecb(&self.key,
                            &profile_for(String::from(email)).as_bytes()).unwrap()
    }
    
    pub fn recv(self: &Self, ciphertext: &[u8]) -> Result<UserProfile, KvParseError> {
        String::from_utf8(decrypt_aes_128_ecb(&self.key, ciphertext)
                          .unwrap())
            .unwrap()
            .parse::<UserProfile>()
    }
}

// attacker

pub fn make_admin_profile(server: &ProfileServer) -> UserProfile {

    // "email=which@foo." "bar&uid=10&role=" "user............"
    // "email=thing@baz." "admin&uid=10&rol" "e=user.........."
    // "email=what@ever." "enough&uid=10&ro" "le=user........."

    let drop_user = &server.serve("which@foo.bar")[0..32];
    let position_admin = &server.serve("thing@baz.admin")[16..32];
    let trailing_junk = &server.serve("what@ever.enough")[32..];

    let mut paste = vec![];

    paste.extend_from_slice(drop_user);
    paste.extend_from_slice(position_admin);
    paste.extend_from_slice(trailing_junk);

    server.recv(&paste).unwrap()

}
