use std::io::prelude::*;
use std::fs::File;
use std::io::BufReader;

use s1::ch1::*;

macro_rules! use_ch {
    ( $s:ident, $( $x:ident ),* ) => {
        $(
            use $s::$x::*;
        )*
    }
}

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

pub fn hex_file_to_raw_lines(fname: &str) -> Vec<Vec<u8>> {
    let f = File::open(fname).unwrap();
    let f = BufReader::new(f);
    let mut v = Vec::new();

    for line in f.lines() {
        v.push(hex_to_raw(&line.unwrap()));
    }
    v
}

pub fn file_concat_lines(filename: &str) -> String {
    let f = File::open(filename).unwrap();
    let f = BufReader::new(f);
    let mut s = String::new();
    
    for line in f.lines() {
        s.push_str(&line.unwrap());
    }
    s
}
