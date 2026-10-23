// SPDX-License-Identifier: GPL-2.0-or-later
//! Host-only OSSLBC1 framing shared by the two separately built examples.
use std::{
    collections::{HashMap, HashSet},
    io::{self, Read, Write},
};

pub fn decimal(s: &str, bits: u32) -> Result<u64, String> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("decimal".into());
    }
    let n = s.parse::<u64>().map_err(|_| "integer width")?;
    if bits < 64 && n >= 1u64 << bits {
        return Err("integer width".into());
    }
    Ok(n)
}
pub fn octets(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("hex".into());
    }
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).map_err(|_| "hex".into()))
        .collect()
}
pub fn fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    octets(s)?.try_into().map_err(|_| "field width".into())
}
pub fn number(s: &str, width: usize) -> Result<u64, String> {
    let b = octets(s)?;
    if b.len() != width {
        return Err("field width".into());
    }
    Ok(b.iter()
        .enumerate()
        .fold(0u64, |v, (i, x)| v | (u64::from(*x) << (i * 8))))
}
pub fn table(s: &str, width: usize, max: usize) -> Result<HashMap<u64, Vec<u8>>, String> {
    let mut result = HashMap::new();
    if s == "-" {
        return Ok(result);
    }
    for item in s.split(',') {
        if result.len() >= max {
            return Err("table limit".into());
        }
        let (k, v) = item.split_once(':').ok_or("table entry")?;
        if k.len() != 16 || v.len() != width * 2 {
            return Err("table width".into());
        }
        let key = number(k, 8)?;
        if result.insert(key, octets(v)?).is_some() {
            return Err("duplicate table key".into());
        }
    }
    Ok(result)
}

// Four fixed protocol operations; semantic and typed-record implementations stay
// local to each executable and retain their separate crate dependency closure.
pub struct Backend {
    pub scalar: fn(&str, &str) -> Result<String, String>,
    pub algorithm: fn(&[&str]) -> Result<String, String>,
    pub trip: fn(&[&str]) -> Result<String, String>,
    pub wire: fn(&str, &str) -> Result<String, String>,
}

fn serve(backend: Backend) -> Result<(), String> {
    if !cfg!(target_endian = "little") {
        return Err("host endian".into());
    }
    let mut input = Vec::new();
    io::stdin()
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut input)
        .map_err(|_| "input read")?;
    if input.len() > 256 * 1024 * 1024 || !input.ends_with(b"\n") || input.contains(&b'\r') {
        return Err("input framing".into());
    }
    let input = std::str::from_utf8(&input).map_err(|_| "utf8")?;
    let mut lines = input.split_terminator('\n');
    if lines.next() != Some("OSSLBC1") {
        return Err("version".into());
    }
    let mut ids = HashSet::new();
    let mut out = String::from("OSSLBC1\n");
    for line in lines {
        if line.len() > 128 * 1024 {
            return Err("line limit".into());
        }
        let c: Vec<&str> = line.split('\t').collect();
        if c.len() < 2
            || c[0].is_empty()
            || c[0].len() > 64
            || !c[0]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || !ids.insert(c[0])
        {
            return Err("id".into());
        }
        let result = match c[1] {
            "s" if c.len() == 4 => format!("s\t{}", (backend.scalar)(c[2], c[3])?),
            "a" if c.len() == 6 => format!("a\t{}", (backend.algorithm)(&c[2..6])?),
            "t" if c.len() == 6 => format!("t\t{}", (backend.trip)(&c[2..6])?),
            "w" if c.len() == 4 => format!("w\t{}", (backend.wire)(c[2], c[3])?),
            _ => return Err("request fields".into()),
        };
        out.push_str(c[0]);
        out.push('\t');
        out.push_str(&result);
        out.push('\n');
    }
    if ids.is_empty() {
        return Err("missing requests".into());
    }
    io::stdout()
        .write_all(out.as_bytes())
        .map_err(|_| "output write".into())
}

pub fn run(backend: Backend) {
    if let Err(error) = serve(backend) {
        eprintln!("invalid contract request: {error}");
        std::process::exit(1);
    }
}
