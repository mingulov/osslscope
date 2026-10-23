// SPDX-License-Identifier: GPL-2.0-or-later
//! Ordinary host probe for the independently authored BPF contract package.
use osslscope_bpf_contract as contract;
use std::{
    collections::{HashMap, HashSet},
    io::{self, Read, Write},
    mem::{align_of, size_of},
};

fn decimal(s: &str, bits: u32) -> Result<u64, String> {
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
fn octets(s: &str) -> Result<Vec<u8>, String> {
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
fn fixed<const N: usize>(s: &str) -> Result<[u8; N], String> {
    octets(s)?.try_into().map_err(|_| "field width".into())
}
fn number(s: &str, width: usize) -> Result<u64, String> {
    let b = octets(s)?;
    if b.len() != width {
        return Err("field width".into());
    }
    Ok(b.iter()
        .enumerate()
        .fold(0u64, |v, (i, x)| v | (u64::from(*x) << (i * 8))))
}
fn table(s: &str, width: usize, max: usize) -> Result<HashMap<u64, Vec<u8>>, String> {
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
fn scalar(name: &str, args: &str) -> Result<String, String> {
    let cells: Vec<_> = args.split(',').collect();
    let arity = match name {
        "make_key" | "make_termd" | "make_seq" | "make_bucket" | "make_rcount"
        | "make_call_flags" => 2,
        "lat_bucket" | "split_seq" | "split_bucket" | "split_rcount" | "loss_for_skip_cause" => 1,
        _ => return Err("scalar name".into()),
    };
    if cells.len() != arity {
        return Err("scalar arity".into());
    }
    let a = decimal(
        cells[0],
        match name {
            "make_key" | "make_termd" | "make_rcount" => 32,
            "make_seq" => 16,
            "make_bucket" | "loss_for_skip_cause" => 8,
            "make_call_flags" => 1,
            _ => 64,
        },
    )?;
    let b = if arity == 2 {
        decimal(
            cells[1],
            match name {
                "make_key" | "make_termd" | "make_rcount" => 32,
                "make_call_flags" => 8,
                _ => 64,
            },
        )?
    } else {
        0
    };
    let result = match name {
        "make_key" => contract::make_key(a as u32, b as u32).to_string(),
        "lat_bucket" => contract::lat_bucket(a).to_string(),
        "make_termd" => contract::make_termd(a as u32, b as u32).to_string(),
        "make_seq" => contract::make_seq(a as u16, b).to_string(),
        "split_seq" => {
            let (x, y) = contract::split_seq(a);
            format!("{x},{y}")
        }
        "make_bucket" => contract::make_bucket(a as u8, b).to_string(),
        "split_bucket" => {
            let (x, y) = contract::split_bucket(a);
            format!("{x},{y}")
        }
        "make_rcount" => contract::make_rcount(a as u32, b as u32).to_string(),
        "split_rcount" => {
            let (x, y) = contract::split_rcount(a);
            format!("{x},{y}")
        }
        "make_call_flags" => contract::make_call_flags(a == 1, b as u8).to_string(),
        "loss_for_skip_cause" => contract::loss_for_skip_cause(a as u8).to_string(),
        _ => unreachable!(),
    };
    Ok(result)
}
fn algorithm(c: &[&str]) -> Result<String, String> {
    let len = decimal(c[0], 64)? as usize;
    let sat = decimal(c[1], 1)? != 0;
    let buf = fixed::<128>(c[2])?;
    let entries = table(c[3], 42, 1024)?;
    let verdict = contract::classify_alg_with(&buf, len, sat, |key| {
        entries.get(&key).map(|v| contract::AlgClassValue {
            class: u16::from_le_bytes([v[0], v[1]]),
            weak: v[2],
            len: v[3],
            canon: u16::from_le_bytes([v[4], v[5]]),
            name: v[6..42].try_into().unwrap(),
        })
    });
    Ok(format!(
        "{}\t{}\t{}",
        verdict.class,
        u8::from(verdict.weak),
        verdict.status
    ))
}
fn trip(c: &[&str]) -> Result<String, String> {
    let sat = decimal(c[0], 1)? != 0;
    let taxonomy = match c[1] {
        "E" => contract::TripTaxonomy::Engine,
        "L" => contract::TripTaxonomy::Load,
        _ => return Err("taxonomy".into()),
    };
    let arg = if c[2] == "-" {
        Vec::new()
    } else {
        octets(c[2])?
    };
    if arg.len() > 1024 {
        return Err("argument limit".into());
    }
    let entries = table(c[3], 22, 64)?;
    let verdict = contract::classify_trip_with(&arg, sat, taxonomy, |key| {
        entries.get(&key).map(|v| contract::TripClassValue {
            engine: u16::from_le_bytes([v[0], v[1]]),
            load: u16::from_le_bytes([v[2], v[3]]),
            len: u16::from_le_bytes([v[4], v[5]]),
            name: v[6..22].try_into().unwrap(),
        })
    });
    Ok(format!("{}\t{}", verdict.class, verdict.status))
}
fn raw<T>(record: &T, size: usize, align: usize) -> Result<String, String> {
    if size_of::<T>() != size || align_of::<T>() != align {
        return Err("layout".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts((record as *const T).cast::<u8>(), size) };
    Ok(bytes.iter().map(|x| format!("{x:02x}")).collect())
}
fn wire(name: &str, cells: &str) -> Result<String, String> {
    let f: Vec<&str> = cells.split(',').collect();
    let pads: &[usize] = match name {
        "ScanRec" => &[4],
        "CtrlValue" => &[2],
        "AlgEvent" => &[5],
        "TripEvent" => &[4, 5],
        "RowEvent" | "InitRetEvent" => &[3],
        "ScanAlgEvent" => &[5, 10],
        "ScanRowEvent" => &[3, 9],
        _ => &[],
    };
    for &index in pads {
        if octets(f.get(index).ok_or("field count")?)?
            .iter()
            .any(|&byte| byte != 0)
        {
            return Err("nonzero pad".into());
        }
    }
    macro_rules! fields {
        ($n:expr) => {
            if f.len() != $n {
                return Err("field count".into());
            }
        };
    }
    macro_rules! u8f {
        ($i:expr) => {
            number(f[$i], 1)? as u8
        };
    }
    macro_rules! u16f {
        ($i:expr) => {
            number(f[$i], 2)? as u16
        };
    }
    macro_rules! u32f {
        ($i:expr) => {
            number(f[$i], 4)? as u32
        };
    }
    macro_rules! u64f {
        ($i:expr) => {
            number(f[$i], 8)?
        };
    }
    let output = match name {
        "CountValue" => {
            fields!(3);
            raw(
                &contract::CountValue {
                    count: u64f!(0),
                    first_ns: u64f!(1),
                    last_ns: u64f!(2),
                },
                24,
                8,
            )
        }
        "PendQuery" => {
            fields!(2);
            raw(
                &contract::PendQuery {
                    op: u64f!(0),
                    ns_ptr: u64f!(1),
                },
                16,
                8,
            )
        }
        "ScanRec" => {
            fields!(6);
            raw(
                &contract::ScanRec {
                    op: u64f!(0),
                    ns_ptr: u64f!(1),
                    seq: u64f!(2),
                    expected: u32f!(3),
                    _pad: u32f!(4),
                    epoch: u64f!(5),
                },
                40,
                8,
            )
        }
        "TCacheValue" => {
            fields!(2);
            raw(
                &contract::TCacheValue {
                    t: u64f!(0),
                    generation: u64f!(1),
                },
                16,
                8,
            )
        }
        "CtrlValue" => {
            fields!(5);
            raw(
                &contract::CtrlValue {
                    expected: u32f!(0),
                    skip_all: u8f!(1),
                    _pad: fixed::<3>(f[2])?,
                    epoch: u64f!(3),
                    governor: u64f!(4),
                },
                24,
                8,
            )
        }
        "AlgEvent" => {
            fields!(9);
            raw(
                &contract::AlgEvent {
                    kind: u32f!(0),
                    op: u32f!(1),
                    class: u16f!(2),
                    status: u8f!(3),
                    weak: u8f!(4),
                    _pad: u32f!(5),
                    arr: u64f!(6),
                    idx: u64f!(7),
                    generation: u64f!(8),
                },
                40,
                8,
            )
        }
        "TripEvent" => {
            fields!(6);
            raw(
                &contract::TripEvent {
                    kind: u32f!(0),
                    cookie: u32f!(1),
                    class: u16f!(2),
                    status: u8f!(3),
                    _pad: u8f!(4),
                    _pad2: u32f!(5),
                },
                16,
                4,
            )
        }
        "RowEvent" => {
            fields!(8);
            raw(
                &contract::RowEvent {
                    kind: u32f!(0),
                    op: u32f!(1),
                    funcid: u32f!(2),
                    _pad: u32f!(3),
                    addr: u64f!(4),
                    aux: u64f!(5),
                    idx: u64f!(6),
                    generation: u64f!(7),
                },
                48,
                8,
            )
        }
        "InitRetEvent" => {
            fields!(6);
            raw(
                &contract::InitRetEvent {
                    kind: u32f!(0),
                    op: u32f!(1),
                    funcid: u32f!(2),
                    _pad: u32f!(3),
                    addr: u64f!(4),
                    aux: u64f!(5),
                },
                32,
                8,
            )
        }
        "ScanCallEvent" => {
            fields!(5);
            raw(
                &contract::ScanCallEvent {
                    kind: u32f!(0),
                    op: u32f!(1),
                    tid: u32f!(2),
                    flags: u32f!(3),
                    seq: u64f!(4),
                },
                24,
                8,
            )
        }
        "ScanRetEvent" => {
            fields!(7);
            raw(
                &contract::ScanRetEvent {
                    kind: u32f!(0),
                    op: u32f!(1),
                    flags: u32f!(2),
                    tid: u32f!(3),
                    seq: u64f!(4),
                    arr: u64f!(5),
                    generation: u64f!(6),
                },
                40,
                8,
            )
        }
        "GuardEvent" => {
            fields!(7);
            raw(
                &contract::GuardEvent {
                    kind: u32f!(0),
                    op: u32f!(1),
                    verdict: u32f!(2),
                    tid: u32f!(3),
                    seq: u64f!(4),
                    arr: u64f!(5),
                    generation: u64f!(6),
                },
                40,
                8,
            )
        }
        "ScanAlgEvent" => {
            fields!(12);
            raw(
                &contract::ScanAlgEvent {
                    kind: u32f!(0),
                    op: u32f!(1),
                    class: u16f!(2),
                    status: u8f!(3),
                    weak: u8f!(4),
                    _pad: u32f!(5),
                    arr: u64f!(6),
                    idx: u64f!(7),
                    generation: u64f!(8),
                    tid: u32f!(9),
                    _pad2: u32f!(10),
                    seq: u64f!(11),
                },
                56,
                8,
            )
        }
        "ScanRowEvent" => {
            fields!(11);
            raw(
                &contract::ScanRowEvent {
                    kind: u32f!(0),
                    op: u32f!(1),
                    funcid: u32f!(2),
                    _pad: u32f!(3),
                    addr: u64f!(4),
                    aux: u64f!(5),
                    idx: u64f!(6),
                    generation: u64f!(7),
                    tid: u32f!(8),
                    _pad2: u32f!(9),
                    seq: u64f!(10),
                },
                64,
                8,
            )
        }
        "AlgClassValue" => {
            fields!(5);
            raw(
                &contract::AlgClassValue {
                    class: u16f!(0),
                    weak: u8f!(1),
                    len: u8f!(2),
                    canon: u16f!(3),
                    name: fixed::<36>(f[4])?,
                },
                42,
                2,
            )
        }
        "TripClassValue" => {
            fields!(4);
            raw(
                &contract::TripClassValue {
                    engine: u16f!(0),
                    load: u16f!(1),
                    len: u16f!(2),
                    name: fixed::<16>(f[3])?,
                },
                22,
                2,
            )
        }
        _ => return Err("record name".into()),
    }?;
    Ok(output)
}
fn run() -> Result<(), String> {
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
            "s" if c.len() == 4 => format!("s\t{}", scalar(c[2], c[3])?),
            "a" if c.len() == 6 => format!("a\t{}", algorithm(&c[2..6])?),
            "t" if c.len() == 6 => format!("t\t{}", trip(&c[2..6])?),
            "w" if c.len() == 4 => format!("w\t{}", wire(c[2], c[3])?),
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
fn main() {
    if let Err(error) = run() {
        eprintln!("invalid contract request: {error}");
        std::process::exit(1);
    }
}
