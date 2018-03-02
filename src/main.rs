extern crate addr2line;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate failure;
extern crate gimli;
extern crate home;
extern crate memmap;
extern crate object;
extern crate panopticon_amd64 as amd64;
extern crate panopticon_core as panopticon;

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;

use object::{Object, ObjectSegment};

#[derive(Debug, Fail)]
enum Error {
    #[fail(display = "{}", reason)]
    FindPanics { reason: String },
    #[fail(display = "Error parsing DWARF: {}", reason)]
    Dwarf { reason: gimli::Error },
    #[fail(display = "Error parsing object file: {}", reason)]
    Object { reason: &'static str },
}

impl From<String> for Error {
    fn from(reason: String) -> Error {
        Error::FindPanics { reason }
    }
}

impl<'a> From<&'a str> for Error {
    fn from(reason: &'a str) -> Error {
        Error::FindPanics {
            reason: reason.into(),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

const OPT_FILE: &str = "FILE";

fn main() {
    let matches = clap::App::new("findpanics")
        .version(crate_version!())
        .setting(clap::AppSettings::UnifiedHelpMessage)
        .arg(
            clap::Arg::with_name(OPT_FILE)
                .help("Path of file to print")
                .required(true)
                .index(1),
        )
        .get_matches();

    let path = matches.value_of(OPT_FILE).unwrap();
    if let Err(e) = process_file(path) {
        eprintln!("{}: {}", path, e);
    }
}

fn process_file(path: &str) -> Result<()> {
    let cwd = match env::current_dir() {
        Ok(dir) => dir,
        Err(e) => return Err(format!("could not determine current dir: {}", e).into()),
    };

    let cargo_home = match home::cargo_home_with_cwd(&cwd) {
        Ok(dir) => dir,
        Err(e) => return Err(format!("could not determine cargo dir: {}", e).into()),
    };

    let handle = match fs::File::open(path) {
        Ok(handle) => handle,
        Err(e) => return Err(format!("open failed: {}", e).into()),
    };

    let map = match unsafe { memmap::Mmap::map(&handle) } {
        Ok(map) => map,
        Err(e) => return Err(format!("memmap failed: {}", e).into()),
    };

    let object = object::File::parse(&*map).map_err(|reason| Error::Object { reason })?;
    let symbolizer = Symbolizer::new(&object)?;

    let mut disassembler = Disassembler::new(&object)?;
    for segment in object.segments() {
        disassembler.add_segment(segment.data(), segment.address());
    }

    let mut source_lines = SourceLines::new();

    let mut panic_symbols = HashMap::new();
    for symbol in symbolizer
        .symbols
        .symbols()
        .iter()
        .filter(|s| is_panic_symbol(s))
    {
        if let Some(name) = symbol.name() {
            panic_symbols.insert(
                symbol.address(),
                addr2line::demangle_auto(name.into(), None),
            );
        }
    }

    let mut symbols: Vec<(&object::Symbol, _)> = symbolizer
        .symbols
        .symbols()
        .iter()
        .filter_map(|symbol| {
            if symbol.kind() != object::SymbolKind::Text || is_panic_symbol(symbol) {
                return None;
            }
            let name = symbol
                .name()
                .map(|name| addr2line::demangle_auto(name.into(), None));
            if is_std_symbol(name.as_ref().map(|n| n.as_ref())) {
                return None;
            }
            Some((symbol, name))
        })
        .collect();
    symbols.sort_by(|&(_, ref a), &(_, ref b)| a.cmp(b));

    let mut calls = Vec::new();
    for (symbol, symbol_name) in symbols {
        calls.clear();
        let begin = symbol.address();
        let end = begin + symbol.size();
        disassembler.calls(begin, end, |from, to| {
            if let Some(name) = panic_symbols.get(&to) {
                calls.push((from, to, name));
            }
        });
        if !calls.is_empty() {
            print!("In function {:x} ", symbol.address());
            if let Some(name) = symbol_name {
                println!("{}", name);
            } else {
                println!("<unknown>");
            }
            for &(from, to, name) in &calls {
                println!();
                println!("    Call to {:x} {}", to, name);
                print!("         at {:x} ", from);
                let mut first = true;
                if let Some(mut frames) = symbolizer.find_frames(from) {
                    while let Ok(Some(frame)) = frames.next() {
                        if !first {
                            print!("         inlined at ");
                        }
                        if let Some(function) = frame.function {
                            if let Ok(name) = function.demangle() {
                                print!("{}", name);
                            } else {
                                print!("<unknown>");
                            }
                        } else {
                            print!("<unknown>");
                        }
                        if let Some(addr2line::Location {
                            file: Some(ref file),
                            line: Some(line),
                            column,
                        }) = frame.location
                        {
                            let rel_file = file.strip_prefix(&cwd)
                                .or_else(|_| file.strip_prefix(&cargo_home))
                                .unwrap_or(file);
                            print!(" ({}:{}", rel_file.to_string_lossy(), line);
                            if let Some(column) = column {
                                print!(":{}", column);
                            }
                            println!(")");
                            if let Some(source) = source_lines.line(file, line as usize) {
                                println!("            source: {}", source.trim());
                            }
                        } else {
                            println!();
                        }
                        first = false;
                    }
                }
                if first {
                    println!("<unknown>");
                }
            }
            println!();
        }
    }

    Ok(())
}

fn is_panic_symbol(symbol: &object::Symbol) -> bool {
    if let Some(name) = symbol.name() {
        name.starts_with("_ZN4core9panicking18panic_bounds_check17h")
            || name.starts_with("_ZN4core9panicking5panic17h")
            || name.starts_with("_ZN4core9panicking9panic_fmt17h")
            || name.starts_with("_ZN4core6result13unwrap_failed17h")
            || name.starts_with("_ZN3std9panicking11begin_panic17h")
            || name.starts_with("_ZN3std9panicking15begin_panic_fmt17h")
    } else {
        false
    }
}

fn is_std_symbol(name: Option<&str>) -> bool {
    if let Some(mut name) = name {
        if name.starts_with('<') {
            name = &name[1..];
        }

        name.starts_with("alloc::") || name.starts_with("core::") || name.starts_with("std::")
            || name.starts_with("std_unicode::") || name == "rust_begin_unwind"
            || name == "__rust_maybe_catch_panic"
    } else {
        false
    }
}

struct SourceLines {
    map: HashMap<PathBuf, Vec<String>>,
}

impl SourceLines {
    fn new() -> Self {
        SourceLines {
            map: HashMap::new(),
        }
    }

    fn line(&mut self, path: &PathBuf, mut line: usize) -> Option<&str> {
        if line == 0 {
            return None;
        }
        line -= 1;

        self.map
            .entry(path.clone())
            .or_insert_with(|| read_lines(path).unwrap_or_default())
            .get(line)
            .map(|line| line.as_ref())
    }
}

fn read_lines(path: &PathBuf) -> io::Result<Vec<String>> {
    let f = fs::File::open(path)?;
    let r = io::BufReader::new(f);
    let mut lines = Vec::new();
    for line in r.lines() {
        lines.push(line?);
    }
    Ok(lines)
}

struct Symbolizer<'a> {
    symbols: object::SymbolMap<'a>,
    dwarf: addr2line::Context<gimli::EndianBuf<'a, gimli::RunTimeEndian>>,
}

impl<'a> Symbolizer<'a> {
    fn new(object: &object::File<'a>) -> Result<Self> {
        let symbols = object.symbol_map();
        let dwarf = addr2line::Context::new(object).map_err(|reason| Error::Dwarf { reason })?;
        Ok(Symbolizer { symbols, dwarf })
    }

    fn find_frames(
        &self,
        address: u64,
    ) -> Option<addr2line::FrameIter<gimli::EndianBuf<'a, gimli::RunTimeEndian>>> {
        self.dwarf.find_frames(address).ok()
    }
}

struct Disassembler {
    machine: panopticon::Machine,
    region: panopticon::Region,
}

impl Disassembler {
    fn new(object: &object::File) -> Result<Self> {
        let (machine, region) = match object.machine() {
            object::Machine::X86_64 => {
                let region =
                    panopticon::Region::undefined("RAM".to_string(), 0xFFFF_FFFF_FFFF_FFFF);
                (panopticon::Machine::Amd64, region)
            }
            _ => return Err("unsupported machine".into()),
        };

        Ok(Disassembler { machine, region })
    }

    fn add_segment(&mut self, data: &[u8], begin: u64) {
        let end = begin + data.len() as u64;
        let bound = panopticon::Bound::new(begin, end);
        let layer = panopticon::Layer::wrap(data.to_vec());
        self.region.cover(bound, layer);
    }

    fn calls<F>(&self, begin: u64, end: u64, f: F)
    where
        F: FnMut(u64, u64),
    {
        match self.machine {
            panopticon::Machine::Amd64 => {
                self.calls_arch::<amd64::Amd64, _>(amd64::Mode::Long, begin, end, f);
            }
            _ => {}
        }
    }

    fn calls_arch<A, F>(&self, cfg: A::Configuration, begin: u64, end: u64, mut f: F)
    where
        A: panopticon::Architecture,
        F: FnMut(u64, u64),
    {
        let mut address = begin;
        while address < end {
            let m = match A::decode(&self.region, address, &cfg) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("failed to disassemble: {}", e);
                    return;
                }
            };

            for mnemonic in m.mnemonics {
                for instruction in &mnemonic.instructions {
                    match *instruction {
                        panopticon::Statement {
                            op: panopticon::Operation::Call(ref call),
                            ..
                        } => match *call {
                            panopticon::Rvalue::Constant { ref value, .. } => {
                                f(mnemonic.area.start, *value);
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
                address = mnemonic.area.end;
            }
        }
    }
}
