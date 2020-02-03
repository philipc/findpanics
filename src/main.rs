use addr2line;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate failure;
use gimli;
use home;
use memmap;
use object::{self, Object};
#[macro_use]
extern crate serde_derive;
use serde_yaml;

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::{self, BufRead};
use std::iter::FromIterator;
use std::path::PathBuf;
use std::{env, fs, mem};

mod code;

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
const OPT_TERSE: &str = "t";
const OPT_ALL: &str = "a";

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
        .arg(
            clap::Arg::with_name(OPT_ALL)
                .short("a")
                .help("Show all, including libstd"),
        )
        .arg(
            clap::Arg::with_name(OPT_TERSE)
                .short("t")
                .help("Terser output for diffing (no addresses or paths)"),
        )
        .get_matches();

    let path = matches.value_of(OPT_FILE).unwrap();
    let all = matches.is_present(OPT_ALL);
    let terse = matches.is_present(OPT_TERSE);
    if let Err(e) = process_file(path, all, terse) {
        eprintln!("{}: {}", path, e);
    }
}

fn process_file(path: &str, all: bool, terse: bool) -> Result<()> {
    let cwd = env::current_dir()
        .map_err(|e| Error::from(format!("could not determine current dir: {}", e)))?;
    let cargo_home = home::cargo_home_with_cwd(&cwd)
        .map_err(|e| Error::from(format!("could not determine cargo dir: {}", e)))?;

    let handle = fs::File::open(path).map_err(|e| Error::from(format!("open failed: {}", e)))?;
    let map = unsafe { memmap::Mmap::map(&handle) }
        .map_err(|e| Error::from(format!("memmap failed: {}", e)))?;

    let object = object::File::parse(&*map).map_err(|reason| Error::Object { reason })?;
    let symbolizer = Symbolizer::new(&object)?;
    let disassembler = code::Code::new(&object).ok_or(Error::from("unsupported architecture"))?;
    let mut source_lines = SourceLines::default();

    let mut config = match fs::File::open("findpanics.yaml") {
        Ok(f) => serde_yaml::from_reader(f)
            .map_err(|e| Error::from(format!("read findpanics.yaml failed: {}", e)))?,
        Err(_) => Config::default(),
    };
    // TODO: validate whitelist source matches source obtained from `source_lines`
    config.whitelist.sort();

    // Build list of symbols.
    let mut symbols: Vec<Symbol> = symbolizer
        .symbols
        .symbols()
        .iter()
        .filter_map(|symbol| {
            if symbol.kind() != object::SymbolKind::Text {
                return None;
            }
            let name = symbol.name().expect("symbols must have names");
            let name = addr2line::demangle_auto(name.into(), None);
            let std = is_std_symbol(&name);
            let whitelist = is_whitelist_symbol(&name, std);
            Some(Symbol {
                name,
                std,
                whitelist,
                panic: false,
                address: symbol.address(),
                size: symbol.size(),
                succ: Vec::new(),
                pred: Vec::new(),
            })
        })
        .collect();
    symbols.sort_by(|a, b| a.name.cmp(&b.name));

    // Map from address to symbol index.
    // We assume calls are always to the start of a symbol.
    let symbol_map: HashMap<u64, usize> =
        HashMap::from_iter(symbols.iter().enumerate().map(|(i, s)| (s.address, i)));

    // Build lists of succ/pred.
    for i in 0..symbols.len() {
        let begin = symbols[i].address;
        let end = begin + symbols[i].size;
        let mut succ = Vec::new();
        disassembler.calls(begin, end, |from, to| {
            if let Some(&to) = symbol_map.get(&to) {
                succ.push((from, to));
                symbols[to].pred.push(i);
            }
        });
        symbols[i].succ = succ;
    }

    /*
    // Check that std symbols aren't calling user symbols.
    // Commented out because it picks up things in crates used by std (e.g. backtrace).
    for symbol in &symbols {
        if symbol.std {
            for succ in &symbol.succ {
                let succ = &symbols[succ.1];
                if !succ.std {
                    println!("{} should be std (called by {})", succ.name, symbol.name);
                }
            }
        }
    }
    */

    // Determine which std symbols can panic.
    let mut todo = Vec::new();
    for (i, symbol) in symbols.iter().enumerate() {
        if is_panic_symbol(&symbol.name) {
            todo.push(i);
        }
    }
    let mut current = Vec::new();
    while !todo.is_empty() {
        mem::swap(&mut current, &mut todo);
        for symbol in current.drain(..) {
            let symbol = &mut symbols[symbol];
            if !symbol.panic && !symbol.whitelist {
                symbol.panic = true;
                if symbol.std {
                    todo.extend_from_slice(&symbol.pred);
                }
            }
        }
    }

    // Finally, determine which user symbols can directly panic.
    let mut calls = Vec::new();
    for symbol in &symbols {
        if !all && symbol.std {
            continue;
        }
        if symbol.whitelist {
            continue;
        }

        calls.clear();
        for &(from, to) in &symbol.succ {
            let to = &symbols[to];
            if !to.panic || !to.std {
                continue;
            }
            let mut frames = Vec::new();
            symbolizer.frames(from, |mut frame| {
                if let Some(ref path) = frame.path {
                    frame.file = Some(
                        path.strip_prefix(&cwd)
                            .or_else(|_| path.strip_prefix(&cargo_home))
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
                frames.push(frame)
            });
            if !config.whitelist_matches(&frames, &to.name) {
                calls.push((from, to, frames));
            }
        }

        if !calls.is_empty() {
            print!("In function ");
            if !terse {
                print!("{:x} ", symbol.address);
            }
            println!("{}", symbol.name);
            for &(from, to, ref frames) in &calls {
                println!();

                print!("    Call to ");
                if !terse {
                    print!("{:x} ", to.address);
                }
                println!("{}", to.name);

                print!("         at ");
                if !terse {
                    print!("{:x} ", from);
                }
                let mut first = true;
                for frame in frames {
                    if !first {
                        print!("         inlined at ");
                    }
                    if let Some(ref function) = frame.function {
                        print!("{}", function);
                    } else {
                        print!("<unknown>");
                    }
                    if !terse {
                        if let Some(ref file) = frame.file {
                            print!(" ({}:{}", file, frame.line);
                            if frame.column != 0 {
                                print!(":{}", frame.column);
                            }
                            print!(")");
                        }
                    }
                    println!();
                    if let Some(source) = frame
                        .path
                        .as_ref()
                        .and_then(|path| source_lines.line(path, frame.line))
                    {
                        println!("            source: {}", source);
                    }
                    first = false;
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

fn is_panic_symbol(name: &str) -> bool {
    // TODO: how do we know this is enough?
    name == "core::panicking::panic"
}

fn is_std_symbol(mut name: &str) -> bool {
    if name.starts_with('<') {
        name = &name[1..];
    }

    false
        || name.starts_with("alloc::")
        || name.starts_with("core::")
        || name.starts_with("std::")
        || name.starts_with("std_unicode::")
        || name.starts_with("rustc_demangle::")
        || name.starts_with("__rust_")
        || name.starts_with("str as core::")
        || name.starts_with("char as core::")
        || name.starts_with("&T as core::")
        || name == "rust_begin_unwind"
        || name == "rust_oom"
        || name == "rust_panic"
}

// functions for which panics are not interesting.
fn is_whitelist_symbol(name: &str, std: bool) -> bool {
    // std-only whitelist
    std && (false
        || name == "alloc::fmt::format"
        || name == "core::fmt::write"
        || name == "std::io::Write::write_all"
        || name == "core::ptr::real_drop_in_place"
        || name == "alloc::raw_vec::capacity_overflow"
        || name == "std::rt::lang_start_internal"
        || name.ends_with("::fmt"))
        // std+user whitelist
        || name.ends_with(" as core::fmt::Debug>::fmt")
}

struct Frame {
    function: Option<String>,
    path: Option<PathBuf>,
    file: Option<String>,
    line: usize,
    column: usize,
}

#[derive(Debug, Eq, Serialize, Deserialize)]
struct WhiteListFrame {
    from: String,
    to: String,
    // TODO: record if relative to cwd or cargo_home
    file: String,
    line: usize,
    source: Option<String>,
    comment: String,
}

impl Ord for WhiteListFrame {
    fn cmp(&self, other: &WhiteListFrame) -> Ordering {
        self.from
            .cmp(&other.from)
            .then_with(|| self.to.cmp(&other.to))
            .then_with(|| self.file.cmp(&other.file))
            .then_with(|| self.line.cmp(&other.line))
            .then_with(|| self.source.cmp(&other.source))
    }
}

impl PartialOrd for WhiteListFrame {
    fn partial_cmp(&self, other: &WhiteListFrame) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for WhiteListFrame {
    fn eq(&self, other: &WhiteListFrame) -> bool {
        self.from == other.from
            && self.to == other.to
            && self.file == other.file
            && self.line == other.line
            && self.source == other.source
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Config {
    whitelist: Vec<WhiteListFrame>,
}

impl Config {
    fn whitelist_matches(&self, frames: &[Frame], to: &str) -> bool {
        let mut to = Some(to);
        for frame in frames {
            if let (Some(from), Some(to), Some(file)) =
                (frame.function.as_ref(), to.as_ref(), frame.file.as_ref())
            {
                if self
                    .whitelist
                    .binary_search_by(|whitelist| {
                        whitelist
                            .from
                            .cmp(&from)
                            .then_with(|| whitelist.to.as_str().cmp(to))
                            .then_with(|| whitelist.file.cmp(file))
                            .then_with(|| whitelist.line.cmp(&frame.line))
                    })
                    .is_ok()
                {
                    return true;
                }
            }
            to = frame.function.as_ref().map(String::as_str);
        }
        false
    }
}

#[derive(Default)]
struct SourceLines {
    map: HashMap<PathBuf, Vec<String>>,
}

impl SourceLines {
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
        lines.push(String::from(line?.trim()));
    }
    Ok(lines)
}

struct Symbolizer<'a> {
    symbols: object::SymbolMap<'a>,
    dwarf: addr2line::ObjectContext,
}

impl<'a> Symbolizer<'a> {
    fn new(object: &object::File<'a>) -> Result<Self> {
        let symbols = object.symbol_map();
        let dwarf = addr2line::Context::new(object).map_err(|reason| Error::Dwarf { reason })?;
        Ok(Symbolizer { symbols, dwarf })
    }

    fn frames<F>(&self, address: u64, mut f: F)
    where
        F: FnMut(Frame),
    {
        if let Ok(mut frames) = self.dwarf.find_frames(address) {
            while let Ok(Some(frame)) = frames.next() {
                let function = frame
                    .function
                    .as_ref()
                    .and_then(|function| function.demangle().ok())
                    .map(Cow::into_owned);
                // Require both file and line.
                if let Some(addr2line::Location {
                    file: Some(path),
                    line: Some(line),
                    column,
                }) = frame.location
                {
                    let line = line as usize;
                    let column = column.unwrap_or(0) as usize;
                    f(Frame {
                        function,
                        path: Some(path.into()),
                        file: None,
                        line,
                        column,
                    });
                } else {
                    f(Frame {
                        function,
                        path: None,
                        file: None,
                        line: 0,
                        column: 0,
                    });
                }
            }
        }
    }
}

#[derive(Debug)]
struct Symbol<'a> {
    name: Cow<'a, str>,
    std: bool,
    whitelist: bool,
    panic: bool,
    address: u64,
    size: u64,
    pred: Vec<usize>,
    succ: Vec<(u64, usize)>,
}
