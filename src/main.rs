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
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;

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
            clap::Arg::with_name(OPT_TERSE)
                .short("t")
                .help("Terser output for diffing (no addresses or paths)"),
        )
        .get_matches();

    let path = matches.value_of(OPT_FILE).unwrap();
    let terse = matches.is_present(OPT_TERSE);
    if let Err(e) = process_file(path, terse) {
        eprintln!("{}: {}", path, e);
    }
}

fn process_file(path: &str, terse: bool) -> Result<()> {
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

    let mut config = match fs::File::open("findpanics.yaml") {
        Ok(f) => serde_yaml::from_reader(f)
            .map_err(|e| Error::from(format!("read findpanics.yaml failed: {}", e)))?,
        Err(_) => Config::default(),
    };
    // TODO: validate whitelist source matches source obtained from `source_lines`
    config.whitelist.sort();

    let mut source_lines = SourceLines::default();

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

    let mut symbols: Vec<(&object::Symbol<'_>, _)> = symbolizer
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
                if !config.whitelist_matches(&frames, &name) {
                    calls.push((from, to, name, frames));
                }
            }
        });
        if !calls.is_empty() {
            print!("In function ");
            if !terse {
                print!("{:x} ", symbol.address());
            }
            if let Some(name) = symbol_name {
                println!("{}", name);
            } else {
                println!("<unknown>");
            }
            for &(from, to, name, ref frames) in &calls {
                println!();

                print!("    Call to ");
                if !terse {
                    print!("{:x} ", to);
                }
                println!("{}", name);

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

fn is_panic_symbol(symbol: &object::Symbol<'_>) -> bool {
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

        name.starts_with("alloc::")
            || name.starts_with("core::")
            || name.starts_with("std::")
            || name.starts_with("std_unicode::")
            || name == "rust_begin_unwind"
            || name == "__rust_maybe_catch_panic"
    } else {
        false
    }
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
