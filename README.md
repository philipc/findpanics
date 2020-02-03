# findpanics - Find calls to panic functions in rust executables

Use disassembly and DWARF debugging information to find calls to panic functions.
Currently only tested on Linux.

This tool is intended for auditing specific aspects of an executable. You will never avoid
most panics in rust code, but avoiding panics in specific locations may be possible.

## Installing
After installing [Rust](https://www.rust-lang.org/), run:
```
cargo install --git https://github.com/philipc/findpanics
```

## Running

Usage: `findpanics <FILE>`

The current directory must be the top level of a crate.

A whitelist of allowed panics is read from `findpanics.yaml` in the current directory.
Currently this whitelist must be created manually.

## Example output

```
In function 45800 findpanics::main::ha119f0252f22d91f

    Call to 1bfe50 core::panicking::panic::hdf4baf73e8b6719e
         at 45acd core::option::{{impl}}::unwrap<&str> (/checkout/src/libcore/macros.rs:20)
         inlined at findpanics::main (src/main.rs:61)
            source: let path = matches.value_of(OPT_FILE).unwrap();
```

## Copyright

Copyright 2018 The findpanics developers

This software is licensed under either of

  * Apache License, Version 2.0 ([`LICENSE-APACHE`](./LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
  * MIT license ([`LICENSE-MIT`](./LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

This software links with a number of libraries, which
have their own licenses. In particular, it links with the
[panopticon](https://github.com/das-labor/panopticon) library, which is
licensed under GPL Version 3.
