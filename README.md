# findpanics - Find calls to panic functions in rust executables

Use disassembly and DWARF debugging information to find calls to panic functions.
Currently only tested on Linux.

## Installing
After installing [Rust](https://www.rust-lang.org/), run:
```
cargo install --git https://github.com/philipc/findpanics
```

## Example output

```
In function 44ab0 findpanics::main::h08f3b0eaa3fb2978

    Call to 1bb730 core::panicking::panic::hdf4baf73e8b6719e
         at 44d7d core::option::{{impl}}::unwrap<&str> (/checkout/src/libcore/macros.rs:20)
         inlined at findpanics::main (/home/philipc/code/rust/findpanics/src/main.rs:57)
```

## Copyright

Copyright 2018 The ddbug developers

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