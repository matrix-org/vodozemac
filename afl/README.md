# AFL based fuzz setup for vodozemac

The subdirectories here contain various fuzz harnesses for vodozemac.

# Setup

You will need a nightly Rust compiler for this to work:

```bash
$ rustup toolchain install nightly
```

After that afl-rs needs to be installed, the complete setup guide can be found
[here](https://rust-fuzz.github.io/book/afl/setup.html), you can install afl
with cargo:

```bash
$ cargo install afl
```

# Fuzzing

To start fuzzing using one of the provided harnesses enter the subdirectory of
the harness.

For example,

```bash
$ cd afl/olm-message-decoding
```

Build the harness using the `cargo afl` command:

```bash
$ cargo afl build
```

Start fuzzing using the `cargo afl` command, for example:

```bash
$ cargo afl fuzz -i in -o out target/debug/olm-message-decoding
```
