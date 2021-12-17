# olm-rs

This project is dedicated towards creating a safe wrapper for [libolm](https://git.matrix.org/git/olm/about/) in Rust.

Matrix room for discussion: *[#olm-rs:matrix.org](https://matrix.to/#/#olm-rs:matrix.org)*

If you are looking for a Matrix client library, you should look [here](https://crates.io/crates/matrix-sdk) instead.
This project concerns itself purely with end-to-end encryption, and not Matrix protocol integration.

### Building

`libolm` is compiled and statically linked on building `olm-sys` - so no further setup is required.
Please note however that `libolm` still needs `libstdc++`/`libc++` on your system (and it should already be there).

For further building options and information see the [Readme of `olm-sys`](https://gitlab.gnome.org/BrainBlasted/olm-sys/-/blob/master/README.md).

### Contributing
If you are considering to contribute, take a look at the CONTRIBUTING guide.

Contributors are expected to follow the [Gnome Code of Conduct](https://wiki.gnome.org/Foundation/CodeOfConduct).

### Licensing
This project is licensed under the Apache License 2.0 license - for further information see the LICENSE file.
