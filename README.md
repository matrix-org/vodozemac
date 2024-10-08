<h1 align="center">vodozemac</h1>
<div align="center">
    <i>vodozemac is an implementation of Olm (Double Ratchet) and Megolm</i>
    <br/><br/>
    <img src="contrib/zemi.png" width="200">
    <br>
    <hr>
    <a href="https://github.com/matrix-org/vodozemac/releases">
        <img src="https://img.shields.io/github/v/release/matrix-org/vodozemac?style=flat&labelColor=1C2E27&color=66845F&logo=GitHub&logoColor=white"></a>
    <a href="https://crates.io/crates/vodozemac/">
        <img src="https://img.shields.io/crates/v/vodozemac?style=flat&labelColor=1C2E27&color=66845F&logo=Rust&logoColor=white"></a>
    <a href="https://codecov.io/gh/matrix-org/vodozemac">
        <img src="https://img.shields.io/codecov/c/gh/matrix-org/vodozemac?style=flat&labelColor=1C2E27&color=66845F&logo=Codecov&logoColor=white"></a>
    <br>
    <a href="https://docs.rs/vodozemac/">
        <img src="https://img.shields.io/docsrs/vodozemac?style=flat&labelColor=1C2E27&color=66845F&logo=Rust&logoColor=white"></a>
    <a href="https://github.com/matrix-org/vodozemac/actions/workflows/ci.yml">
        <img src="https://img.shields.io/github/actions/workflow/status/matrix-org/vodozemac/ci.yml?style=flat&labelColor=1C2E27&color=66845F&logo=GitHub%20Actions&logoColor=white"></a>
    <br>
    <br>
</div>

[vodozemac] is a pure Rust implementation of the [Olm] and [Megolm]
cryptographic ratchets, offering a high-level API for straightforward creation
of secure communication channels using these ratchets.

Designed as a modern alternative to the [libolm] cryptographic library, which is
used for end-to-end encryption in [Matrix], vodozemac provides not only the
[Olm] and [Megolm] ratchets but also additional cryptographic features useful
for developing Matrix clients, such as [SAS] and the integrated encryption
scheme outlined in [MSC4108].

[vodozemac]: https://hjp.znanje.hr/index.php?show=search_by_id&id=f19vXxZ%2F
[Olm]: https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md
[Megolm]: https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md
[libolm]: https://gitlab.matrix.org/matrix-org/olm
[SAS]: https://spec.matrix.org/v1.2/client-server-api/#short-authentication-string-sas-verification
[Matrix]: https://matrix.org
[MSC4108]: https://github.com/matrix-org/matrix-spec-proposals/pull/4108

# Documentation

Explore how to implement end-to-end encryption in our [documentation].

[documentation]: https://docs.rs/vodozemac/latest/vodozemac/

# Installation

To install add the following to your project's `Cargo.toml`:

```toml
[dependencies]
vodozemac = "0.8.1"
```

# Security Notes

This crate has received one security [audit] by [Least Authority], with no
significant findings.

[audit]: https://matrix.org/media/Least%20Authority%20-%20Matrix%20vodozemac%20Final%20Audit%20Report.pdf
[Least Authority]: https://leastauthority.com/
