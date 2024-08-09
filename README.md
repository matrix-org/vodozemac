<p align="center">
    <a href="https://git-cliff.org">
        <img src="contrib/mascot.webp" width="300"></a>
    <br>
    <a href="https://github.com/matrix-org/vodozemac/releases">
        <img src="https://img.shields.io/github/v/release/matrix-org/vodozemac?style=flat&labelColor=1C2E27&color=66845F&logo=GitHub&logoColor=white">
    </a>
    <a href="https://crates.io/crates/vodozemac/">
        <img src="https://img.shields.io/crates/v/vodozemac?style=flat&labelColor=1C2E27&color=66845F&logo=Rust&logoColor=white">
    </a>
    <a href="https://codecov.io/gh/matrix-org/vodozemac">
        <img src="https://img.shields.io/codecov/c/gh/matrix-org/vodozemac?style=flat&labelColor=1C2E27&color=66845F&logo=Codecov&logoColor=white">
    </a>
    <br>
    <a href="https://docs.rs/vodozemac/">
        <img src="https://img.shields.io/docsrs/vodozemac?style=flat&labelColor=1C2E27&color=66845F&logo=Rust&logoColor=white">
    </a>
    <a href="https://github.com/matrix-org/vodozemac/actions/workflows/ci.yml">
        <img src="https://img.shields.io/github/actions/workflow/status/matrix-org/vodozemac/ci.yml?style=flat&labelColor=1C2E27&color=66845F&logo=GitHub%20Actions&logoColor=white">
    </a>
    <br>
</p>

A Rust implementation of [Olm][olm-docs] and [Megolm][megolm-docs].

[vodozemac] is a Rust reimplementation of
[libolm](https://gitlab.matrix.org/matrix-org/olm), a cryptographic library used
for end-to-end encryption in [Matrix](https://matrix.org). At its core, it is an
implementation of the [Olm][olm-docs] and [Megolm][megolm-docs] cryptographic
ratchets, along with a high-level API to easily establish cryptographic
communication channels employing those ratchets with other parties. It also
implements some other miscellaneous cryptographic functionality which is useful
for building Matrix clients, such as [SAS][sas].

[vodozemac]: https://hjp.znanje.hr/index.php?show=search_by_id&id=f19vXxZ%2F
[olm-docs]: <https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md>
[megolm-docs]: <https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md>
[sas]: <https://spec.matrix.org/v1.2/client-server-api/#short-authentication-string-sas-verification>

# Features

## Supported

- [Olm](https://matrix-org.github.io/vodozemac/vodozemac/olm/index.html)
- [Megolm](https://matrix-org.github.io/vodozemac/vodozemac/megolm/index.html)
- libolm pickle format (read-only)
- Modern pickle format
- [SAS (Short Authentication Strings)](https://matrix-org.github.io/vodozemac/vodozemac/sas/index.html)

## Unsupported

- Creating asymmetric [server-side message key
  backups][legacy-message-key-backup], since these have been implemented in
  [matrix-sdk-crypto].

[legacy-message-key-backup]:
<https://spec.matrix.org/v1.2/client-server-api/#server-side-key-backups>

[matrix-sdk-crypto]:
<https://github.com/matrix-org/matrix-rust-sdk/tree/main/crates/matrix-sdk-crypto/src/backups>

## Planned

- Primitives for the asymmetric authenticated [server-side message key backups][authenticated-message-key-backup].

[authenticated-message-key-backup]:
<https://github.com/matrix-org/matrix-spec-proposals/pull/4048>
