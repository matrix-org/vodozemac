![Build Status](https://img.shields.io/github/actions/workflow/status/matrix-org/vodozemac/ci.yml?style=flat-square)
[![codecov](https://img.shields.io/codecov/c/github/matrix-org/vodozemac/main.svg?style=flat-square)](https://codecov.io/gh/matrix-org/vodozemac)
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen.svg?style=flat-square)](https://opensource.org/licenses/Apache-2.0)
[![Docs - Main](https://img.shields.io/badge/docs-main-blue.svg?style=flat-square)](https://matrix-org.github.io/vodozemac/vodozemac/index.html)
[![Docs - Stable](https://img.shields.io/crates/v/vodozemac?color=blue&label=docs&style=flat-square)](https://docs.rs/vodozemac)

A Rust implementation of Olm and Megolm

vodozemac is a Rust reimplementation of
[libolm](https://gitlab.matrix.org/matrix-org/olm), a cryptographic library
used for end-to-end encryption in [Matrix](https://matrix.org). At its core, it
is an implementation of the [Olm][olm-docs] and [Megolm][megolm-docs] cryptographic ratchets,
along with a high-level API to easily establish cryptographic communication
channels employing those ratchets with other parties. It also implements some
other miscellaneous cryptographic functionality which is useful for building
Matrix clients, such as [SAS][sas].

[olm-docs]:
<https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/olm.md>

[megolm-docs]:
<https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md>

[sas]:
<https://spec.matrix.org/v1.2/client-server-api/#short-authentication-string-sas-verification>

# Features

## Supported

- [Olm](https://matrix-org.github.io/vodozemac/vodozemac/olm/index.html)
- [Megolm](https://matrix-org.github.io/vodozemac/vodozemac/megolm/index.html)
- libolm pickle format (read-only)
- Modern pickle format
- [SAS (Short Authentication Strings)](https://matrix-org.github.io/vodozemac/vodozemac/sas/index.html)

## Unsupported

- Creating asymmetric [server-side message key
  backups][legacy-message-key-backup], since they are slated to be replaced
  with symmetric backups.

## Planned

- Symmetric [server-side message key backups][symmetric-message-key-backup]
- Importing asymmetric [server-side message key
  backups][legacy-message-key-backup], for compatibility with existing backups
  created by libolm.

[legacy-message-key-backup]:
<https://spec.matrix.org/v1.2/client-server-api/#server-side-key-backups>

[symmetric-message-key-backup]:
https://github.com/uhoreg/matrix-doc/blob/symmetric-backups/proposals/3270-symmetric-megolm-backup.md
