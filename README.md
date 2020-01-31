
[![Release](https://img.shields.io/github/release/trustbloc/edv.svg?style=flat-square)](https://github.com/trustbloc/edv/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/edv/master/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/edv)

[![Build Status](https://dev.azure.com/trustbloc/edge/_apis/build/status/trustbloc.edv?branchName=master)](https://dev.azure.com/trustbloc/edge/_build/latest?definitionId=27&branchName=master)
[![codecov](https://codecov.io/gh/trustbloc/edv/branch/master/graph/badge.svg)](https://codecov.io/gh/trustbloc/edv)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/edv)](https://goreportcard.com/report/github.com/trustbloc/edv)

# edv
An implementation of the [Encrypted Data Vault 0.1 (26 January 2020) specification](https://digitalbazaar.github.io/encrypted-data-vaults/). This implementation is at a very early stage; be sure to read the [limitations](#limitations) section which outlines which parts of the specification have yet to be implemented.

## Limitations
The following has not yet been implemented:
* Encryption
* Update and delete document endpoints
* Streams
* Indexes
* Service Discovery

## Testing
- [Build + BDD Tests](docs/test/build.md)

## Contributing
Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/master/CONTRIBUTING.md) for more information.

## License
Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.