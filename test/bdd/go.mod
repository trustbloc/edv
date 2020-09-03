// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv/test/bdd

replace github.com/trustbloc/edv => ../..

go 1.13

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/google/tink/go v1.4.0-rc2.0.20200807212851-52ae9c6679b2
	github.com/google/uuid v1.1.1
	github.com/hyperledger/aries-framework-go v0.1.4
	github.com/tidwall/gjson v1.6.0
	github.com/trustbloc/edge-core v0.1.5-0.20200902222811-9a73214c780d
	github.com/trustbloc/edv v0.0.0-00010101000000-000000000000
)
