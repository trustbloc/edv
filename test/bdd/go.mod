// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv/test/bdd

replace github.com/trustbloc/edv => ../..

go 1.15

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.5
	github.com/google/tink/go v1.4.0-rc2.0.20200807212851-52ae9c6679b2
	github.com/google/uuid v1.1.1
	github.com/hyperledger/aries-framework-go v0.1.4
	github.com/tidwall/gjson v1.6.0
	github.com/trustbloc/edge-core v0.1.5-0.20201106164919-76ecfeca954f
	github.com/trustbloc/edv v0.0.0-00010101000000-000000000000
	github.com/trustbloc/hub-auth/test/bdd v0.0.0-20201116135852-764f60b8417b
	gotest.tools/v3 v3.0.3 // indirect
)
