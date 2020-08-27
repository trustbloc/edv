// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv/test/bdd

replace github.com/trustbloc/edv => ../..

go 1.13

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/google/tink/go v0.0.0-20200403150819-3a14bf4b3380
	github.com/google/uuid v1.1.1
	github.com/hyperledger/aries-framework-go v0.1.3
	github.com/sirupsen/logrus v1.4.2
	github.com/tidwall/gjson v1.6.0
	github.com/trustbloc/edge-core v0.1.4-0.20200814194611-5f3b95f18b63
	github.com/trustbloc/edv v0.0.0-00010101000000-000000000000
)
