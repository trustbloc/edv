// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv/test/bdd

replace github.com/trustbloc/edv => ../..

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8

// https://github.com/ory/dockertest/issues/208#issuecomment-686820414
replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6

go 1.15

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.6
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210212132055-b94cce120dda
	github.com/igor-pavlenko/httpsignatures-go v0.0.21
	github.com/tidwall/gjson v1.6.7
	github.com/trustbloc/edge-core v0.1.6-0.20210212172534-81ab3a5abf5b
	github.com/trustbloc/edv v0.0.0-00010101000000-000000000000
	gotest.tools/v3 v3.0.3 // indirect
)
