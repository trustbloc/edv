// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.5
	github.com/piprate/json-gold v0.3.0
	github.com/square/go-jose v2.4.1+incompatible
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5
)

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
