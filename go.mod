// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210303180208-4bb3ae8b32c9
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210305233053-d3d22c802c12
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210304152953-16ffd16ca955
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210226235232-298aa129d822
	github.com/piprate/json-gold v0.3.1-0.20201222165305-f4ce31c02ca3
	github.com/square/go-jose v2.4.1+incompatible
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.6-0.20210224175343-275d0e0370c4
)

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e
