// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv/cmd/edv-rest

replace github.com/trustbloc/edv => ../..

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/google/tink/go v1.5.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210303180208-4bb3ae8b32c9
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210303194824-a55a12f8d063
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210209170459-14c492334960
	github.com/hyperledger/aries-framework-go-ext/test/component/storage v0.0.0-20201020105420-c85a221b09b5 // indirect
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210304152953-16ffd16ca955
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210303180208-4bb3ae8b32c9
	github.com/phoreproject/bls v0.0.0-20200525203911-a88a5ae26844 // indirect
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.6-0.20210224175343-275d0e0370c4
	github.com/trustbloc/edv v0.0.0
	golang.org/x/net v0.0.0-20210226172049-e18ecbb05110 // indirect
)

go 1.15
