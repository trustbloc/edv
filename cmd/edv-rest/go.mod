// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv/cmd/edv-rest

replace github.com/trustbloc/edv => ../..

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/google/tink/go v1.5.0
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201110161050-249e1c428734
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20201113155502-c4ba5d2c7c0a
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5-0.20201106164919-76ecfeca954f
	github.com/trustbloc/edv v0.0.0
)

go 1.15
