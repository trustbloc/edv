// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv/cmd/edv-rest

go 1.16

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/google/tink/go v1.6.1-0.20210519071714-58be99b3c4d0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210907141159-23c785674547
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210823223913-7a89535c5407
	github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb v0.0.0-20210823223913-7a89535c5407
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210816155124-45ab1ecd4762
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210907141159-23c785674547
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210907141159-23c785674547
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210907153728-2447efe4140a
	github.com/trustbloc/edv v0.0.0-00010101000000-000000000000
	golang.org/x/net v0.0.0-20210813160813-60bc85c4be6d // indirect
)

replace github.com/trustbloc/edv => ../..
