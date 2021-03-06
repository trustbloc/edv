// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv/cmd/edv-rest

replace github.com/trustbloc/edv => ../..

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201104214312-31de2a204df8

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e

require (
	github.com/bluele/gcache v0.0.2 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/cenkalti/backoff/v4 v4.1.0 // indirect
	github.com/containerd/continuity v0.0.0-20200928162600-f2cc35102c2a // indirect
	github.com/google/tink/go v1.5.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.6
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210306170115-156a24580a5c
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210306170115-156a24580a5c
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210306162754-1a1e0c4a378e
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210306162754-1a1e0c4a378e
	github.com/magefile/mage v1.11.0 // indirect
	github.com/rs/cors v1.7.0
	github.com/sirupsen/logrus v1.8.0 // indirect
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.6
	github.com/trustbloc/edv v0.0.0
)

go 1.15
