// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv/cmd/edv-rest

go 1.16

require (
	github.com/bluele/gcache v0.0.2 // indirect
	github.com/btcsuite/btcd v0.21.0-beta // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/containerd/continuity v0.0.0-20200928162600-f2cc35102c2a // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/tink/go v1.5.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210429205242-c5e97865879c
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210426192704-553740e279e5
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.1.0
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210505173234-006b2f4723fd // indirect
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210510053848-903ac6748b72
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210510053848-903ac6748b72
	github.com/kilic/bls12-381 v0.1.0 // indirect
	github.com/klauspost/cpuid/v2 v2.0.6 // indirect
	github.com/magefile/mage v1.11.0 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.1.0 // indirect
	github.com/rs/cors v1.7.0
	github.com/sirupsen/logrus v1.8.0 // indirect
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8 // indirect
	github.com/trustbloc/edge-core v0.1.7-0.20210429222332-96b987820e63
	github.com/trustbloc/edv v0.0.0
	github.com/trustbloc/orb v0.1.0 // indirect
	golang.org/x/crypto v0.0.0-20210506145944-38f3c27a63bf // indirect
	golang.org/x/sys v0.0.0-20210507161434-a76c4d0a0096 // indirect
)

replace github.com/trustbloc/edv => ../..
