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
	github.com/google/tink/go v1.5.0
	github.com/gorilla/mux v1.8.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210429013345-a595aa0b19c4
	github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb v0.0.0-20210326155331-14f4ca7d75cb
	github.com/hyperledger/aries-framework-go-ext/component/vdr/orb v0.0.0-20210415184514-aa162c522bc1
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210427144858-06fb8b7d2d30
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210422133815-2ef2d99cb692
	github.com/kilic/bls12-381 v0.1.0 // indirect
	github.com/magefile/mage v1.11.0 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20201205024021-ac21108117ac // indirect
	github.com/rs/cors v1.7.0
	github.com/sirupsen/logrus v1.8.0 // indirect
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.7.0
	github.com/teserakt-io/golang-ed25519 v0.0.0-20210104091850-3888c087a4c8 // indirect
	github.com/trustbloc/edge-core v0.1.7-0.20210429084532-c385778b4d8b
	github.com/trustbloc/edv v0.0.0
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83 // indirect
	golang.org/x/sys v0.0.0-20210305230114-8fe3ee5dd75b // indirect
)

replace github.com/trustbloc/edv => ../..
