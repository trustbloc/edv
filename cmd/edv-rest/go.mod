// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/edv/cmd/edv-rest

replace github.com/trustbloc/edv => ../..

require (
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/gorilla/mux v1.7.4
	github.com/rs/cors v1.7.0
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5-0.20201023140820-2a85df5bc1aa
	github.com/trustbloc/edv v0.0.0
)

go 1.15
