/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package zcapld

import (
	"fmt"
	"testing"

	mockcrypto "github.com/hyperledger/aries-framework-go/pkg/mock/crypto"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/zcapld"
)

func TestNew(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, err := New(&mockkms.KeyManager{}, &mockcrypto.Crypto{}, mockstorage.NewMockStoreProvider())
		require.NoError(t, err)
		require.NotNil(t, svc)
	})

	t.Run("success", func(t *testing.T) {
		svc, err := New(&mockkms.KeyManager{}, &mockcrypto.Crypto{},
			&mockstorage.MockStoreProvider{ErrOpenStoreHandle: fmt.Errorf("failed to open")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to open")
		require.Nil(t, svc)
	})
}

func TestService_Create(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, err := New(&mockkms.KeyManager{}, &mockcrypto.Crypto{}, mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		bytes, err := svc.Create("id", "k1")
		require.NoError(t, err)

		capability, err := zcapld.ParseCapability(bytes)
		require.NoError(t, err)
		require.Equal(t, capability.Context, zcapld.SecurityContextV2)
	})

	t.Run("failed to create signer for root capability", func(t *testing.T) {
		svc, err := New(&mockkms.KeyManager{CreateKeyErr: fmt.Errorf("failed to create key")},
			&mockcrypto.Crypto{}, mockstorage.NewMockStoreProvider())
		require.NoError(t, err)

		_, err = svc.Create("id", "k1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create key")
	})

	t.Run("failed to store root capability in db", func(t *testing.T) {
		svc, err := New(&mockkms.KeyManager{}, &mockcrypto.Crypto{},
			&mockstorage.MockStoreProvider{Store: &mockstorage.MockStore{Store: make(map[string][]byte),
				ErrPut: fmt.Errorf("failed to store")}})
		require.NoError(t, err)

		_, err = svc.Create("id", "k1")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to store")
	})
}
