/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memstore

import (
	"testing"

	"github.com/trustbloc/edv/pkg/storage"

	"github.com/stretchr/testify/require"
)

func TestMemStore_OpenStore(t *testing.T) {
	provider := NewProvider()

	newStore, err := provider.OpenStore("store1")
	require.NoError(t, err)
	require.IsType(t, &MemStore{}, newStore)
}

func TestMemStore_OpenExistingStore(t *testing.T) {
	provider := NewProvider()

	newStore, err := provider.OpenStore("store1")
	require.NoError(t, err)
	require.IsType(t, &MemStore{}, newStore)

	existingStore, err := provider.OpenStore("store1")
	require.NoError(t, err)
	require.Equal(t, newStore, existingStore)
}

func TestProvider_Close(t *testing.T) {
	provider := NewProvider()

	_, err := provider.OpenStore("store1")
	require.NoError(t, err)

	_, err = provider.OpenStore("store2")
	require.NoError(t, err)

	err = provider.Close()
	require.NoError(t, err)

	require.Equal(t, 0, len(provider.dbs))
}

func TestProvider_CloseStore(t *testing.T) {
	provider := NewProvider()

	newStore, err := provider.OpenStore("store1")
	require.NoError(t, err)

	err = newStore.Put("something", []byte("value"))
	require.NoError(t, err)

	_, err = provider.OpenStore("store2")
	require.NoError(t, err)

	err = provider.CloseStore("store1")
	require.NoError(t, err)

	_, err = newStore.Get("something")
	require.Equal(t, storage.ErrValueNotFound, err)

	require.Equal(t, 1, len(provider.dbs))
}

func TestProvider_CloseStoreDoesNotExist(t *testing.T) {
	provider := NewProvider()

	err := provider.CloseStore("store1")
	require.Equal(t, storage.ErrStoreNotFound, err)
}

func TestMemStore_Get(t *testing.T) {
	memStore := MemStore{db: make(map[string][]byte)}

	memStore.db["testKey"] = []byte("testValue")

	value, err := memStore.Get("testKey")
	require.NoError(t, err)

	require.Equal(t, []byte("testValue"), value)
}
