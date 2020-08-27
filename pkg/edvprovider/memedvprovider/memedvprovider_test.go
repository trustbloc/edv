/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package memedvprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/trustbloc/edv/pkg/restapi/models"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"
)

const testStoreName = "TestStore"

func TestNewProvider(t *testing.T) {
	prov := NewProvider()
	require.NotNil(t, prov)
}

func TestMemEDVStore_GetAll(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		prov := NewProvider()
		require.NotNil(t, prov)

		err := prov.CreateStore(testStoreName)
		require.NoError(t, err)

		store, err := prov.OpenStore(testStoreName)
		require.NoError(t, err)
		require.NotNil(t, store)

		testDocument1 := models.EncryptedDocument{
			ID:                          "Doc1",
			Sequence:                    0,
			IndexedAttributeCollections: nil,
			JWE:                         []byte(`{"SomeJWEKey1":"SomeJWEValue1"}`),
		}

		testDocument2 := models.EncryptedDocument{
			ID:                          "Doc2",
			Sequence:                    0,
			IndexedAttributeCollections: nil,
			JWE:                         []byte(`{"SomeJWEKey2":"SomeJWEValue2"}`),
		}

		err = store.Put(testDocument1)
		require.NoError(t, err)

		err = store.Put(testDocument2)
		require.NoError(t, err)

		expectedValue1, err := json.Marshal(testDocument1)
		require.NoError(t, err)

		expectedValue2, err := json.Marshal(testDocument2)
		require.NoError(t, err)

		allValues, err := store.GetAll()
		require.NoError(t, err)
		require.Contains(t, allValues, expectedValue1)
		require.Contains(t, allValues, expectedValue2)
		require.Len(t, allValues, 2)
	})
	t.Run("Fail to get all key value pairs from core store", func(t *testing.T) {
		errGetAll := errors.New("get all error")
		store := MemEDVStore{coreStore: &mockstore.MockStore{ErrGetAll: errGetAll}}

		values, err := store.GetAll()
		require.EqualError(t, err, fmt.Errorf(failGetKeyValuePairsFromCoreStoreErrMsg, errGetAll).Error())
		require.Nil(t, values)
	})
}
