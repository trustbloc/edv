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

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const testStoreName = "TestStore"
const testVaultID = "9ANbuHxeBcicymvRZfcKB2"

func TestNewProvider(t *testing.T) {
	prov := NewProvider()
	require.NotNil(t, prov)
}

func TestMemEDVStore_GetAll(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := createAndOpenStoreExpectSuccess(t)

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

		err := store.Put(testDocument1)
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

func TestMemEDVStore_Get(t *testing.T) {
	store := createAndOpenStoreExpectSuccess(t)

	testDocument := models.EncryptedDocument{
		ID:                          "Doc1",
		Sequence:                    0,
		IndexedAttributeCollections: nil,
		JWE:                         []byte(`{"SomeJWEKey1":"SomeJWEValue1"}`),
	}

	err := store.Put(testDocument)
	require.NoError(t, err)

	expectedValue, err := json.Marshal(testDocument)
	require.NoError(t, err)

	value, err := store.Get(testDocument.ID)
	require.NoError(t, err)
	require.Equal(t, expectedValue, value)
}

func TestMemEDVStore_StoreDataVaultConfiguration(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := createAndOpenStoreExpectSuccess(t)
		testVaultConfig := buildTestDataVaultConfig()

		testConfigEntry := models.DataVaultConfigurationMapping{
			DataVaultConfiguration: testVaultConfig,
			VaultID:                testVaultID,
		}

		expectedValue, err := json.Marshal(testConfigEntry)
		require.NoError(t, err)

		err = store.StoreDataVaultConfiguration(&testVaultConfig, testVaultID)
		require.NoError(t, err)

		allValues, err := store.GetAll()
		require.NoError(t, err)
		require.Contains(t, allValues, expectedValue)
	})
	t.Run("ReferenceID already exists", func(t *testing.T) {
		store := createAndOpenStoreExpectSuccess(t)
		testVaultConfig := buildTestDataVaultConfig()

		err := store.StoreDataVaultConfiguration(&testVaultConfig, testVaultID)
		require.NoError(t, err)

		err = store.StoreDataVaultConfiguration(&testVaultConfig, testVaultID)
		require.Equal(t, fmt.Errorf(messages.CheckDuplicateRefIDFailure, messages.ErrDuplicateVault), err)
	})
	t.Run("Fail to store vaultID and vaultName key value pair", func(t *testing.T) {
		errTest := errors.New("error putting key value pair in coreStore")
		store := MemEDVStore{coreStore: &mockstore.MockStore{Store: make(map[string][]byte), ErrPut: errTest}}

		testVaultConfig := buildTestDataVaultConfig()
		err := store.StoreDataVaultConfiguration(&testVaultConfig, testVaultID)

		require.Equal(t, errTest, err)
	})
	t.Run("Other error in checking duplicate referenceID", func(t *testing.T) {
		errTest := errors.New("other error in getting referenceID in coreStore")
		store := MemEDVStore{coreStore: &mockstore.MockStore{Store: make(map[string][]byte), ErrGet: errTest}}

		testVaultConfig := buildTestDataVaultConfig()
		err := store.StoreDataVaultConfiguration(&testVaultConfig, testVaultID)
		require.NoError(t, err)

		// Needs to store twice because Get() in mockstore returns ErrValueNotFound if the key does not exist,
		// ErrGet can only be returned if the key is found
		err = store.StoreDataVaultConfiguration(&testVaultConfig, testVaultID)
		require.Equal(t, fmt.Errorf(messages.CheckDuplicateRefIDFailure, errTest), err)
	})
}

func TestMemEDVStore_Update(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := createAndOpenStoreExpectSuccess(t)
		origDoc := models.EncryptedDocument{
			ID:       "Doc1",
			Sequence: 0,
			IndexedAttributeCollections: []models.IndexedAttributeCollection{
				{Sequence: 0, IndexedAttributes: []models.IndexedAttribute{
					{Name: "IndexName1", Value: "TestVal", Unique: true},
				}},
			},
			JWE: []byte(`{"SomeJWEKey1":"SomeJWEValue1"}`),
		}

		err := store.Put(origDoc)
		require.NoError(t, err)

		newDoc := models.EncryptedDocument{
			ID:       "Doc1",
			Sequence: 0,
			IndexedAttributeCollections: []models.IndexedAttributeCollection{
				{Sequence: 0, IndexedAttributes: []models.IndexedAttribute{
					{Name: "IndexName2", Value: "TestVal", Unique: true},
				}},
			},
			JWE: []byte(`{"SomeJWEKey2":"SomeJWEValue2"}`),
		}

		err = store.Update(newDoc)
		require.NoError(t, err)

		docBytes, err := store.Get("Doc1")
		require.NoError(t, err)

		updatedDoc := &models.EncryptedDocument{}
		err = json.Unmarshal(docBytes, updatedDoc)
		require.NoError(t, err)

		require.Equal(t, 1, len(updatedDoc.IndexedAttributeCollections))
		require.Equal(t, 1, len(updatedDoc.IndexedAttributeCollections[0].IndexedAttributes))
		require.Equal(t, "IndexName2", updatedDoc.IndexedAttributeCollections[0].IndexedAttributes[0].Name)
		require.Equal(t, json.RawMessage(`{"SomeJWEKey2":"SomeJWEValue2"}`), updatedDoc.JWE)
	})
}

func TestMemEDVStore_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := createAndOpenStoreExpectSuccess(t)
		origDoc := models.EncryptedDocument{
			ID:       "Doc1",
			Sequence: 0,
			JWE:      []byte(`{"SomeJWEKey1":"SomeJWEValue1"}`),
		}

		err := store.Put(origDoc)
		require.NoError(t, err)

		err = store.Delete("Doc1")
		require.NoError(t, err)

		_, err = store.Get("Doc1")
		require.Error(t, err, storage.ErrValueNotFound)
	})
}

func TestMemEDVStore_CreateReferenceIDIndex(t *testing.T) {
	store := createAndOpenStoreExpectSuccess(t)
	err := store.CreateReferenceIDIndex()
	require.Equal(t, edvprovider.ErrIndexingNotSupported, err)
}

func TestMemEDVStore_CreateEncryptedDocIDIndex(t *testing.T) {
	store := createAndOpenStoreExpectSuccess(t)
	err := store.CreateEncryptedDocIDIndex()
	require.Equal(t, edvprovider.ErrIndexingNotSupported, err)
}

func createAndOpenStoreExpectSuccess(t *testing.T) edvprovider.EDVStore {
	prov := NewProvider()
	require.NotNil(t, prov)

	err := prov.CreateStore(testStoreName)
	require.NoError(t, err)

	store, err := prov.OpenStore(testStoreName)
	require.NoError(t, err)
	require.NotNil(t, store)

	return store
}

func buildTestDataVaultConfig() models.DataVaultConfiguration {
	testVaultConfig := models.DataVaultConfiguration{
		Sequence:    0,
		Controller:  "did:example:123456789",
		ReferenceID: "referenceID",
		KEK: models.IDTypePair{
			ID:   "https://example.com/kms/12345",
			Type: "AesKeyWrappingKey2019",
		},
		HMAC: models.IDTypePair{
			ID:   "https://example.com/kms/67891",
			Type: "Sha256HmacKey2019",
		},
	}

	return testVaultConfig
}
