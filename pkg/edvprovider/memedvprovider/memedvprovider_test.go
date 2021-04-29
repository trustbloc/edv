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

	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	testStoreName = "TestStore"
	testVaultID   = "9ANbuHxeBcicymvRZfcKB2"
)

func TestNewProvider(t *testing.T) {
	prov := NewProvider()
	require.NotNil(t, prov)
}

func TestMemEDVProvider_StoreExists(t *testing.T) {
	t.Run("Success: store exists", func(t *testing.T) {
		provider := NewProvider()

		_, err := provider.OpenStore("storename")
		require.NoError(t, err)

		exists, err := provider.StoreExists("storename")
		require.NoError(t, err)
		require.True(t, exists)
	})
	t.Run("Success: store does not exist", func(t *testing.T) {
		provider := NewProvider()

		exists, err := provider.StoreExists("storename")
		require.NoError(t, err)
		require.False(t, exists)
	})
	t.Run("Unexpected error while getting store config", func(t *testing.T) {
		provider := &MemEDVProvider{
			coreProvider: &mock.Provider{ErrGetStoreConfig: errors.New("get store config failure")},
		}

		exists, err := provider.StoreExists("storename")
		require.EqualError(t, err, "unexpected error while getting store config: get store config failure")
		require.False(t, exists)
	})
}

func TestMemEDVProvider_OpenStore(t *testing.T) {
	t.Run("Failed to open store in core provider", func(t *testing.T) {
		provider := MemEDVProvider{coreProvider: &mock.Provider{ErrOpenStore: errors.New("open store failure")}}

		store, err := provider.OpenStore("storename")
		require.EqualError(t, err, "failed to open store in core provider: open store failure")
		require.Nil(t, store)
	})
}

func TestMemEDVProvider_SetStoreConfig(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := NewProvider()

		_, err := provider.OpenStore("storename")
		require.NoError(t, err)

		err = provider.SetStoreConfig("storename", storage.StoreConfiguration{})
		require.NoError(t, err)
	})
	t.Run("Success", func(t *testing.T) {
		provider := NewProvider()

		err := provider.SetStoreConfig("storename", storage.StoreConfiguration{})
		require.EqualError(t, err, "failed to set store config in core provider: "+storage.ErrStoreNotFound.Error())
	})
}

func TestMemEDVStore_Get(t *testing.T) {
	store := openStoreExpectSuccess(t)

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

func TestMemEDVStore_UpsertBulk(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := openStoreExpectSuccess(t)

		testDocument := models.EncryptedDocument{
			ID:                          "Doc1",
			Sequence:                    0,
			IndexedAttributeCollections: nil,
			JWE:                         []byte(`{"SomeJWEKey1":"SomeJWEValue1"}`),
		}

		err := store.UpsertBulk([]models.EncryptedDocument{testDocument})
		require.NoError(t, err)
	})
	t.Run("Fail to store document", func(t *testing.T) {
		store := &MemEDVStore{coreStore: &mock.Store{ErrPut: errors.New("put failure")}}

		testDocument := models.EncryptedDocument{
			ID:                          "Doc1",
			Sequence:                    0,
			IndexedAttributeCollections: nil,
			JWE:                         []byte(`{"SomeJWEKey1":"SomeJWEValue1"}`),
		}

		err := store.UpsertBulk([]models.EncryptedDocument{testDocument})
		require.EqualError(t, err, "failed to store document: put failure")
	})
}

func TestMemEDVStore_StoreDataVaultConfiguration(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := openStoreExpectSuccess(t)
		testVaultConfig := buildTestDataVaultConfig()

		err := store.StoreDataVaultConfiguration(&testVaultConfig, testVaultID)
		require.NoError(t, err)
	})
	t.Run("ReferenceID already exists", func(t *testing.T) {
		store := openStoreExpectSuccess(t)
		testVaultConfig := buildTestDataVaultConfig()

		err := store.StoreDataVaultConfiguration(&testVaultConfig, testVaultID)
		require.NoError(t, err)

		err = store.StoreDataVaultConfiguration(&testVaultConfig, testVaultID)
		require.Equal(t, fmt.Errorf(messages.CheckDuplicateRefIDFailure, messages.ErrDuplicateVault), err)
	})
	t.Run("Fail to store vaultID and vaultName key value pair", func(t *testing.T) {
		errTest := errors.New("error putting key value pair in coreStore")
		store := MemEDVStore{coreStore: &mock.Store{ErrGet: storage.ErrDataNotFound, ErrPut: errTest}}

		testVaultConfig := buildTestDataVaultConfig()
		err := store.StoreDataVaultConfiguration(&testVaultConfig, testVaultID)

		require.Equal(t, errTest, err)
	})
	t.Run("Unexpected error while checking for duplicate reference ID", func(t *testing.T) {
		store := &MemEDVStore{coreStore: &mock.Store{ErrGet: errors.New("get failure")}}
		testVaultConfig := buildTestDataVaultConfig()

		err := store.StoreDataVaultConfiguration(&testVaultConfig, testVaultID)
		require.EqualError(t, err, "an error occurred while querying reference IDs: "+
			"unexpected error while trying to get existing data vault configuration: get failure")
	})
}

func TestMemEDVStore_Update(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		store := openStoreExpectSuccess(t)
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
		store := openStoreExpectSuccess(t)
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
		require.Error(t, err, storage.ErrDataNotFound)
	})
}

func TestMemEDVStore_Query(t *testing.T) {
	store := MemEDVStore{}

	documents, err := store.Query(nil)
	require.Equal(t, ErrQueryingNotSupported, err)
	require.Nil(t, documents)
}

func openStoreExpectSuccess(t *testing.T) edvprovider.EDVStore {
	t.Helper()

	prov := NewProvider()
	require.NotNil(t, prov)

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
