/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package couchdbedvprovider

import (
	"errors"
	"testing"

	"github.com/trustbloc/edv/pkg/restapi/edv/edverrors"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edv/pkg/restapi/edv/models"
)

const (
	testDocID1       = "VJYHHJx4C8J9Fsgz7rZqSp"
	testEncryptedDoc = `{
    "id": "` + testDocID1 + `",
    "sequence": 0,
    "indexed": [
        {
            "sequence": 0,
            "hmac": {
                "id": "https://example.com/kms/z7BgF536GaR",
                "type": "Sha256HmacKey2019"
            },
            "attributes": [
                {
                    "name": "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
                    "value": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
                    "unique": true
                },
                {
                    "name": "DUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
                    "value": "QV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
                }
            ]
        }
    ],
    "jwe": {
        "protected": "eyJlbmMiOiJDMjBQIn0",
        "recipients": [
            {
                "header": {
                    "alg": "A256KW",
                    "kid": "https://example.com/kms/z7BgF536GaR"
                },
                "encrypted_key": "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"
            }
        ],
        "iv": "i8Nins2vTI3PlrYW",
        "ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
        "tag": "pfZO0JulJcrc3trOZy8rjA"
    }
}`

	testDocID2        = "DUXDBhi4qGZij3VMjqFY2q"
	testEncryptedDoc2 = `{
    "id": "` + testDocID2 + `",
    "sequence": 0,
    "indexed": [
        {
            "sequence": 0,
            "hmac": {
                "id": "https://example.com/kms/z7BgF536GaR",
                "type": "Sha256HmacKey2019"
            },
            "attributes": [
                {
                    "name": "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
                    "value": "abcdef",
                    "unique": true
                },
                {
                    "name": "some other index",
                    "value": "some other value"
                },
                {
                    "name": "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
                    "value": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
                    "unique": true
                }
            ]
        }
    ],
    "jwe": {
        "protected": "eyJlbmMiOiJDMjBQIn0",
        "recipients": [
            {
                "header": {
                    "alg": "A256KW",
                    "kid": "https://example.com/kms/z7BgF536GaR"
                },
                "encrypted_key": "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"
            }
        ],
        "iv": "i8Nins2vTI3PlrYW",
        "ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
        "tag": "pfZO0JulJcrc3trOZy8rjA"
    }
}`
	testQuery = `{"IndexName":"","MatchingEncryptedDocID":"` + testDocID1 + `"}`
)

func TestNewProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		prov, err := NewProvider("someURL")
		require.NoError(t, err)
		require.NotNil(t, prov)
	})
	t.Run("Failure: blank URL", func(t *testing.T) {
		prov, err := NewProvider("")
		require.Equal(t, ErrMissingDatabaseURL, err)
		require.Nil(t, prov)
	})
	t.Run("Failure: invalid URL", func(t *testing.T) {
		prov, err := NewProvider("%")
		require.EqualError(t, err, `parse http://%: invalid URL escape "%"`)
		require.Nil(t, prov)
	})
}

func TestCouchDBEDVProvider_CreateStore(t *testing.T) {
	prov, err := NewProvider("someURL")
	require.NoError(t, err)
	require.NotNil(t, prov)

	err = prov.CreateStore("testStore")
	require.Contains(t, err.Error(), "Put http://someURL/testStore: dial tcp: lookup someURL:")
}

func TestCouchDBEDVProvider_OpenStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockCoreProv := mockstore.NewMockStoreProvider()

		err := mockCoreProv.CreateStore("testStore")
		require.NoError(t, err)

		prov := CouchDBEDVProvider{coreProvider: mockCoreProv}

		store, err := prov.OpenStore("testStore")
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Failure: unable to open store due to lookup failure", func(t *testing.T) {
		prov, err := NewProvider("someURL")
		require.NoError(t, err)
		require.NotNil(t, prov)

		store, err := prov.OpenStore("testStore")
		require.Nil(t, store)
		require.Contains(t, err.Error(), "http://someURL/testStore: dial tcp: lookup someURL:")
	})
}

func TestCouchDBEDVStore_Put(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte)}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		err := store.Put(models.EncryptedDocument{ID: "someID"})
		require.NoError(t, err)
	})
	t.Run("Fail: error while creating mapping document", func(t *testing.T) {
		errTest := errors.New("testError")
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte), ErrPut: errTest}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		indexedAttributeCollection1 := models.IndexedAttributeCollection{
			Sequence:          0,
			HMAC:              models.IDTypePair{},
			IndexedAttributes: make([]models.IndexedAttribute, 1),
		}

		testDoc := models.EncryptedDocument{ID: "someID",
			IndexedAttributeCollections: []models.IndexedAttributeCollection{indexedAttributeCollection1}}

		err := store.Put(testDoc)
		require.Equal(t, errTest, err)
	})
}

func TestCouchDBEDVStore_createMappingDocument(t *testing.T) {
	mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte)}
	store := CouchDBEDVStore{coreStore: &mockCoreStore}

	err := store.createMappingDocument("", "")
	require.NoError(t, err)
}

func TestCouchDBEDVStore_Get(t *testing.T) {
	mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte)}
	store := CouchDBEDVStore{coreStore: &mockCoreStore}

	value, err := store.Get("")
	require.Equal(t, storage.ErrValueNotFound, err)
	require.Nil(t, value)
}

func TestCouchDBEDVStore_CreateEDVIndex(t *testing.T) {
	mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte)}
	store := CouchDBEDVStore{coreStore: &mockCoreStore}

	err := store.CreateEDVIndex()
	require.NoError(t, err)
}

type mockIterator struct {
	timesNextCalled         int
	maxTimesNextCanBeCalled int
	errNext                 error
	errValue                error
	errRelease              error
	valueReturn             []byte
}

func (m *mockIterator) Next() (bool, error) {
	if m.timesNextCalled == m.maxTimesNextCanBeCalled {
		return false, m.errNext
	}
	m.timesNextCalled++

	return true, nil
}

func (m *mockIterator) Release() error {
	return m.errRelease
}

func (m *mockIterator) Key() (string, error) {
	return "testKey", nil
}

func (m *mockIterator) Value() ([]byte, error) {
	return m.valueReturn, m.errValue
}

func TestCouchDBEDVStore_Query(t *testing.T) {
	t.Run("Success: no documents match query", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 1,
				valueReturn: []byte(testQuery)}}

		err := mockCoreStore.Put(testDocID1, []byte(testEncryptedDoc))
		require.NoError(t, err)

		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		query := models.Query{
			Name:  "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
			Value: "NotGoingToMatch",
		}

		docIDs, err := store.Query(&query)
		require.NoError(t, err)
		require.Empty(t, docIDs)
	})
	t.Run("Success: one document matches query", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 1,
				valueReturn: []byte(testQuery)}}

		err := mockCoreStore.Put(testDocID1, []byte(testEncryptedDoc))
		require.NoError(t, err)
		err = mockCoreStore.Put(testDocID2, []byte(testEncryptedDoc2))
		require.NoError(t, err)

		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		query := models.Query{
			Name:  "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
			Value: "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
		}

		docIDs, err := store.Query(&query)
		require.NoError(t, err)
		require.Len(t, docIDs, 1)
		require.Equal(t, testDocID1, docIDs[0])
	})
	t.Run("Failure: coreStore query returns error", func(t *testing.T) {
		errTest := errors.New("queryError")
		mockCoreStore := mockstore.MockStore{ErrQuery: errTest}

		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		query := models.Query{}

		docIDs, err := store.Query(&query)
		require.Equal(t, errTest, err)
		require.Empty(t, docIDs)
	})
	t.Run("Failure: first iterator next() call returns error", func(t *testing.T) {
		errTest := errors.New("next error")
		mockCoreStore := mockstore.MockStore{
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 0, errNext: errTest}}

		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		query := models.Query{}

		docIDs, err := store.Query(&query)
		require.Equal(t, errTest, err)
		require.Empty(t, docIDs)
	})
	t.Run("Failure: second iterator next() call returns error", func(t *testing.T) {
		errTest := errors.New("next error")
		mockCoreStore := mockstore.MockStore{
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 1, errNext: errTest,
				valueReturn: []byte(testQuery)}}

		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		query := models.Query{}

		docIDs, err := store.Query(&query)
		require.Equal(t, errTest, err)
		require.Empty(t, docIDs)
	})
	t.Run("Failure: iterator value() call returns error", func(t *testing.T) {
		errTest := errors.New("value error")
		mockCoreStore := mockstore.MockStore{
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 1, errValue: errTest}}

		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		query := models.Query{}

		docIDs, err := store.Query(&query)
		require.Equal(t, errTest, err)
		require.Empty(t, docIDs)
	})
	t.Run("Failure: iterator release() call returns error", func(t *testing.T) {
		errTest := errors.New("release error")
		mockCoreStore := mockstore.MockStore{
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 0, errRelease: errTest}}

		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		query := models.Query{}

		docIDs, err := store.Query(&query)
		require.Equal(t, errTest, err)
		require.Empty(t, docIDs)
	})
	t.Run("Failure: iterator value() call returns value that can't be unmarshalled into a mapping document",
		func(t *testing.T) {
			mockCoreStore := mockstore.MockStore{
				ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 1, valueReturn: []byte("")}}

			store := CouchDBEDVStore{coreStore: &mockCoreStore}

			query := models.Query{}

			docIDs, err := store.Query(&query)
			require.EqualError(t, err, "unexpected end of JSON input")
			require.Empty(t, docIDs)
		})
	t.Run("Failure: value returned from coreStore while "+
		"filtering docs by query can't be unmarshalled into an encrypted document", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 1,
				valueReturn: []byte(testQuery)}}

		err := mockCoreStore.Put(testDocID1, []byte(""))
		require.NoError(t, err)

		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		query := models.Query{
			Name: "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
		}

		docIDs, err := store.Query(&query)
		require.EqualError(t, err, "unexpected end of JSON input")
		require.Empty(t, docIDs)
	})
	t.Run("Failure: document not found in coreStore while filtering docs by query", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 1,
				valueReturn: []byte(testQuery)}}

		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		query := models.Query{
			Name: "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
		}

		docIDs, err := store.Query(&query)
		require.Equal(t, edverrors.ErrDocumentNotFound, err)
		require.Empty(t, docIDs)
	})
	t.Run("Failure: other error in coreStore while filtering docs by query", func(t *testing.T) {
		errTest := errors.New("other store error")
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 1,
				valueReturn: []byte(testQuery)}, ErrGet: errTest}

		err := mockCoreStore.Put(testDocID1, []byte(testEncryptedDoc))
		require.NoError(t, err)
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		query := models.Query{
			Name: "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
		}

		docIDs, err := store.Query(&query)
		require.Equal(t, errTest, err)
		require.Empty(t, docIDs)
	})
}
