/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package couchdbedvprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"
	"github.com/trustbloc/edge-core/pkg/storage/mockstore"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
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
	testJWE = `{
	"protected": "eyJlbmMiOiJDMjBQIn0",
	"recipients": [{
		"header": {
		"alg": "A256KW",
		"kid": "https://example.com/kms/z7BgF536GaR"
		},
	"encrypted_key": "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"
	}],
	"iv": "i8Nins2vTI3PlrYW",
	"ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
	"tag": "pfZO0JulJcrc3trOZy8rjA"
}`

	testQuery       = `{"IndexName":"","MatchingEncryptedDocID":"` + testDocID1 + `"}`
	testReferenceID = "referenceID"
	testVaultID     = "9ANbuHxeBcicymvRZfcKB2"

	testIndexName1      = "indexName1"
	testIndexName2      = "indexName2"
	testIndexName3      = "indexName3"
	testMappingDocName1 = "mappingDocumentName1"
	testMappingDocName2 = "mappingDocumentName2"

	testError = "test error"
)

func TestNewProvider(t *testing.T) {
	t.Run("Failure: blank URL", func(t *testing.T) {
		prov, err := NewProvider("", "")
		require.Equal(t, ErrMissingDatabaseURL, err)
		require.Nil(t, prov)
	})
	t.Run("Failure: invalid URL", func(t *testing.T) {
		prov, err := NewProvider("%", "")
		require.EqualError(t, err, `failure while instantiate Kivik CouchDB client: parse "http://%": invalid URL escape "%"`)
		require.Nil(t, prov)
	})
	t.Run("Failure: connection refused", func(t *testing.T) {
		prov, err := NewProvider("http://localhost:5984", "")
		require.NotNil(t, err)
		require.Nil(t, prov)
		require.Contains(t, err.Error(), "failure while pinging couchDB")
	})
}

func TestCouchDBEDVProvider_CreateStore(t *testing.T) {
	t.Run("Success - using base58-encoded 128-bit vaultID as name", func(t *testing.T) {
		prov := CouchDBEDVProvider{coreProvider: mockstore.NewMockStoreProvider()}

		err := prov.CreateStore(testVaultID)
		require.NoError(t, err)
	})
	t.Run("Success - using regular string as name", func(t *testing.T) {
		prov := CouchDBEDVProvider{coreProvider: mockstore.NewMockStoreProvider()}

		err := prov.CreateStore("testStore")
		require.NoError(t, err)
	})
}

func TestCouchDBEDVProvider_OpenStore(t *testing.T) {
	t.Run("Success - regular string store name", func(t *testing.T) {
		mockCoreProv := mockstore.NewMockStoreProvider()

		err := mockCoreProv.CreateStore("testStore")
		require.NoError(t, err)

		prov := CouchDBEDVProvider{coreProvider: mockCoreProv}

		store, err := prov.OpenStore("testStore")
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Success - base58-encoded 128-bit store name", func(t *testing.T) {
		mockCoreProv := mockstore.NewMockStoreProvider()

		err := mockCoreProv.CreateStore("testStore")
		require.NoError(t, err)

		prov := CouchDBEDVProvider{coreProvider: mockCoreProv}

		store, err := prov.OpenStore(testVaultID)
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Failure: other error in open store", func(t *testing.T) {
		testErr := errors.New("test error")
		prov := CouchDBEDVProvider{coreProvider: &mockstore.Provider{ErrOpenStoreHandle: testErr}}

		_, err := prov.OpenStore("testStore")
		require.Equal(t, testErr, err)
	})
}

func TestCouchDBEDVStore_Put(t *testing.T) {
	t.Run("Success - no new encrypted indices", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte)}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		err := store.Put(models.EncryptedDocument{ID: "someID"})
		require.NoError(t, err)
	})
	t.Run("Store documents with encrypted indices", func(t *testing.T) {
		uniqueIndexedAttribute := models.IndexedAttribute{
			Name:   "indexName1",
			Value:  "indexValue1",
			Unique: true,
		}

		nonUniqueIndexedAttribute := models.IndexedAttribute{
			Name:   "indexName1",
			Value:  "indexValue1",
			Unique: false,
		}
		t.Run("Success - new encrypted index doesn't conflict with existing ones", func(t *testing.T) {
			err := storeDocumentsWithEncryptedIndices(t, nonUniqueIndexedAttribute, nonUniqueIndexedAttribute)
			require.NoError(t, err)
		})
		t.Run("Failure - new encrypted index conflicts with an existing "+
			"index name+value pair already declared unique", func(t *testing.T) {
			err := storeDocumentsWithEncryptedIndices(t, uniqueIndexedAttribute, nonUniqueIndexedAttribute)
			require.Equal(t, edvprovider.ErrIndexNameAndValueAlreadyDeclaredUnique, err)
		})
		t.Run("Failure - new encrypted index+value pair is declared unique "+
			"but can't be due to an existing index+value pair", func(t *testing.T) {
			err := storeDocumentsWithEncryptedIndices(t, nonUniqueIndexedAttribute, uniqueIndexedAttribute)
			require.Equal(t, edvprovider.ErrIndexNameAndValueCannotBeUnique, err)
		})
	})

	t.Run("Fail: error while creating mapping document", func(t *testing.T) {
		errTest := errors.New("testError")
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte), ErrPut: errTest}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		testDoc := models.EncryptedDocument{ID: "someID",
			IndexedAttributeCollections: nil}

		err := store.Put(testDoc)
		require.Equal(t, errTest, err)
	})
}

func storeDocumentsWithEncryptedIndices(t *testing.T,
	firstDocumentIndexedAttribute, secondDocumentIndexedAttribute models.IndexedAttribute) error {
	mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
		ResultsIteratorToReturn: &mockIterator{}}
	store := CouchDBEDVStore{coreStore: &mockCoreStore}

	indexedAttributeCollection1 := models.IndexedAttributeCollection{
		Sequence:          0,
		HMAC:              models.IDTypePair{},
		IndexedAttributes: []models.IndexedAttribute{firstDocumentIndexedAttribute},
	}

	testDoc1 := models.EncryptedDocument{ID: "someID1",
		IndexedAttributeCollections: []models.IndexedAttributeCollection{indexedAttributeCollection1}}

	err := store.Put(testDoc1)
	require.NoError(t, err)

	mappingDoc := couchDBIndexMappingDocument{
		IndexName:              "indexName1",
		MatchingEncryptedDocID: "someID1",
	}

	marshalledMappingDoc, err := json.Marshal(mappingDoc)
	require.NoError(t, err)

	mockCoreStore.ResultsIteratorToReturn = &mockIterator{
		maxTimesNextCanBeCalled: 1,
		valueReturn:             marshalledMappingDoc,
	}

	indexedAttributeCollection2 := models.IndexedAttributeCollection{
		Sequence:          0,
		HMAC:              models.IDTypePair{},
		IndexedAttributes: []models.IndexedAttribute{secondDocumentIndexedAttribute},
	}

	testDoc2 := models.EncryptedDocument{ID: "someID2",
		IndexedAttributeCollections: []models.IndexedAttributeCollection{indexedAttributeCollection2}}

	return store.Put(testDoc2)
}

func TestCouchDBEDVStore_createMappingDocument(t *testing.T) {
	mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte)}
	store := CouchDBEDVStore{coreStore: &mockCoreStore}

	err := store.createMappingDocument("", "")
	require.NoError(t, err)
}

func TestCouchDBEDVStore_GetAll(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		coreStore := mockstore.MockStore{
			Store: make(map[string][]byte),
		}

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

		testDocument3 := models.EncryptedDocument{
			ID:                          "Doc3",
			Sequence:                    0,
			IndexedAttributeCollections: nil,
			JWE:                         []byte(`{"SomeJWEKey3":"SomeJWEValue3"}`),
		}

		testDocumentBytes1, err := json.Marshal(testDocument1)
		require.NoError(t, err)

		testDocumentBytes2, err := json.Marshal(testDocument2)
		require.NoError(t, err)

		testDocumentBytes3, err := json.Marshal(testDocument3)
		require.NoError(t, err)

		err = coreStore.Put("Key1", testDocumentBytes1)
		require.NoError(t, err)

		err = coreStore.Put("Key2", testDocumentBytes2)
		require.NoError(t, err)

		err = coreStore.Put("Key3_mapping_", testDocumentBytes3)
		require.NoError(t, err)

		couchDBStore := CouchDBEDVStore{
			coreStore: &coreStore,
			name:      "",
		}

		// testDocument3 should be filtered out since it was stored with a key that indicates that
		// it's a mapping document.
		allValues, err := couchDBStore.GetAll()
		require.NoError(t, err)
		require.Contains(t, allValues, testDocumentBytes1)
		require.Contains(t, allValues, testDocumentBytes2)
		require.Len(t, allValues, 2)
	})
	t.Run("Fail to get all key value pairs from core store", func(t *testing.T) {
		errGetAll := errors.New("get all error")
		store := CouchDBEDVStore{coreStore: &mockstore.MockStore{ErrGetAll: errGetAll}}

		values, err := store.GetAll()
		require.EqualError(t, err, fmt.Errorf(failGetKeyValuePairsFromCoreStoreErrMsg, errGetAll).Error())
		require.Nil(t, values)
	})
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

func TestCouchDBEDVStore_CreateReferenceIDIndex(t *testing.T) {
	mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte)}
	store := CouchDBEDVStore{coreStore: &mockCoreStore}

	err := store.CreateReferenceIDIndex()
	require.NoError(t, err)
}

func TestCouchDBEDVStore_CreateEncryptedDocIDIndex(t *testing.T) {
	mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte)}
	store := CouchDBEDVStore{coreStore: &mockCoreStore}

	err := store.CreateEncryptedDocIDIndex()
	require.NoError(t, err)
}

type wrappedMockStore struct {
	mockStoreToWrap mockstore.MockStore
	mockIterator    *mockIterator
}

func (m *wrappedMockStore) Put(k string, v []byte) error {
	return m.mockStoreToWrap.Put(k, v)
}

func (m *wrappedMockStore) GetAll() (map[string][]byte, error) {
	return m.mockStoreToWrap.GetAll()
}

func (m *wrappedMockStore) Get(k string) ([]byte, error) {
	return m.mockStoreToWrap.Get(k)
}

func (m *wrappedMockStore) CreateIndex(createIndexRequest storage.CreateIndexRequest) error {
	return m.mockStoreToWrap.CreateIndex(createIndexRequest)
}

func (m *wrappedMockStore) Query(query string) (storage.ResultsIterator, error) {
	if strings.Contains(query, "bookmark") {
		return m.mockIterator, nil
	}

	return m.mockStoreToWrap.ResultsIteratorToReturn, nil
}

func (m *wrappedMockStore) Delete(k string) error {
	return m.mockStoreToWrap.Delete(k)
}

type mockIterator struct {
	timesNextCalled         int
	maxTimesNextCanBeCalled int
	noResultsFound          bool
	errNext                 error
	errValue                error
	errRelease              error
	keyReturn               string
	valueReturn             []byte
}

func (m *mockIterator) Next() (bool, error) {
	if m.timesNextCalled == m.maxTimesNextCanBeCalled {
		return false, m.errNext
	}
	m.timesNextCalled++

	if m.noResultsFound {
		return false, nil
	}

	return true, nil
}

func (m *mockIterator) Release() error {
	m.timesNextCalled = 0
	return m.errRelease
}

func (m *mockIterator) Key() (string, error) {
	return m.keyReturn, nil
}

func (m *mockIterator) Value() ([]byte, error) {
	return m.valueReturn, m.errValue
}

func (m *mockIterator) Bookmark() string {
	return "MockBookmark"
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
	t.Run("Success: one document matches query, "+
		"and paging was required (total number of documents found = queryResultsLimit+10)", func(t *testing.T) {
		mockCoreStore := wrappedMockStore{
			mockStoreToWrap: mockstore.MockStore{Store: make(map[string][]byte),
				ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: queryResultsLimit,
					valueReturn: []byte(testQuery)}},
			mockIterator: &mockIterator{maxTimesNextCanBeCalled: 10,
				valueReturn: []byte(testQuery)},
		}

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
	t.Run("Success: one document matches query, "+
		"and paging was required (total number of documents found = queryResultsLimit)", func(t *testing.T) {
		// While it's true that there's no need to fetch another page in this case, we can't know for sure
		// without doing another query and getting an empty page (empty iterator) back,
		// at which point we can be confident that we've got all the documents.
		mockCoreStore := wrappedMockStore{
			mockStoreToWrap: mockstore.MockStore{Store: make(map[string][]byte),
				ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: queryResultsLimit,
					valueReturn: []byte(testQuery)}},
			mockIterator: &mockIterator{maxTimesNextCanBeCalled: 0,
				valueReturn: []byte(testQuery)},
		}

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
		require.Equal(t, messages.ErrDocumentNotFound, err)
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

func TestCouchDBEDVStore_StoreDataVaultConfiguration(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 1, noResultsFound: true}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		err := store.StoreDataVaultConfiguration(&models.DataVaultConfiguration{
			ReferenceID: testReferenceID}, testVaultID)
		require.NoError(t, err)
	})
	t.Run("Failure: error during query in coreStore", func(t *testing.T) {
		errTest := errors.New("coreStore query referenceID error")
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte), ErrQuery: errTest}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		err := store.StoreDataVaultConfiguration(&models.DataVaultConfiguration{
			ReferenceID: testReferenceID}, testVaultID)
		require.EqualError(t, fmt.Errorf(messages.CheckDuplicateRefIDFailure, errTest), err.Error())
	})
	t.Run("Failure: iterator next() call returns error", func(t *testing.T) {
		errTest := errors.New("iterator next error")
		mockCoreStore := mockstore.MockStore{
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 0, errNext: errTest}}

		store := CouchDBEDVStore{coreStore: &mockCoreStore}
		err := store.StoreDataVaultConfiguration(&models.DataVaultConfiguration{
			ReferenceID: testReferenceID}, testVaultID)
		require.EqualError(t, fmt.Errorf(messages.CheckDuplicateRefIDFailure, errTest), err.Error())
	})
	t.Run("Failure: vault with duplicated referenceID already exists", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 1, noResultsFound: false}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		err := store.StoreDataVaultConfiguration(&models.DataVaultConfiguration{
			ReferenceID: testReferenceID}, testVaultID)
		require.EqualError(t, fmt.Errorf(messages.CheckDuplicateRefIDFailure, messages.ErrDuplicateVault), err.Error())
	})
	t.Run("Failure: error when putting config entry in coreStore", func(t *testing.T) {
		errTest := errors.New("coreStore put config error")
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 1, noResultsFound: true}, ErrPut: errTest}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		testConfig := models.DataVaultConfiguration{ReferenceID: testReferenceID}

		err := store.StoreDataVaultConfiguration(&testConfig, testVaultID)
		require.Equal(t, errTest, err)
	})
}

func TestCouchDBEDVStore_Update(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		storeOriginalDocumentBeforeUpdate(t, store, &mockCoreStore, testIndexName1, testDocID1, testMappingDocName1)
		storeOriginalDocumentBeforeUpdate(t, store, &mockCoreStore, testIndexName2, testDocID1, testMappingDocName1)

		documentIndexedAttribute2 := buildIndexedAttribute(testIndexName2, true)
		documentIndexedAttribute3 := buildIndexedAttribute(testIndexName3, true)
		indexedAttributeCollection2 := models.IndexedAttributeCollection{
			Sequence:          0,
			HMAC:              models.IDTypePair{},
			IndexedAttributes: []models.IndexedAttribute{documentIndexedAttribute2, documentIndexedAttribute3},
		}

		newDoc := buildEncryptedDoc(testDocID1, indexedAttributeCollection2)

		err := store.Update(newDoc)
		require.NoError(t, err)

		updatedDocBytes, err := store.Get(testDocID1)
		require.NoError(t, err)

		updatedDoc := &models.EncryptedDocument{}
		err = json.Unmarshal(updatedDocBytes, updatedDoc)
		require.NoError(t, err)

		updated := false

		if (updatedDoc.IndexedAttributeCollections[0].IndexedAttributes[0].Name == testIndexName2 &&
			updatedDoc.IndexedAttributeCollections[0].IndexedAttributes[1].Name == testIndexName3) ||
			(updatedDoc.IndexedAttributeCollections[0].IndexedAttributes[0].Name == testIndexName3 &&
				updatedDoc.IndexedAttributeCollections[0].IndexedAttributes[1].Name == testIndexName2) {
			updated = true
		}

		require.True(t, updated)
	})
	t.Run("Failure - unable to store document since it contains an index name and value that are already "+
		"declared as unique in an existing document", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		storeOriginalDocumentBeforeUpdate(t, store, &mockCoreStore, testIndexName1, testDocID1, testMappingDocName1)
		storeOriginalDocumentBeforeUpdate(t, store, &mockCoreStore, testIndexName2, testDocID2, testMappingDocName2)

		documentIndexedAttribute2 := buildIndexedAttribute(testIndexName2, false)
		indexedAttributeCollection2 := models.IndexedAttributeCollection{
			Sequence:          0,
			HMAC:              models.IDTypePair{},
			IndexedAttributes: []models.IndexedAttribute{documentIndexedAttribute2},
		}

		newDoc := buildEncryptedDoc(testDocID1, indexedAttributeCollection2)

		err := store.Update(newDoc)
		require.Equal(t, edvprovider.ErrIndexNameAndValueAlreadyDeclaredUnique, err)
	})
	t.Run("Failure - error deleting old mapping documents", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte), ErrDelete: errors.New(testError),
			ResultsIteratorToReturn: &mockIterator{}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		storeOriginalDocumentBeforeUpdate(t, store, &mockCoreStore, testIndexName1, testDocID1, testMappingDocName1)

		documentIndexedAttribute2 := buildIndexedAttribute(testIndexName2, true)
		indexedAttributeCollection2 := models.IndexedAttributeCollection{
			Sequence:          0,
			HMAC:              models.IDTypePair{},
			IndexedAttributes: []models.IndexedAttribute{documentIndexedAttribute2},
		}

		newDoc := buildEncryptedDoc(testDocID1, indexedAttributeCollection2)
		err := store.Update(newDoc)
		require.NotNil(t, err)
		require.Equal(t, fmt.Errorf(messages.UpdateMappingDocumentFailure, testDocID1, testError), err)
	})
}

func TestCouchDBEDVStore_findDocMatchingQueryEncryptedDocID(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		storeOriginalDocumentBeforeUpdate(t, store, &mockCoreStore, testIndexName1, testDocID1, testMappingDocName1)

		mappingDocNamesAndIndexNames, err := store.findDocMatchingQueryEncryptedDocID(testDocID1)
		require.NoError(t, err)
		require.NotEmpty(t, mappingDocNamesAndIndexNames)
		require.NotEmpty(t, mappingDocNamesAndIndexNames[testMappingDocName1])
		require.Equal(t, testIndexName1, mappingDocNamesAndIndexNames[testMappingDocName1])
	})
	t.Run("Failure - error making query in coreStore", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte), ErrQuery: errors.New(testError),
			ResultsIteratorToReturn: &mockIterator{}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		mappingDocNamesAndIndexNames, err := store.findDocMatchingQueryEncryptedDocID(testDocID1)
		require.Nil(t, mappingDocNamesAndIndexNames)
		require.NotNil(t, err)
		require.Error(t, err, testError)
	})
	t.Run("Failure - error in iterator Next()", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{maxTimesNextCanBeCalled: 0, errNext: errors.New(testError)}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		mappingDocNamesAndIndexNames, err := store.findDocMatchingQueryEncryptedDocID(testDocID1)
		require.Nil(t, mappingDocNamesAndIndexNames)
		require.NotNil(t, err)
		require.Error(t, err, testError)
	})
	t.Run("Failure - error in iterator Value()", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		mappingDoc := buildIndexMappingDocument(testIndexName1, testDocID1, testMappingDocName1)

		marshalledMappingDoc, err := json.Marshal(mappingDoc)
		require.NoError(t, err)

		mockCoreStore.ResultsIteratorToReturn = &mockIterator{
			maxTimesNextCanBeCalled: 1,
			errValue:                errors.New(testError),
			valueReturn:             marshalledMappingDoc,
		}

		mappingDocNamesAndIndexNames, err := store.findDocMatchingQueryEncryptedDocID(testDocID1)
		require.Nil(t, mappingDocNamesAndIndexNames)
		require.NotNil(t, err)
		require.Error(t, err, testError)
	})
	t.Run("Failure - error in iterator Next() while traversing query results", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		mappingDoc := buildIndexMappingDocument(testIndexName1, testDocID1, testMappingDocName1)

		marshalledMappingDoc, err := json.Marshal(mappingDoc)
		require.NoError(t, err)

		mockCoreStore.ResultsIteratorToReturn = &mockIterator{
			maxTimesNextCanBeCalled: 1,
			errNext:                 errors.New(testError),
			valueReturn:             marshalledMappingDoc,
		}

		mappingDocNamesAndIndexNames, err := store.findDocMatchingQueryEncryptedDocID(testDocID1)
		require.Nil(t, mappingDocNamesAndIndexNames)
		require.NotNil(t, err)
		require.Error(t, err, testError)
	})
	t.Run("Failure - error unmarshalling queried rawDoc", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		mockCoreStore.ResultsIteratorToReturn = &mockIterator{
			maxTimesNextCanBeCalled: 1,
			valueReturn:             []byte("notAMappingDocument"),
		}

		mappingDocNamesAndIndexNames, err := store.findDocMatchingQueryEncryptedDocID(testDocID1)
		require.Nil(t, mappingDocNamesAndIndexNames)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "error unmarshalling rawDoc")
	})
	t.Run("Failure - error in iterator Release()", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		mappingDoc := buildIndexMappingDocument(testIndexName1, testDocID1, testMappingDocName1)

		marshalledMappingDoc, err := json.Marshal(mappingDoc)
		require.NoError(t, err)

		mockCoreStore.ResultsIteratorToReturn = &mockIterator{
			maxTimesNextCanBeCalled: 1,
			errRelease:              errors.New(testError),
			valueReturn:             marshalledMappingDoc,
		}

		mappingDocNamesAndIndexNames, err := store.findDocMatchingQueryEncryptedDocID(testDocID1)
		require.Nil(t, mappingDocNamesAndIndexNames)
		require.NotNil(t, err)
		require.Error(t, err, testError)
	})
}

func TestCouchDBEDVStore_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		storeOriginalDocumentBeforeUpdate(t, store, &mockCoreStore, testIndexName1, testDocID1, testMappingDocName1)

		err := store.Delete(testDocID1)
		require.NoError(t, err)

		_, err = store.Get(testDocID1)
		require.NotNil(t, err)
		require.Equal(t, storage.ErrValueNotFound, err)

		mockCoreStore.ResultsIteratorToReturn = &mockIterator{}

		documentIndexedAttribute1 := buildIndexedAttribute(testIndexName1, true)
		indexedAttributeCollection1 := models.IndexedAttributeCollection{
			Sequence:          0,
			HMAC:              models.IDTypePair{},
			IndexedAttributes: []models.IndexedAttribute{documentIndexedAttribute1},
		}

		doc := buildEncryptedDoc(testDocID1, indexedAttributeCollection1)

		err = store.Put(doc)
		require.NoError(t, err)
	})
	t.Run("Failure - error finding matching document names for the document", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte),
			ResultsIteratorToReturn: &mockIterator{errNext: errors.New(testError)}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		doc := buildEncryptedDoc(testDocID1, models.IndexedAttributeCollection{})

		err := store.Put(doc)
		require.NoError(t, err)

		err = store.Delete(testDocID1)
		require.Error(t, err, testError)
	})
	t.Run("Failure - error deleting mapping documents", func(t *testing.T) {
		mockCoreStore := mockstore.MockStore{Store: make(map[string][]byte), ErrDelete: errors.New(testError),
			ResultsIteratorToReturn: &mockIterator{}}
		store := CouchDBEDVStore{coreStore: &mockCoreStore}

		storeOriginalDocumentBeforeUpdate(t, store, &mockCoreStore, testIndexName1, testDocID1, testMappingDocName1)

		err := store.Delete(testDocID1)
		require.Error(t, err, fmt.Sprintf(messages.DeleteMappingDocumentFailure, testError))
	})
}

func storeOriginalDocumentBeforeUpdate(t *testing.T, store CouchDBEDVStore, mockCoreStore *mockstore.MockStore,
	indexName, encryptedDocID, mappingDocumentID string) {
	documentIndexedAttribute1 := buildIndexedAttribute(indexName, true)
	indexedAttributeCollection1 := models.IndexedAttributeCollection{
		Sequence:          0,
		HMAC:              models.IDTypePair{},
		IndexedAttributes: []models.IndexedAttribute{documentIndexedAttribute1},
	}

	originalDoc := buildEncryptedDoc(encryptedDocID, indexedAttributeCollection1)

	err := store.Put(originalDoc)
	require.NoError(t, err)

	mappingDoc := buildIndexMappingDocument(indexName, encryptedDocID, mappingDocumentID)

	marshalledMappingDoc, err := json.Marshal(mappingDoc)
	require.NoError(t, err)

	mockCoreStore.ResultsIteratorToReturn = &mockIterator{
		maxTimesNextCanBeCalled: 1,
		valueReturn:             marshalledMappingDoc,
	}
}

func buildIndexedAttribute(name string, unique bool) models.IndexedAttribute {
	docIndexedAttribute := models.IndexedAttribute{
		Name:   name,
		Value:  "some value",
		Unique: unique,
	}

	return docIndexedAttribute
}

func buildEncryptedDoc(id string, indexedAttributeCol models.IndexedAttributeCollection) models.EncryptedDocument {
	doc := models.EncryptedDocument{
		ID:                          id,
		Sequence:                    0,
		IndexedAttributeCollections: []models.IndexedAttributeCollection{indexedAttributeCol},
		JWE:                         json.RawMessage(testJWE),
	}

	return doc
}

func buildIndexMappingDocument(indexName, encryptedDocID, mappingDocumentID string) *couchDBIndexMappingDocument {
	mappingDoc := couchDBIndexMappingDocument{
		IndexName:              indexName,
		MatchingEncryptedDocID: encryptedDocID,
		MappingDocumentName:    mappingDocumentID,
	}

	return &mappingDoc
}
