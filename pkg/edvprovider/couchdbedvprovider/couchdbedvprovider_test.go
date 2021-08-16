/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package couchdbedvprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/edvutils"
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

	testMappingDocument = `{"AttributeName":"","MatchingEncryptedDocID":"` + testDocID1 + `"}`
	testReferenceID     = "referenceID"
	testVaultID         = "9ANbuHxeBcicymvRZfcKB2"

	testIndexName2 = "indexName2"
	testIndexName3 = "indexName3"
)

type mockIterator struct {
	timesNextCalled         int
	maxTimesNextCanBeCalled int
	noResultsFound          bool
	errNext                 error
	errValue                error
	errClose                error
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

func (m *mockIterator) Close() error {
	m.timesNextCalled = 0
	return m.errClose
}

func (m *mockIterator) Key() (string, error) {
	return m.keyReturn, nil
}

func (m *mockIterator) Value() ([]byte, error) {
	return m.valueReturn, m.errValue
}

func (m *mockIterator) Tags() ([]storage.Tag, error) {
	return nil, nil
}

func (m *mockIterator) TotalItems() (int, error) {
	return 0, nil
}

func TestNewProvider(t *testing.T) {
	t.Run("Failure: blank URL", func(t *testing.T) {
		prov, err := NewProvider("", "", 100)
		require.EqualError(t, err, "failed to create new CouchDB storage provider: "+
			"failed to ping couchDB: url can't be blank")
		require.Nil(t, prov)
	})
	t.Run("Failure: invalid URL", func(t *testing.T) {
		prov, err := NewProvider("%", "", 100)
		require.EqualError(t, err, `failed to create new CouchDB storage provider: `+
			`failed to ping couchDB: parse "http://%": invalid URL escape "%"`)
		require.Nil(t, prov)
	})
	t.Run("Failure: connection refused", func(t *testing.T) {
		prov, err := NewProvider("http://localhost:1234", "", 100)
		require.EqualError(t, err, `failed to create new CouchDB storage provider: `+
			`failed to ping couchDB: failed to probe couchdb for '_users' DB at http://localhost:1234: `+
			`Head "http://localhost:1234/_users": dial tcp [::1]:1234: connect: connection refused`)
		require.Nil(t, prov)
	})
}

func TestCouchDBEDVProvider_StoreExists(t *testing.T) {
	t.Run("Success: store exists - regular string store name", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		store, err := prov.OpenStore("testStore")
		require.NoError(t, err)
		require.NotNil(t, store)

		exists, err := prov.StoreExists("teststore")
		require.NoError(t, err)
		require.True(t, exists)
	})
	t.Run("Success: store exists - base58-encoded 128-bit store name", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		store, err := prov.OpenStore(testVaultID)
		require.NoError(t, err)
		require.NotNil(t, store)

		exists, err := prov.StoreExists(testVaultID)
		require.NoError(t, err)
		require.True(t, exists)
	})
	t.Run("Success: store does not exist", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		exists, err := prov.StoreExists("teststore")
		require.NoError(t, err)
		require.False(t, exists)
	})
	t.Run("Fail to determine store name to use", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID: func(string) (string, error) {
				return "", errors.New("uuid generation error")
			},
		}

		exists, err := prov.StoreExists(testVaultID)
		require.EqualError(t, err, "failed to determine store name to use: "+
			"failed to generate UUID from base 58 encoded 128 bit name: uuid generation error")
		require.False(t, exists)
	})
	t.Run("unexpected error while getting store config", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider: &mock.Provider{
				ErrGetStoreConfig: errors.New("get store config failure"),
			},
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		exists, err := prov.StoreExists(testVaultID)
		require.EqualError(t, err, "unexpected error while getting store config: "+
			"get store config failure")
		require.False(t, exists)
	})
}

func TestCouchDBEDVProvider_OpenStore(t *testing.T) {
	t.Run("Success - regular string store name", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		store, err := prov.OpenStore("testStore")
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Success - base58-encoded 128-bit store name", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		store, err := prov.OpenStore(testVaultID)
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Failure: other error in open store", func(t *testing.T) {
		testErr := errors.New("test error")
		prov := CouchDBEDVProvider{
			coreProvider:                    &mock.Provider{ErrOpenStore: testErr},
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		_, err := prov.OpenStore("testStore")
		require.Equal(t, testErr, err)
	})
	t.Run("Fail to determine store name to use", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID: func(string) (string, error) {
				return "", errors.New("uuid generation error")
			},
		}

		store, err := prov.OpenStore(testVaultID)
		require.EqualError(t, err, "failed to determine store name to use: "+
			"failed to generate UUID from base 58 encoded 128 bit name: uuid generation error")
		require.Nil(t, store)
	})
}

func TestCouchDBEDVProvider_SetStoreConfig(t *testing.T) {
	t.Run("Success - regular string store name", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		store, err := prov.OpenStore("teststore")
		require.NoError(t, err)
		require.NotNil(t, store)

		err = prov.SetStoreConfig("teststore", storage.StoreConfiguration{})
		require.NoError(t, err)
	})
	t.Run("Success - base58-encoded 128-bit store name", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		store, err := prov.OpenStore(testVaultID)
		require.NoError(t, err)
		require.NotNil(t, store)

		err = prov.SetStoreConfig(testVaultID, storage.StoreConfiguration{})
		require.NoError(t, err)
	})
	t.Run("Success - base58-encoded 128-bit store name", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		store, err := prov.OpenStore(testVaultID)
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Failure: other error in open store", func(t *testing.T) {
		testErr := errors.New("test error")
		prov := CouchDBEDVProvider{
			coreProvider:                    &mock.Provider{ErrOpenStore: testErr},
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		_, err := prov.OpenStore("testStore")
		require.Equal(t, testErr, err)
	})
	t.Run("Fail to determine store name to use", func(t *testing.T) {
		prov := CouchDBEDVProvider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID: func(string) (string, error) {
				return "", errors.New("uuid generation error")
			},
		}

		err := prov.SetStoreConfig(testVaultID, storage.StoreConfiguration{})
		require.EqualError(t, err, "failed to determine store name to use: "+
			"failed to generate UUID from base 58 encoded 128 bit name: uuid generation error")
	})
}

func TestCouchDBEDVStore_Put(t *testing.T) {
	t.Run("Success - no new encrypted indices", func(t *testing.T) {
		memCoreStore, err := mem.NewProvider().OpenStore("corestore")
		require.NoError(t, err)

		store := CouchDBEDVStore{coreStore: memCoreStore, retrievalPageSize: 100}

		err = store.Put(models.EncryptedDocument{ID: "someID"})
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
			require.EqualError(t, err,
				fmt.Errorf("failure during encrypted document validation: %w",
					edvprovider.ErrIndexNameAndValueAlreadyDeclaredUnique).Error())
		})
		t.Run("Failure - new encrypted index+value pair is declared unique "+
			"but can't be due to an existing index+value pair", func(t *testing.T) {
			err := storeDocumentsWithEncryptedIndices(t, nonUniqueIndexedAttribute, uniqueIndexedAttribute)
			require.EqualError(t, err,
				fmt.Errorf("failure during encrypted document validation: %w",
					edvprovider.ErrIndexNameAndValueCannotBeUnique).Error())
		})
	})
	t.Run("Fail: error while creating mapping document", func(t *testing.T) {
		errTest := errors.New("testError")
		mockCoreStore := mock.Store{ErrBatch: errTest}
		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		testDoc := models.EncryptedDocument{
			ID:                          "someID",
			IndexedAttributeCollections: nil,
		}

		err := store.Put(testDoc)
		require.EqualError(t, err, fmt.Errorf("failed to put encrypted document(s) and their associated "+
			"mapping document(s) into CouchDB: %w", errTest).Error())
	})
}

func TestCouchDBEDVStore_Get(t *testing.T) {
	memCoreStore, err := mem.NewProvider().OpenStore("corestore")
	require.NoError(t, err)

	store := CouchDBEDVStore{coreStore: memCoreStore, retrievalPageSize: 100}

	value, err := store.Get("key")
	require.Equal(t, storage.ErrDataNotFound, err)
	require.Nil(t, value)
}

func TestCouchDBEDVStore_Query(t *testing.T) {
	t.Run("Success: no documents match query", func(t *testing.T) {
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{
				maxTimesNextCanBeCalled: 1,
				valueReturn:             []byte(testMappingDocument),
			},
		}

		err := mockCoreStore.Put(testDocID1, []byte(testEncryptedDoc))
		require.NoError(t, err)

		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{
			Name:  "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
			Value: "NotGoingToMatch",
		}

		docs, err := store.Query(&query)
		require.NoError(t, err)
		require.Empty(t, docs)
	})
	t.Run("Success: one document matches query", func(t *testing.T) {
		t.Run(`"index + equals" query`, func(t *testing.T) {
			mockCoreStore := mock.Store{
				QueryReturn: &mockIterator{
					maxTimesNextCanBeCalled: 1,
					valueReturn:             []byte(testMappingDocument),
				},
				GetBulkReturn: [][]byte{[]byte(testEncryptedDoc)},
			}

			store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

			query := models.Query{
				Name:  "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
				Value: "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
			}

			docs, err := store.Query(&query)
			require.NoError(t, err)
			require.Len(t, docs, 1)
			require.Equal(t, testDocID1, docs[0].ID)
		})
		t.Run(`"has" query`, func(t *testing.T) {
			mockCoreStore := mock.Store{
				QueryReturn: &mockIterator{
					maxTimesNextCanBeCalled: 1,
					valueReturn:             []byte(testMappingDocument),
				},
				GetBulkReturn: [][]byte{[]byte(testEncryptedDoc)},
			}

			store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

			query := models.Query{
				Has: "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
			}

			docs, err := store.Query(&query)
			require.NoError(t, err)
			require.Len(t, docs, 1)
			require.Equal(t, testDocID1, docs[0].ID)
		})
	})
	t.Run("Failure: coreStore query returns error", func(t *testing.T) {
		errTest := errors.New("queryError")
		mockCoreStore := mock.Store{ErrQuery: errTest}

		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{}

		docs, err := store.Query(&query)
		require.EqualError(t, err, "failed to get mapping documents: queryError")
		require.Empty(t, docs)
	})
	t.Run("Failure: first iterator next() call returns error", func(t *testing.T) {
		errTest := errors.New("next error")
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 0, errNext: errTest},
		}

		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{}

		docs, err := store.Query(&query)
		require.EqualError(t, err, "failed to get mapping documents: "+
			"failed to get next entry from iterator: next error")
		require.Empty(t, docs)
	})
	t.Run("Failure: second iterator next() call returns error", func(t *testing.T) {
		errTest := errors.New("next error")
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{
				maxTimesNextCanBeCalled: 1, errNext: errTest,
				valueReturn: []byte(testMappingDocument),
			},
		}

		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{}

		docs, err := store.Query(&query)
		require.EqualError(t, err, "failed to get mapping documents: next error")
		require.Empty(t, docs)
	})
	t.Run("Failure: iterator value() call returns error", func(t *testing.T) {
		errTest := errors.New("value error")
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 1, errValue: errTest},
		}

		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{}

		docs, err := store.Query(&query)
		require.EqualError(t, err, "failed to get mapping documents: value error")
		require.Empty(t, docs)
	})
	t.Run("Failure: iterator value() call returns value that "+
		"can't be unmarshalled into a mapping document", func(t *testing.T) {
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 1, valueReturn: []byte("")},
		}

		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{}

		docs, err := store.Query(&query)
		require.EqualError(t, err, "failed to get mapping documents: "+
			"failed to unmarshal mapping document bytes: unexpected end of JSON input")
		require.Empty(t, docs)
	})
	t.Run("Failure: value returned from coreStore while "+
		"filtering docs by query that can't be unmarshalled into an encrypted document", func(t *testing.T) {
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{
				maxTimesNextCanBeCalled: 1,
				valueReturn:             []byte(testMappingDocument),
			},
			GetBulkReturn: [][]byte{[]byte("")},
		}

		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{
			Name: "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
		}

		docs, err := store.Query(&query)
		require.EqualError(t, err, "failed to unmarshal matching encrypted document with ID "+
			"VJYHHJx4C8J9Fsgz7rZqSp: unexpected end of JSON input")
		require.Empty(t, docs)
	})
	t.Run("Failure: failed to get encrypted documents containing matching attribute names", func(t *testing.T) {
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{
				maxTimesNextCanBeCalled: 1,
				valueReturn:             []byte(testMappingDocument),
			},
			ErrGetBulk: errors.New("get bulk failure"),
		}

		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{
			Name:  "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
			Value: "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
		}

		docs, err := store.Query(&query)
		require.EqualError(t, err,
			"failed to get encrypted documents containing matching attribute names: get bulk failure")
		require.Nil(t, docs)
	})
}

func TestCouchDBEDVStore_StoreDataVaultConfiguration(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		memCoreStore, err := mem.NewProvider().OpenStore("corestore")
		require.NoError(t, err)

		store := CouchDBEDVStore{coreStore: memCoreStore, retrievalPageSize: 100}

		err = store.StoreDataVaultConfiguration(&models.DataVaultConfiguration{
			ReferenceID: testReferenceID,
		}, testVaultID)
		require.NoError(t, err)
	})
	t.Run("Failure: error during query in coreStore", func(t *testing.T) {
		errTest := errors.New("coreStore query referenceID error")
		mockCoreStore := mock.Store{ErrQuery: errTest}
		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		err := store.StoreDataVaultConfiguration(&models.DataVaultConfiguration{
			ReferenceID: testReferenceID,
		}, testVaultID)
		require.EqualError(t, err, fmt.Errorf(messages.CheckDuplicateRefIDFailure, errTest).Error())
	})
	t.Run("Failure: iterator next() call returns error", func(t *testing.T) {
		errTest := errors.New("iterator next error")
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 0, errNext: errTest},
		}

		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}
		err := store.StoreDataVaultConfiguration(&models.DataVaultConfiguration{
			ReferenceID: testReferenceID,
		}, testVaultID)
		require.EqualError(t, err, fmt.Errorf(messages.CheckDuplicateRefIDFailure, errTest).Error())
	})
	t.Run("Failure: vault with duplicated referenceID already exists", func(t *testing.T) {
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 1, noResultsFound: false},
		}
		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		err := store.StoreDataVaultConfiguration(&models.DataVaultConfiguration{
			ReferenceID: testReferenceID,
		}, testVaultID)
		require.EqualError(t, err, fmt.Errorf(messages.CheckDuplicateRefIDFailure, messages.ErrDuplicateVault).Error())
	})
	t.Run("Failure: error when putting config entry in coreStore", func(t *testing.T) {
		errTest := errors.New("coreStore put config error")
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 1, noResultsFound: true}, ErrPut: errTest,
		}
		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		testConfig := models.DataVaultConfiguration{ReferenceID: testReferenceID}

		err := store.StoreDataVaultConfiguration(&testConfig, testVaultID)
		require.Equal(t, errTest, err)
	})
}

func TestCouchDBEDVStore_Update(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		memCoreStore, err := mem.NewProvider().OpenStore("corestore")
		require.NoError(t, err)

		store := CouchDBEDVStore{coreStore: memCoreStore, retrievalPageSize: 100}

		documentIndexedAttribute2 := buildIndexedAttribute(testIndexName2)
		documentIndexedAttribute3 := buildIndexedAttribute(testIndexName3)
		indexedAttributeCollection2 := models.IndexedAttributeCollection{
			Sequence:          0,
			HMAC:              models.IDTypePair{},
			IndexedAttributes: []models.IndexedAttribute{documentIndexedAttribute2, documentIndexedAttribute3},
		}

		newDoc := buildEncryptedDoc(testDocID1, indexedAttributeCollection2)

		err = store.Update(newDoc)
		require.NoError(t, err)
	})
	t.Run("Failure during encrypted document validation", func(t *testing.T) {
		store := &CouchDBEDVStore{coreStore: &mock.Store{ErrQuery: errors.New("query failure")}}

		err := store.Update(models.EncryptedDocument{
			IndexedAttributeCollections: []models.IndexedAttributeCollection{
				{
					IndexedAttributes: []models.IndexedAttribute{{}},
				},
			},
		})
		require.EqualError(t, err, "failure during encrypted document validation: "+
			"failed to query for documents: failed to get mapping documents: query failure")
	})
	t.Run("Fail to update mapping documents", func(t *testing.T) {
		mockCoreStore := &mock.Store{
			QueryReturn: &mockIterator{
				maxTimesNextCanBeCalled: 1,
				valueReturn:             []byte(testMappingDocument),
			},
			ErrDelete: errors.New("delete failure"),
		}

		store := &CouchDBEDVStore{coreStore: mockCoreStore}

		documentIndexedAttribute2 := buildIndexedAttribute(testIndexName2)
		documentIndexedAttribute3 := buildIndexedAttribute(testIndexName3)
		indexedAttributeCollection2 := models.IndexedAttributeCollection{
			Sequence:          0,
			HMAC:              models.IDTypePair{},
			IndexedAttributes: []models.IndexedAttribute{documentIndexedAttribute2, documentIndexedAttribute3},
		}

		newDoc := buildEncryptedDoc(testDocID1, indexedAttributeCollection2)

		err := store.Update(newDoc)
		require.EqualError(t, err, "failed to update mapping document for document VJYHHJx4C8J9Fsgz7rZqSp: "+
			"delete failure")
	})
}

func TestCouchDBEDVStore_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{},
		}
		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		err := store.Delete(testDocID1)
		require.NoError(t, err)
	})
	t.Run("Fail to get mapping documents", func(t *testing.T) {
		mockCoreStore := mock.Store{
			ErrQuery: errors.New("query failure"),
		}
		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		err := store.Delete(testDocID1)
		require.EqualError(t, err, "failed to get mapping documents: query failure")
	})
	t.Run("Fail to delete mapping document", func(t *testing.T) {
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{
				maxTimesNextCanBeCalled: 1,
				valueReturn:             []byte(testMappingDocument),
			},
			ErrDelete: errors.New("delete failure"),
		}
		store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

		err := store.Delete(testDocID1)
		require.EqualError(t, err, "failed to delete mapping document: delete failure")
	})
}

func TestCouchDBEDVStore_createAndStoreMappingDocument(t *testing.T) {
	memCoreStore, err := mem.NewProvider().OpenStore("corestore")
	require.NoError(t, err)

	store := CouchDBEDVStore{coreStore: memCoreStore, retrievalPageSize: 100}

	err = store.createAndStoreMappingDocument("", "")
	require.NoError(t, err)
}

func storeDocumentsWithEncryptedIndices(t *testing.T,
	firstDocumentIndexedAttribute, secondDocumentIndexedAttribute models.IndexedAttribute) error {
	t.Helper()

	mockCoreStore := mock.Store{QueryReturn: &mockIterator{}}
	store := CouchDBEDVStore{coreStore: &mockCoreStore, retrievalPageSize: 100}

	indexedAttributeCollection1 := models.IndexedAttributeCollection{
		Sequence:          0,
		HMAC:              models.IDTypePair{},
		IndexedAttributes: []models.IndexedAttribute{firstDocumentIndexedAttribute},
	}

	testDoc1 := models.EncryptedDocument{
		ID:                          "someID1",
		IndexedAttributeCollections: []models.IndexedAttributeCollection{indexedAttributeCollection1},
	}

	testDoc1Bytes, err := json.Marshal(testDoc1)
	require.NoError(t, err)

	mockCoreStore.GetBulkReturn = [][]byte{testDoc1Bytes}

	mappingDoc := indexMappingDocument{
		AttributeName:          "indexName1",
		MatchingEncryptedDocID: "someID1",
	}

	marshalledMappingDoc, err := json.Marshal(mappingDoc)
	require.NoError(t, err)

	mockCoreStore.QueryReturn = &mockIterator{
		maxTimesNextCanBeCalled: 1,
		valueReturn:             marshalledMappingDoc,
	}

	indexedAttributeCollection2 := models.IndexedAttributeCollection{
		Sequence:          0,
		HMAC:              models.IDTypePair{},
		IndexedAttributes: []models.IndexedAttribute{secondDocumentIndexedAttribute},
	}

	testDoc2 := models.EncryptedDocument{
		ID:                          "someID2",
		IndexedAttributeCollections: []models.IndexedAttributeCollection{indexedAttributeCollection2},
	}

	return store.Put(testDoc2)
}

func buildIndexedAttribute(name string) models.IndexedAttribute {
	docIndexedAttribute := models.IndexedAttribute{
		Name:   name,
		Value:  "some value",
		Unique: true,
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
