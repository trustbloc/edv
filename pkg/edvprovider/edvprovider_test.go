/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvprovider

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edv/pkg/edvutils"
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

	testReferenceID = "referenceID"
	testVaultID     = "9ANbuHxeBcicymvRZfcKB2"

	encryptedAttributeName1 = "attributeName1"
	encryptedAttributeName2 = "attributeName2"
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
	panic("implement me")
}

func TestNewProvider(t *testing.T) {
	prov := NewProvider(mem.NewProvider(), 100)
	require.NotNil(t, prov)
}

func TestEDVProvider_StoreExists(t *testing.T) {
	t.Run("Success: store exists - regular string store name", func(t *testing.T) {
		prov := Provider{
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
		prov := Provider{
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
		prov := Provider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		exists, err := prov.StoreExists("teststore")
		require.NoError(t, err)
		require.False(t, exists)
	})
	t.Run("Fail to determine store name to use", func(t *testing.T) {
		prov := Provider{
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
		prov := Provider{
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

func TestEDVProvider_OpenStore(t *testing.T) {
	t.Run("Success - regular string store name", func(t *testing.T) {
		prov := Provider{
			coreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		store, err := prov.OpenStore("testStore")
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Success - base58-encoded 128-bit store name", func(t *testing.T) {
		prov := Provider{
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
		prov := Provider{
			coreProvider:                    &mock.Provider{ErrOpenStore: testErr},
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		_, err := prov.OpenStore("testStore")
		require.Equal(t, testErr, err)
	})
	t.Run("Fail to determine store name to use", func(t *testing.T) {
		prov := Provider{
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

func TestEDVProvider_SetStoreConfig(t *testing.T) {
	t.Run("Success - regular string store name", func(t *testing.T) {
		prov := Provider{
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
		prov := Provider{
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
		prov := Provider{
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
		prov := Provider{
			coreProvider:                    &mock.Provider{ErrOpenStore: testErr},
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		_, err := prov.OpenStore("testStore")
		require.Equal(t, testErr, err)
	})
	t.Run("Fail to determine store name to use", func(t *testing.T) {
		prov := Provider{
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

func TestEDVStore_Put(t *testing.T) {
	t.Run("Success - document does not have encrypted attributes", func(t *testing.T) {
		memCoreStore, err := mem.NewProvider().OpenStore("corestore")
		require.NoError(t, err)

		store := Store{coreStore: memCoreStore, retrievalPageSize: 100}

		err = store.Put(models.EncryptedDocument{ID: "someID"})
		require.NoError(t, err)
	})
	t.Run("Success - document has encrypted attributes", func(t *testing.T) {
		memCoreStore, err := mem.NewProvider().OpenStore("corestore")
		require.NoError(t, err)

		store := Store{coreStore: memCoreStore, retrievalPageSize: 100}

		var encryptedDocument models.EncryptedDocument

		err = json.Unmarshal([]byte(testEncryptedDoc), &encryptedDocument)
		require.NoError(t, err)

		err = store.Put(encryptedDocument)
		require.NoError(t, err)
	})
}

func TestEDVStore_Get(t *testing.T) {
	memCoreStore, err := mem.NewProvider().OpenStore("corestore")
	require.NoError(t, err)

	store := Store{coreStore: memCoreStore, retrievalPageSize: 100}

	value, err := store.Get("key")
	require.Equal(t, storage.ErrDataNotFound, err)
	require.Nil(t, value)
}

func TestEDVStore_Query(t *testing.T) {
	t.Run("Success: one document matches query", func(t *testing.T) {
		t.Run(`"index + equals" query`, func(t *testing.T) {
			mockCoreStore := mock.Store{
				QueryReturn: &mockIterator{
					maxTimesNextCanBeCalled: 1,
					valueReturn:             []byte(testEncryptedDoc),
				},
			}

			store := Store{coreStore: &mockCoreStore, retrievalPageSize: 100}

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
					valueReturn:             []byte(testEncryptedDoc),
				},
			}

			store := Store{coreStore: &mockCoreStore, retrievalPageSize: 100}

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

		store := Store{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{}

		docs, err := store.Query(&query)
		require.EqualError(t, err, "failed to query underlying store: queryError")
		require.Empty(t, docs)
	})
	t.Run("Failure: first iterator next() call returns error", func(t *testing.T) {
		errTest := errors.New("next error")
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 0, errNext: errTest},
		}

		store := Store{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{}

		docs, err := store.Query(&query)
		require.EqualError(t, err, "next error")
		require.Empty(t, docs)
	})
	t.Run("Failure: second iterator next() call returns error", func(t *testing.T) {
		errTest := errors.New("next error")
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{
				maxTimesNextCanBeCalled: 1, errNext: errTest,
				valueReturn: []byte(testEncryptedDoc),
			},
		}

		store := Store{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{}

		docs, err := store.Query(&query)
		require.EqualError(t, err, "next error")
		require.Empty(t, docs)
	})
	t.Run("Failure: iterator value() call returns error", func(t *testing.T) {
		errTest := errors.New("value error")
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 1, errValue: errTest},
		}

		store := Store{coreStore: &mockCoreStore, retrievalPageSize: 100}

		query := models.Query{}

		docs, err := store.Query(&query)
		require.EqualError(t, err, "value error")
		require.Empty(t, docs)
	})
}

func TestEDVStore_StoreDataVaultConfiguration(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		memCoreStore, err := mem.NewProvider().OpenStore("corestore")
		require.NoError(t, err)

		store := Store{coreStore: memCoreStore, retrievalPageSize: 100}

		err = store.StoreDataVaultConfiguration(&models.DataVaultConfiguration{
			ReferenceID: testReferenceID,
		})
		require.NoError(t, err)
	})
	t.Run("Failure: error when putting config entry in coreStore", func(t *testing.T) {
		errTest := errors.New("coreStore put config error")
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 1, noResultsFound: true}, ErrPut: errTest,
		}
		store := Store{coreStore: &mockCoreStore, retrievalPageSize: 100}

		testConfig := models.DataVaultConfiguration{ReferenceID: testReferenceID}

		err := store.StoreDataVaultConfiguration(&testConfig)
		require.Equal(t, errTest, err)
	})
}

func TestEDVStore_Update(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		memCoreStore, err := mem.NewProvider().OpenStore("corestore")
		require.NoError(t, err)

		store := Store{coreStore: memCoreStore, retrievalPageSize: 100}

		documentIndexedAttribute2 := buildIndexedAttribute(encryptedAttributeName1)
		documentIndexedAttribute3 := buildIndexedAttribute(encryptedAttributeName2)
		indexedAttributeCollection2 := models.IndexedAttributeCollection{
			Sequence:          0,
			HMAC:              models.IDTypePair{},
			IndexedAttributes: []models.IndexedAttribute{documentIndexedAttribute2, documentIndexedAttribute3},
		}

		newDoc := buildEncryptedDoc(testDocID1, indexedAttributeCollection2)

		err = store.Update(newDoc)
		require.NoError(t, err)
	})
}

func TestEDVStore_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{},
		}
		store := Store{coreStore: &mockCoreStore, retrievalPageSize: 100}

		err := store.Delete(testDocID1)
		require.NoError(t, err)
	})
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
