/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edvprovider

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
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

	testReferenceID = "referenceID"
	testVaultID     = "9ANbuHxeBcicymvRZfcKB2"

	mongoDBConnString    = "mongodb://localhost:27017"
	dockerMongoDBImage   = "mongo"
	dockerMongoDBTagV400 = "4.0.0"
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

func TestEDVProvider_CreateNewVault(t *testing.T) {
	t.Run("Fail to open store for vault", func(t *testing.T) {
		prov := Provider{
			CoreProvider:                    &mock.Provider{ErrOpenStore: errors.New("open error")},
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		err := prov.CreateNewVault(testVaultID, &models.DataVaultConfiguration{})
		require.EqualError(t, err, "failed to open store for vault: open error")
	})
	t.Run("Invalid vault ID", func(t *testing.T) {
		prov := Provider{
			CoreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		err := prov.CreateNewVault("NotValidVaultIDFormat", &models.DataVaultConfiguration{})
		require.EqualError(t, err, "failed to open store for vault: failed to determine underlying store "+
			"name: invalid vault ID: ID must be a base58-encoded 128-bit value")
	})
	t.Run("Fail to create MongoDB index", func(t *testing.T) {
		mongoDBProvider, err := mongodb.NewProvider("mongodb://BadURL", mongodb.WithTimeout(time.Nanosecond))
		require.NoError(t, err)

		prov := Provider{
			CoreProvider:                    mongoDBProvider,
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		err = prov.CreateNewVault(testVaultID, &models.DataVaultConfiguration{})
		require.EqualError(t, err, "failed to create index for indexed attributes: failed to create indexes "+
			"in MongoDB collection: failed to create indexes in MongoDB collection: server selection error: "+
			"context deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, "+
			"Type: Unknown }, ] }")
	})
	t.Run("Fail to store data vault configuration", func(t *testing.T) {
		prov := Provider{
			CoreProvider: &mock.Provider{
				OpenStoreReturn: &mock.Store{ErrPut: errors.New("put error")},
			},
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		err := prov.CreateNewVault(testVaultID, &models.DataVaultConfiguration{})
		require.EqualError(t, err, "failed to store data vault configuration: put error")
	})
}

func TestEDVProvider_StoreExists(t *testing.T) {
	t.Run("Success: store exists - base58-encoded 128-bit store name", func(t *testing.T) {
		prov := Provider{
			CoreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		store, err := prov.OpenVault(testVaultID)
		require.NoError(t, err)
		require.NotNil(t, store)

		exists, err := prov.VaultExists(testVaultID)
		require.NoError(t, err)
		require.True(t, exists)
	})
	t.Run("Success: store does not exist", func(t *testing.T) {
		prov := Provider{
			CoreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		exists, err := prov.VaultExists(testVaultID)
		require.NoError(t, err)
		require.False(t, exists)
	})
	t.Run("Fail to determine store name to use", func(t *testing.T) {
		prov := Provider{
			CoreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID: func(string) (string, error) {
				return "", errors.New("uuid generation error")
			},
		}

		exists, err := prov.VaultExists(testVaultID)
		require.EqualError(t, err, "failed to determine store name to use: "+
			"failed to generate UUID from base 58 encoded 128 bit name: uuid generation error")
		require.False(t, exists)
	})
	t.Run("unexpected error while getting store config", func(t *testing.T) {
		prov := Provider{
			CoreProvider: &mock.Provider{
				ErrGetStoreConfig: errors.New("get store config failure"),
			},
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		exists, err := prov.VaultExists(testVaultID)
		require.EqualError(t, err, "unexpected error while getting store config: "+
			"get store config failure")
		require.False(t, exists)
	})
}

func TestEDVProvider_OpenVault(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		prov := Provider{
			CoreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		store, err := prov.OpenVault(testVaultID)
		require.NoError(t, err)
		require.NotNil(t, store)
	})
	t.Run("Failure: other error in open store", func(t *testing.T) {
		testErr := errors.New("test error")
		prov := Provider{
			CoreProvider:                    &mock.Provider{ErrOpenStore: testErr},
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		_, err := prov.OpenVault(testVaultID)
		require.Equal(t, testErr, err)
	})
	t.Run("Fail to determine underlying store name", func(t *testing.T) {
		prov := Provider{
			CoreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID: func(string) (string, error) {
				return "", errors.New("uuid generation error")
			},
		}

		store, err := prov.OpenVault(testVaultID)
		require.EqualError(t, err, "failed to determine underlying store name: "+
			"failed to generate UUID from base 58 encoded 128 bit name: uuid generation error")
		require.Nil(t, store)
	})
}

func TestEDVProvider_AddIndexes(t *testing.T) {
	t.Run("Success - add 2 indexes", func(t *testing.T) {
		prov := Provider{
			CoreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		err := prov.AddIndexes(testVaultID, []string{"AttributeName1", "AttributeName2"})
		require.NoError(t, err)

		underlyingStoreName, err := prov.getUnderlyingStoreName(testVaultID)
		require.NoError(t, err)

		storeConfig, err := prov.CoreProvider.GetStoreConfig(underlyingStoreName)
		require.NoError(t, err)

		require.Len(t, storeConfig.TagNames, 2)
		require.Equal(t, storeConfig.TagNames[0], "AttributeName1")
		require.Equal(t, storeConfig.TagNames[1], "AttributeName2")
	})
	t.Run("Success - add 2 indexes, then add another new one", func(t *testing.T) {
		prov := Provider{
			CoreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		err := prov.AddIndexes(testVaultID, []string{"AttributeName1", "AttributeName2"})
		require.NoError(t, err)

		err = prov.AddIndexes(testVaultID, []string{"AttributeName3"})
		require.NoError(t, err)

		underlyingStoreName, err := prov.getUnderlyingStoreName(testVaultID)
		require.NoError(t, err)

		storeConfig, err := prov.CoreProvider.GetStoreConfig(underlyingStoreName)
		require.NoError(t, err)

		require.Len(t, storeConfig.TagNames, 3)
		require.Equal(t, storeConfig.TagNames[0], "AttributeName1")
		require.Equal(t, storeConfig.TagNames[1], "AttributeName2")
		require.Equal(t, storeConfig.TagNames[2], "AttributeName3")
	})
	t.Run("Success - add 2 indexes, then add two more (but one was already set before)", func(t *testing.T) {
		prov := Provider{
			CoreProvider:                    mem.NewProvider(),
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		err := prov.AddIndexes(testVaultID, []string{"AttributeName1", "AttributeName2"})
		require.NoError(t, err)

		err = prov.AddIndexes(testVaultID, []string{"AttributeName2", "AttributeName3"})
		require.NoError(t, err)

		underlyingStoreName, err := prov.getUnderlyingStoreName(testVaultID)
		require.NoError(t, err)

		storeConfig, err := prov.CoreProvider.GetStoreConfig(underlyingStoreName)
		require.NoError(t, err)

		require.Len(t, storeConfig.TagNames, 3)
		require.Equal(t, storeConfig.TagNames[0], "AttributeName1")
		require.Equal(t, storeConfig.TagNames[1], "AttributeName2")
		require.Equal(t, storeConfig.TagNames[2], "AttributeName3")
	})
	t.Run("Failed to open underlying store", func(t *testing.T) {
		prov := Provider{
			CoreProvider:                    &mock.Provider{ErrOpenStore: errors.New("open store failure")},
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		err := prov.AddIndexes(testVaultID, []string{"AttributeName1", "AttributeName2"})
		require.EqualError(t, err, "failed to open underlying store: open store failure")
	})
	t.Run("Failed to get existing store configuration", func(t *testing.T) {
		prov := Provider{
			CoreProvider: &mock.Provider{
				ErrGetStoreConfig: errors.New("get store config failure"),
			},
			checkIfBase58Encoded128BitValue: edvutils.CheckIfBase58Encoded128BitValue,
			base58Encoded128BitToUUID:       edvutils.Base58Encoded128BitToUUID,
		}

		err := prov.AddIndexes(testVaultID, []string{"AttributeName1", "AttributeName2"})
		require.EqualError(t, err, "failed to get existing store configuration: get store config failure")
	})
}

func TestEDVStore_Put(t *testing.T) {
	t.Run("Success - document does not have encrypted attributes", func(t *testing.T) {
		memCoreStore, err := mem.NewProvider().OpenStore("corestore")
		require.NoError(t, err)

		store := Vault{CoreStore: memCoreStore, retrievalPageSize: 100}

		err = store.Put(models.EncryptedDocument{ID: "someID"})
		require.NoError(t, err)
	})
	t.Run("Success - document has encrypted attributes", func(t *testing.T) {
		memCoreStore, err := mem.NewProvider().OpenStore("corestore")
		require.NoError(t, err)

		store := Vault{CoreStore: memCoreStore, retrievalPageSize: 100}

		var encryptedDocument models.EncryptedDocument

		err = json.Unmarshal([]byte(testEncryptedDoc), &encryptedDocument)
		require.NoError(t, err)

		err = store.Put(encryptedDocument)
		require.NoError(t, err)
	})
}

func TestEDVStore_Get(t *testing.T) {
	var encryptedDocument models.EncryptedDocument

	err := json.Unmarshal([]byte(testEncryptedDoc), &encryptedDocument)
	require.NoError(t, err)

	t.Run("Using MongoDB", func(t *testing.T) {
		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		pool, mongoDBResource := startMongoDBContainer(t, mongoDBProvider)

		defer func() {
			require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
		}()

		coreStore, err := mongoDBProvider.OpenStore("corestore")
		require.NoError(t, err)

		t.Run("Found", func(t *testing.T) {
			store := Vault{CoreStore: coreStore, retrievalPageSize: 100}

			err = store.Put(encryptedDocument)
			require.NoError(t, err)

			value, err := store.Get(testDocID1)
			require.NoError(t, err)

			var retrievedEncryptedDocument models.EncryptedDocument

			err = json.Unmarshal(value, &retrievedEncryptedDocument)
			require.NoError(t, err)

			require.Equal(t, testDocID1, retrievedEncryptedDocument.ID)
		})
		t.Run("Not found", func(t *testing.T) {
			store := Vault{CoreStore: coreStore, retrievalPageSize: 100}

			value, err := store.Get("DocumentID")
			require.Equal(t, storage.ErrDataNotFound, err)
			require.Nil(t, value)
		})
	})
	t.Run("Using in-memory storage", func(t *testing.T) {
		memCoreStore, err := mem.NewProvider().OpenStore("corestore")
		require.NoError(t, err)

		store := Vault{CoreStore: memCoreStore, retrievalPageSize: 100}

		t.Run("Found", func(t *testing.T) {
			err = store.Put(encryptedDocument)
			require.NoError(t, err)

			value, err := store.Get(testDocID1)
			require.NoError(t, err)

			var retrievedEncryptedDocument models.EncryptedDocument

			err = json.Unmarshal(value, &retrievedEncryptedDocument)
			require.NoError(t, err)

			require.Equal(t, testDocID1, retrievedEncryptedDocument.ID)
		})
		t.Run("Not found", func(t *testing.T) {
			value, err := store.Get("key")
			require.Equal(t, storage.ErrDataNotFound, err)
			require.Nil(t, value)
		})
	})
}

type queryTestEntry struct {
	testName          string
	query             models.Query
	storedDocuments   []models.EncryptedDocument
	expectedDocuments []models.EncryptedDocument
}

func TestEDVStore_Query(t *testing.T) {
	t.Run("Using MongoDB", func(t *testing.T) {
		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		pool, mongoDBResource := startMongoDBContainer(t, mongoDBProvider)

		defer func() {
			require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
		}()

		t.Run("Various single and multiple attribute queries", func(t *testing.T) {
			testTable := generateQueryTestTable(t)

			edvProvider := NewProvider(mongoDBProvider, 100)

			// For each test, we:
			// 1. Create a fresh (empty) vault.
			// 2. Store the test documents in it.
			// 3. Do the test query.
			// 4. Check if we got the expected results back.
			for _, queryTest := range testTable {
				testFailureExtraInfo := fmt.Sprintf("Scenario: %s", queryTest.testName)

				vaultID, err := edvutils.GenerateEDVCompatibleID()
				require.NoError(t, err)

				err = edvProvider.CreateNewVault(vaultID, &models.DataVaultConfiguration{})
				require.NoError(t, err)

				store, err := edvProvider.OpenVault(vaultID)
				require.NoError(t, err)

				storeDocuments(t, store, queryTest.storedDocuments, testFailureExtraInfo)

				documents, err := store.Query(queryTest.query)
				require.NoError(t, err)

				expectedDocumentIDs := extractDocumentIDs(queryTest.expectedDocuments)
				actualDocumentIDs := extractDocumentIDs(documents)

				verifyDocumentIDsMatch(t, actualDocumentIDs, expectedDocumentIDs, testFailureExtraInfo)
			}
		})
	})
	t.Run("Using other storage providers", func(t *testing.T) {
		t.Run("Success: one document matches query", func(t *testing.T) {
			t.Run(`"index + equals" query`, func(t *testing.T) {
				mockCoreStore := mock.Store{
					QueryReturn: &mockIterator{
						maxTimesNextCanBeCalled: 1,
						valueReturn:             []byte(testEncryptedDoc),
					},
				}

				store := Vault{CoreStore: &mockCoreStore, retrievalPageSize: 100}

				query := models.Query{
					Equals: []map[string]string{
						{"CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"},
					},
				}

				docs, err := store.Query(query)
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

				store := Vault{CoreStore: &mockCoreStore, retrievalPageSize: 100}

				query := models.Query{
					Has: "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
				}

				docs, err := store.Query(query)
				require.NoError(t, err)
				require.Len(t, docs, 1)
				require.Equal(t, testDocID1, docs[0].ID)
			})
		})
		t.Run("Failure: coreStore query returns error", func(t *testing.T) {
			errTest := errors.New("queryError")
			mockCoreStore := mock.Store{ErrQuery: errTest}

			store := Vault{CoreStore: &mockCoreStore, retrievalPageSize: 100}

			docs, err := store.Query(models.Query{Equals: []map[string]string{{}}})
			require.EqualError(t, err, "failed to query underlying store: queryError")
			require.Empty(t, docs)
		})
		t.Run("Failure: first iterator next() call returns error", func(t *testing.T) {
			errTest := errors.New("next error")
			mockCoreStore := mock.Store{
				QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 0, errNext: errTest},
			}

			store := Vault{CoreStore: &mockCoreStore, retrievalPageSize: 100}

			docs, err := store.Query(models.Query{Equals: []map[string]string{{}}})
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

			store := Vault{CoreStore: &mockCoreStore, retrievalPageSize: 100}

			docs, err := store.Query(models.Query{Equals: []map[string]string{{}}})
			require.EqualError(t, err, "next error")
			require.Empty(t, docs)
		})
		t.Run("Failure: iterator value() call returns error", func(t *testing.T) {
			errTest := errors.New("value error")
			mockCoreStore := mock.Store{
				QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 1, errValue: errTest},
			}

			store := Vault{CoreStore: &mockCoreStore, retrievalPageSize: 100}

			docs, err := store.Query(models.Query{Equals: []map[string]string{{}}})
			require.EqualError(t, err, "value error")
			require.Empty(t, docs)
		})
		t.Run("Failure: support for multiple attribute queries not implemented for CouchDB or in-memory storage",
			func(t *testing.T) {
				memStore, err := mem.NewProvider().OpenStore("VaultID")
				require.NoError(t, err)

				store := Vault{CoreStore: memStore, retrievalPageSize: 100}

				docs, err := store.Query(models.Query{Equals: []map[string]string{{}, {}}})
				require.EqualError(t, err, "support for multiple attribute queries not implemented for "+
					"CouchDB or in-memory storage")
				require.Empty(t, docs)
			})
	})
}

func TestEDVStore_StoreDataVaultConfiguration(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		memCoreStore, err := mem.NewProvider().OpenStore("corestore")
		require.NoError(t, err)

		store := Vault{CoreStore: memCoreStore, retrievalPageSize: 100}

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
		store := Vault{CoreStore: &mockCoreStore, retrievalPageSize: 100}

		testConfig := models.DataVaultConfiguration{ReferenceID: testReferenceID}

		err := store.StoreDataVaultConfiguration(&testConfig)
		require.Equal(t, errTest, err)
	})
}

func TestEDVStore_Delete(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		mockCoreStore := mock.Store{
			QueryReturn: &mockIterator{},
		}
		store := Vault{CoreStore: &mockCoreStore, retrievalPageSize: 100}

		err := store.Delete(testDocID1)
		require.NoError(t, err)
	})
}

func startMongoDBContainer(t *testing.T, provider *mongodb.Provider) (*dctest.Pool, *dctest.Resource) {
	t.Helper()

	pool, err := dctest.NewPool("")
	require.NoError(t, err)

	mongoDBResource, err := pool.RunWithOptions(&dctest.RunOptions{
		Repository: dockerMongoDBImage,
		Tag:        dockerMongoDBTagV400,
		PortBindings: map[dc.Port][]dc.PortBinding{
			"27017/tcp": {{HostIP: "", HostPort: "27017"}},
		},
	})
	require.NoError(t, err)

	require.NoError(t, waitForMongoDBToBeUp(provider))

	return pool, mongoDBResource
}

func waitForMongoDBToBeUp(provider *mongodb.Provider) error {
	return backoff.Retry(provider.Ping, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 30))
}

func generateQueryTestTable(t *testing.T) []queryTestEntry {
	t.Helper()

	testDocuments := generateTestDocuments(t)

	testQueries := generateTestQueries()

	testTable := []queryTestEntry{
		{
			testName:          "Vault a single document - query for one attribute pair - one result.",
			query:             testQueries[0],
			storedDocuments:   []models.EncryptedDocument{testDocuments[0]},
			expectedDocuments: []models.EncryptedDocument{testDocuments[0]},
		},
		{
			testName:          "Vault three documents - query for one attribute pair - one result.",
			query:             testQueries[0],
			storedDocuments:   []models.EncryptedDocument{testDocuments[0], testDocuments[1], testDocuments[2]},
			expectedDocuments: []models.EncryptedDocument{testDocuments[0]},
		},
		{
			testName:          "Vault three documents - query for one attribute pair - two results.",
			query:             testQueries[1],
			storedDocuments:   []models.EncryptedDocument{testDocuments[0], testDocuments[1], testDocuments[2]},
			expectedDocuments: []models.EncryptedDocument{testDocuments[0], testDocuments[1]},
		},
		{
			testName:          "Vault three documents - query for two attribute pairs (AND) - one result.",
			query:             testQueries[2],
			storedDocuments:   []models.EncryptedDocument{testDocuments[0], testDocuments[1], testDocuments[2]},
			expectedDocuments: []models.EncryptedDocument{testDocuments[1]},
		},
		{
			testName: "Vault five documents - query for an attribute name AND another attribute pair" +
				" - two results.",
			query: testQueries[3],
			storedDocuments: []models.EncryptedDocument{
				testDocuments[0], testDocuments[1], testDocuments[2],
				testDocuments[3], testDocuments[4],
			},
			expectedDocuments: []models.EncryptedDocument{testDocuments[3], testDocuments[4]},
		},
		{
			testName: "Vault five documents - query for an attribute name only - three results.",
			query:    testQueries[4],
			storedDocuments: []models.EncryptedDocument{
				testDocuments[0], testDocuments[1], testDocuments[2],
				testDocuments[3], testDocuments[4],
			},
			expectedDocuments: []models.EncryptedDocument{testDocuments[0], testDocuments[1], testDocuments[2]},
		},
		{
			testName: "Vault five documents - query for an attribute name OR a different attribute name" +
				" - four results.",
			query: testQueries[5],
			storedDocuments: []models.EncryptedDocument{
				testDocuments[0], testDocuments[1], testDocuments[2],
				testDocuments[3], testDocuments[4],
			},
			expectedDocuments: []models.EncryptedDocument{
				testDocuments[0], testDocuments[1],
				testDocuments[3], testDocuments[4],
			},
		},
		{
			testName: "Vault five documents - query for an attribute name OR a different attribute pair" +
				" - two results.",
			query: testQueries[6],
			storedDocuments: []models.EncryptedDocument{
				testDocuments[0], testDocuments[1], testDocuments[2],
				testDocuments[3], testDocuments[4],
			},
			expectedDocuments: []models.EncryptedDocument{
				testDocuments[0],
				testDocuments[3],
			},
		},
		{
			testName: "Vault five documents - query for a first attribute pair AND a second attribute pair" +
				" OR a third attribute pair AND a fourth attribute pair - four results.",
			query: testQueries[7],
			storedDocuments: []models.EncryptedDocument{
				testDocuments[0], testDocuments[1], testDocuments[2],
				testDocuments[3], testDocuments[4],
			},
			expectedDocuments: []models.EncryptedDocument{
				testDocuments[0],
				testDocuments[4],
			},
		},
	}

	return testTable
}

func generateTestDocuments(t *testing.T) []models.EncryptedDocument {
	t.Helper()

	testDocument1Bytes := []byte(`{
    "id": "AJYHHJx4C8J9Fsgz7rZqAE",
    "sequence": 0,
    "indexed": [{
      "sequence": 0,
      "hmac": {
        "id": "https://example.com/kms/z7BgF536GaR",
        "type": "Sha256HmacKey2019"
      },
      "attributes": [{
        "name": "AUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
        "value": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
      },
	  {
        "name": "B2UQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
        "value": "BV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
      }]
    }],
    "jwe": {
      "protected": "eyJlbmMiOiJDMjBQIn0",
      "recipients": [
        {
          "header": {
            "alg": "A256KW",
            "kid": "https://example.com/kms/z7BgF536GaR"
          },
          "encrypted_key":
            "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"
        }
      ],
      "iv": "i8Nins2vTI3PlrYW",
      "ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
      "tag": "pfZO0JulJcrc3trOZy8rjA"
    }
  }`)

	var testDocument1 models.EncryptedDocument

	err := json.Unmarshal(testDocument1Bytes, &testDocument1)
	require.NoError(t, err)

	testDocument2Bytes := []byte(`{
    "id": "BJYHHJx4C8J9Fsgz7rZqAE",
    "sequence": 0,
    "indexed": [{
      "sequence": 0,
      "hmac": {
        "id": "https://example.com/kms/z7BgF536GaR",
        "type": "Sha256HmacKey2019"
      },
      "attributes": [{
        "name": "BUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
        "value": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
      },{
        "name": "B2UQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
        "value": "BV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
      }]
    }],
    "jwe": {
      "protected": "eyJlbmMiOiJDMjBQIn0",
      "recipients": [
        {
          "header": {
            "alg": "A256KW",
            "kid": "https://example.com/kms/z7BgF536GaR"
          },
          "encrypted_key":
            "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"
        }
      ],
      "iv": "i8Nins2vTI3PlrYW",
      "ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
      "tag": "pfZO0JulJcrc3trOZy8rjA"
    }
  }`)

	var testDocument2 models.EncryptedDocument

	err = json.Unmarshal(testDocument2Bytes, &testDocument2)
	require.NoError(t, err)

	testDocument3Bytes := []byte(`{
    "id": "CJYHHJx4C8J9Fsgz7rZqAE",
    "sequence": 0,
    "indexed": [{
      "sequence": 0,
      "hmac": {
        "id": "https://example.com/kms/z7BgF536GaR",
        "type": "Sha256HmacKey2019"
      },
      "attributes": [{
        "name": "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
        "value": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
      },{
        "name": "B2UQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
        "value": "OV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
      }]
    }],
    "jwe": {
      "protected": "eyJlbmMiOiJDMjBQIn0",
      "recipients": [
        {
          "header": {
            "alg": "A256KW",
            "kid": "https://example.com/kms/z7BgF536GaR"
          },
          "encrypted_key":
            "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"
        }
      ],
      "iv": "i8Nins2vTI3PlrYW",
      "ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
      "tag": "pfZO0JulJcrc3trOZy8rjA"
    }
  }`)

	var testDocument3 models.EncryptedDocument

	err = json.Unmarshal(testDocument3Bytes, &testDocument3)
	require.NoError(t, err)

	testDocument4Bytes := []byte(`{
    "id": "DJYHHJx4C8J9Fsgz7rZqAE",
    "sequence": 0,
    "indexed": [{
      "sequence": 0,
      "hmac": {
        "id": "https://example.com/kms/z7BgF536GaR",
        "type": "Sha256HmacKey2019"
      },
      "attributes": [{
        "name": "BUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
        "value": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
      },{
        "name": "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
        "value": "PV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
      }]
    }],
    "jwe": {
      "protected": "eyJlbmMiOiJDMjBQIn0",
      "recipients": [
        {
          "header": {
            "alg": "A256KW",
            "kid": "https://example.com/kms/z7BgF536GaR"
          },
          "encrypted_key":
            "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"
        }
      ],
      "iv": "i8Nins2vTI3PlrYW",
      "ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
      "tag": "pfZO0JulJcrc3trOZy8rjA"
    }
  }`)

	var testDocument4 models.EncryptedDocument

	err = json.Unmarshal(testDocument4Bytes, &testDocument4)
	require.NoError(t, err)

	testDocument5Bytes := []byte(`{
    "id": "EJYHHJx4C8J9Fsgz7rZqAE",
    "sequence": 0,
    "indexed": [{
      "sequence": 0,
      "hmac": {
        "id": "https://example.com/kms/z7BgF536GaR",
        "type": "Sha256HmacKey2019"
      },
      "attributes": [{
        "name": "BUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
        "value": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
      },{
        "name": "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
        "value": "NV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
      }]
    }],
    "jwe": {
      "protected": "eyJlbmMiOiJDMjBQIn0",
      "recipients": [
        {
          "header": {
            "alg": "A256KW",
            "kid": "https://example.com/kms/z7BgF536GaR"
          },
          "encrypted_key":
            "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"
        }
      ],
      "iv": "i8Nins2vTI3PlrYW",
      "ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
      "tag": "pfZO0JulJcrc3trOZy8rjA"
    }
  }`)

	var testDocument5 models.EncryptedDocument

	err = json.Unmarshal(testDocument5Bytes, &testDocument5)
	require.NoError(t, err)

	return []models.EncryptedDocument{testDocument1, testDocument2, testDocument3, testDocument4, testDocument5}
}

func generateTestQueries() []models.Query {
	testQuery1 := models.Query{
		Equals: []map[string]string{
			{
				"AUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
			},
		},
	}

	testQuery2 := models.Query{
		Equals: []map[string]string{
			{
				"B2UQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "BV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
			},
		},
	}

	testQuery3 := models.Query{
		Equals: []map[string]string{
			{
				"BUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ":  "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
				"B2UQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "BV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
			},
		},
	}

	testQuery4 := models.Query{
		Equals: []map[string]string{
			{
				"BUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
				"CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "",
			},
		},
	}

	testQuery5 := models.Query{
		Equals: []map[string]string{
			{
				"B2UQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "",
			},
		},
	}

	testQuery6 := models.Query{
		Equals: []map[string]string{
			{
				"AUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "",
			},
			{
				"BUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "",
			},
		},
	}

	testQuery7 := models.Query{
		Equals: []map[string]string{
			{
				"AUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "",
			},
			{
				"CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "PV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
			},
		},
	}

	testQuery8 := models.Query{
		Equals: []map[string]string{
			{
				"AUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ":  "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
				"B2UQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "BV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
			},
			{
				"BUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
				"CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "NV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
			},
		},
	}

	return []models.Query{
		testQuery1, testQuery2, testQuery3, testQuery4,
		testQuery5, testQuery6, testQuery7, testQuery8,
	}
}

func extractDocumentIDs(documents []models.EncryptedDocument) []string {
	documentIDs := make([]string, len(documents))

	for i, document := range documents {
		documentIDs[i] = document.ID
	}

	return documentIDs
}

func storeDocuments(t *testing.T, store *Vault, documents []models.EncryptedDocument, testFailureExtraInfo string) {
	t.Helper()

	err := store.Put(documents...)
	require.NoError(t, err, testFailureExtraInfo)
}

func verifyDocumentIDsMatch(t *testing.T, actualDocumentIDs, expectedDocumentIDs []string,
	testFailureExtraInfo string) {
	t.Helper()

	require.Equal(t, len(expectedDocumentIDs), len(actualDocumentIDs),
		"Unexpected number of documents received. Expected: %d. Actual: %d. %s",
		len(expectedDocumentIDs), len(actualDocumentIDs), testFailureExtraInfo)

	ensureNoDuplicates(t, actualDocumentIDs,
		fmt.Sprintf("%s. %s", "server returned duplicate documents", testFailureExtraInfo))
	ensureNoDuplicates(t, expectedDocumentIDs,
		fmt.Sprintf("%s. %s", "expected document IDs cannot have duplicates", testFailureExtraInfo))

	checklist := make([]bool, len(expectedDocumentIDs))

	for i, expectedDocumentID := range expectedDocumentIDs {
		for _, actualDocumentID := range actualDocumentIDs {
			if actualDocumentID == expectedDocumentID {
				checklist[i] = true
				break
			}
		}
	}

	for i, documentIDReceived := range checklist {
		require.True(t, documentIDReceived,
			"Document ID %s (and possibly others) was expected but was not returned by the "+
				"server. %s",
			expectedDocumentIDs[i], testFailureExtraInfo)
	}
}

func ensureNoDuplicates(t *testing.T, values []string, errMsg string) {
	t.Helper()

	for i := 0; i < len(values); i++ {
		for j := 0; j < len(values); j++ {
			if i == j {
				continue
			}

			require.NotEqual(t, values[i], values[j], errMsg)
		}
	}
}
