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

	testVaultID = "9ANbuHxeBcicymvRZfcKB2"

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
	tagsReturn              []storage.Tag
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
	return m.tagsReturn, nil
}

func (m *mockIterator) TotalItems() (int, error) {
	panic("implement me")
}

func TestNewProvider(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		prov, err := NewProvider(mem.NewProvider(),
			"configurations", "documents", 100)
		require.NoError(t, err)
		require.NotNil(t, prov)
	})
	t.Run("Fail to open configurations store", func(t *testing.T) {
		prov, err := NewProvider(&mock.Provider{ErrOpenStore: errors.New("open store error")},
			"configurations", "documents", 100)
		require.EqualError(t, err, "failed to open configuration store: open store error")
		require.Nil(t, prov)
	})
	t.Run("Fail to create indexes in MongoDB", func(t *testing.T) {
		mongoDBProvider, err := mongodb.NewProvider("mongodb://BadURL",
			mongodb.WithTimeout(1))
		require.NoError(t, err)

		prov, err := NewProvider(mongoDBProvider,
			"configurations", "documents", 100)
		require.EqualError(t, err, "failed to create indexes in MongoDB: failed to create indexes in "+
			"MongoDB collection: failed to create indexes in MongoDB collection: server selection error: "+
			"context deadline exceeded, current topology: { Type: Unknown, Servers: [{ Addr: badurl:27017, "+
			"Type: Unknown }, ] }")
		require.Nil(t, prov)
	})
}

func TestProvider_CreateNewVault(t *testing.T) {
	t.Run("Fail to store data vault configuration", func(t *testing.T) {
		prov := Provider{
			configStore: &mock.Store{ErrPut: errors.New("put error")},
		}

		err := prov.CreateNewVault(testVaultID, &models.DataVaultConfiguration{})
		require.EqualError(t, err, "failed to store data vault configuration: put error")
	})
}

func TestProvider_StoreExists(t *testing.T) {
	t.Run("Success: store exists", func(t *testing.T) {
		provider, err := NewProvider(mem.NewProvider(),
			"configurations", "documents", 100)
		require.NoError(t, err)

		err = provider.CreateNewVault(testVaultID, &models.DataVaultConfiguration{})
		require.NoError(t, err)

		exists, err := provider.VaultExists(testVaultID)
		require.NoError(t, err)
		require.True(t, exists)
	})
	t.Run("Success: store does not exist", func(t *testing.T) {
		provider, err := NewProvider(mem.NewProvider(),
			"configurations", "documents", 100)
		require.NoError(t, err)

		exists, err := provider.VaultExists(testVaultID)
		require.NoError(t, err)
		require.False(t, exists)
	})
}

func TestProvider_Put(t *testing.T) {
	provider, err := NewProvider(mem.NewProvider(),
		"configurations", "documents", 100)
	require.NoError(t, err)

	t.Run("Success - document does not have encrypted attributes", func(t *testing.T) {
		err = provider.Put(testVaultID, models.EncryptedDocument{ID: "someID"})
		require.NoError(t, err)
	})
	t.Run("Success - document has encrypted attributes", func(t *testing.T) {
		var encryptedDocument models.EncryptedDocument

		err = json.Unmarshal([]byte(testEncryptedDoc), &encryptedDocument)
		require.NoError(t, err)

		err = provider.Put(testVaultID, encryptedDocument)
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

		edvProvider, err := NewProvider(mongoDBProvider,
			"configurations", "documents", 100)
		require.NoError(t, err)

		t.Run("Found", func(t *testing.T) {
			err = edvProvider.Put(testVaultID, encryptedDocument)
			require.NoError(t, err)

			value, err := edvProvider.Get(testVaultID, testDocID1)
			require.NoError(t, err)

			var retrievedEncryptedDocument models.EncryptedDocument

			err = json.Unmarshal(value, &retrievedEncryptedDocument)
			require.NoError(t, err)

			require.Equal(t, testDocID1, retrievedEncryptedDocument.ID)
		})
		t.Run("Not found", func(t *testing.T) {
			value, err := edvProvider.Get(testVaultID, "NonExistentDocID")
			require.Equal(t, storage.ErrDataNotFound, err)
			require.Nil(t, value)
		})
	})
	t.Run("Using in-memory storage", func(t *testing.T) {
		edvProvider, err := NewProvider(mem.NewProvider(),
			"configurations", "documents", 100)
		require.NoError(t, err)

		t.Run("Found", func(t *testing.T) {
			err = edvProvider.Put(testVaultID, encryptedDocument)
			require.NoError(t, err)

			value, err := edvProvider.Get(testVaultID, testDocID1)
			require.NoError(t, err)

			var retrievedEncryptedDocument models.EncryptedDocument

			err = json.Unmarshal(value, &retrievedEncryptedDocument)
			require.NoError(t, err)

			require.Equal(t, testDocID1, retrievedEncryptedDocument.ID)
		})
		t.Run("Not found", func(t *testing.T) {
			value, err := edvProvider.Get(testVaultID, "NonExistentDocID")
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

		provider, err := NewProvider(mongoDBProvider,
			"configurations", "documents", 100)
		require.NoError(t, err)

		t.Run("Success cases", func(t *testing.T) {
			doQueryTests(t, provider, false)
		})
	})
	t.Run("Using in-memory storage", func(t *testing.T) {
		t.Run("Success cases", func(t *testing.T) {
			provider, err := NewProvider(mem.NewProvider(),
				"configurations", "documents", 100)
			require.NoError(t, err)

			doQueryTests(t, provider, true)
		})
		t.Run("Failure: document store query call returns error", func(t *testing.T) {
			errTest := errors.New("queryError")
			mockCoreStore := mock.Store{ErrQuery: errTest}

			provider := Provider{
				documentsStore: &mockCoreStore,
			}

			docs, err := provider.Query(testVaultID, models.Query{Equals: []map[string]string{{}}})
			require.EqualError(t, err, "failed to query underlying store: queryError")
			require.Empty(t, docs)
		})
		t.Run("Failure: first iterator next() call returns error", func(t *testing.T) {
			errTest := errors.New("next error")
			mockCoreStore := mock.Store{
				QueryReturn: &mockIterator{maxTimesNextCanBeCalled: 0, errNext: errTest},
			}

			provider := Provider{
				documentsStore: &mockCoreStore,
			}

			docs, err := provider.Query(testVaultID, models.Query{Equals: []map[string]string{{}}})
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

			provider := Provider{
				documentsStore: &mockCoreStore,
			}

			docs, err := provider.Query(testVaultID, models.Query{Equals: []map[string]string{{}}})
			require.EqualError(t, err, "next error")
			require.Empty(t, docs)
		})
		t.Run("Failure: iterator value() call returns error", func(t *testing.T) {
			errTest := errors.New("value error")
			mockCoreStore := mock.Store{
				QueryReturn: &mockIterator{
					maxTimesNextCanBeCalled: 1,
					errValue:                errTest,
					tagsReturn: []storage.Tag{
						{Name: vaultIDTagName, Value: testVaultID},
					},
				},
			}

			provider := Provider{
				documentsStore: &mockCoreStore,
			}

			docs, err := provider.Query(testVaultID, models.Query{Equals: []map[string]string{{}}})
			require.EqualError(t, err, "value error")
			require.Empty(t, docs)
		})
		t.Run("Failure: support for multiple attribute queries not implemented for CouchDB or in-memory storage",
			func(t *testing.T) {
				memStore, err := mem.NewProvider().OpenStore("documents")
				require.NoError(t, err)

				provider := Provider{
					documentsStore: memStore,
				}

				docs, err := provider.Query(testVaultID, models.Query{Equals: []map[string]string{{}, {}}})
				require.EqualError(t, err, "support for multiple attribute queries not implemented for "+
					"CouchDB or in-memory storage")
				require.Empty(t, docs)
			})
	})
}

func TestEDVStore_Delete(t *testing.T) {
	t.Run("Using MongoDB", func(t *testing.T) {
		doDeleteTest(t, mem.NewProvider())
	})
	t.Run("Using in-memory storage", func(t *testing.T) {
		mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
		require.NoError(t, err)

		pool, mongoDBResource := startMongoDBContainer(t, mongoDBProvider)

		defer func() {
			require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
		}()

		doDeleteTest(t, mongoDBProvider)
	})
}

func doQueryTests(t *testing.T, edvProvider *Provider, skipMultipleAttributeQueries bool) {
	t.Helper()

	testTable := generateQueryTestTable(t, skipMultipleAttributeQueries)

	// For each test, we:
	// 1. Create a fresh (empty) vault.
	// 2. Store the test documents in it.
	// 3. Do the test query.
	// 4. Check if we got the expected results back.
	for _, queryTest := range testTable { //nolint:gocritic // test file
		testFailureExtraInfo := fmt.Sprintf("Scenario: %s", queryTest.testName)

		vaultID, err := edvutils.GenerateEDVCompatibleID()
		require.NoError(t, err)

		err = edvProvider.CreateNewVault(vaultID, &models.DataVaultConfiguration{})
		require.NoError(t, err)

		storeDocuments(t, vaultID, edvProvider, queryTest.storedDocuments, testFailureExtraInfo)

		documents, err := edvProvider.Query(vaultID, queryTest.query)
		require.NoError(t, err)

		expectedDocumentIDs := extractDocumentIDs(queryTest.expectedDocuments)
		actualDocumentIDs := extractDocumentIDs(documents)

		verifyDocumentIDsMatch(t, actualDocumentIDs, expectedDocumentIDs, testFailureExtraInfo)
	}
}

func doDeleteTest(t *testing.T, underlyingProvider storage.Provider) {
	t.Helper()

	provider, err := NewProvider(underlyingProvider,
		"configurations", "documents", 100)
	require.NoError(t, err)

	var encryptedDocument models.EncryptedDocument

	err = json.Unmarshal([]byte(testEncryptedDoc), &encryptedDocument)
	require.NoError(t, err)

	err = provider.Put(testVaultID, encryptedDocument)
	require.NoError(t, err)

	retrievedDocumentBytes, err := provider.Get(testVaultID, encryptedDocument.ID)
	require.NoError(t, err)

	var retrievedEncryptedDocument models.EncryptedDocument

	err = json.Unmarshal(retrievedDocumentBytes, &retrievedEncryptedDocument)
	require.NoError(t, err)

	require.Equal(t, encryptedDocument.ID, retrievedEncryptedDocument.ID)

	err = provider.Delete(testVaultID, testDocID1)
	require.NoError(t, err)

	_, err = provider.Get(testVaultID, encryptedDocument.ID)
	require.EqualError(t, err, storage.ErrDataNotFound.Error())
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

func generateQueryTestTable(t *testing.T, skipMultipleAttributeQueries bool) []queryTestEntry {
	t.Helper()

	testDocuments := generateTestDocuments(t)

	testQueries := generateTestQueries()

	testTable := []queryTestEntry{
		{
			testName:          "Store a single document - query for one attribute pair - one result.",
			query:             testQueries[0],
			storedDocuments:   []models.EncryptedDocument{testDocuments[0]},
			expectedDocuments: []models.EncryptedDocument{testDocuments[0]},
		},
		{
			testName:          "Store has three documents - query for one attribute pair - one result.",
			query:             testQueries[0],
			storedDocuments:   []models.EncryptedDocument{testDocuments[0], testDocuments[1], testDocuments[2]},
			expectedDocuments: []models.EncryptedDocument{testDocuments[0]},
		},
		{
			testName:          "Store has three documents - query for one attribute pair - two results.",
			query:             testQueries[1],
			storedDocuments:   []models.EncryptedDocument{testDocuments[0], testDocuments[1], testDocuments[2]},
			expectedDocuments: []models.EncryptedDocument{testDocuments[0], testDocuments[1]},
		},
		{
			testName: "Store has five documents - query for an attribute name only - three results.",
			query:    testQueries[4],
			storedDocuments: []models.EncryptedDocument{
				testDocuments[0], testDocuments[1], testDocuments[2],
				testDocuments[3], testDocuments[4],
			},
			expectedDocuments: []models.EncryptedDocument{testDocuments[0], testDocuments[1], testDocuments[2]},
		},
		{
			testName: "Store has five documents - query for an attribute name only using " +
				`a "has" query - three results.`,
			query: testQueries[8],
			storedDocuments: []models.EncryptedDocument{
				testDocuments[0], testDocuments[1], testDocuments[2],
				testDocuments[3], testDocuments[4],
			},
			expectedDocuments: []models.EncryptedDocument{testDocuments[2], testDocuments[3], testDocuments[4]},
		},
	}

	if !skipMultipleAttributeQueries {
		testTable = append(testTable,
			queryTestEntry{
				testName:          "Store has three documents - query for two attribute pairs (AND) - one result.",
				query:             testQueries[2],
				storedDocuments:   []models.EncryptedDocument{testDocuments[0], testDocuments[1], testDocuments[2]},
				expectedDocuments: []models.EncryptedDocument{testDocuments[1]},
			},
			queryTestEntry{
				testName: "Store has five documents - query for an attribute name AND another attribute pair" +
					" - two results.",
				query: testQueries[3],
				storedDocuments: []models.EncryptedDocument{
					testDocuments[0], testDocuments[1], testDocuments[2],
					testDocuments[3], testDocuments[4],
				},
				expectedDocuments: []models.EncryptedDocument{testDocuments[3], testDocuments[4]},
			},
			queryTestEntry{
				testName: "Store five documents - query for an attribute name OR a different attribute name" +
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
			queryTestEntry{
				testName: "Store five documents - query for an attribute name OR a different attribute pair" +
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
			queryTestEntry{
				testName: "Store five documents - query for a first attribute pair AND a second attribute pair" +
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
			})
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

	testQuery9 := models.Query{
		Has: "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
	}

	return []models.Query{
		testQuery1, testQuery2, testQuery3, testQuery4, testQuery5,
		testQuery6, testQuery7, testQuery8, testQuery9,
	}
}

func extractDocumentIDs(documents []models.EncryptedDocument) []string {
	documentIDs := make([]string, len(documents))

	for i, document := range documents {
		documentIDs[i] = document.ID
	}

	return documentIDs
}

func storeDocuments(t *testing.T, vaultID string, provider *Provider,
	documents []models.EncryptedDocument, testFailureExtraInfo string) {
	t.Helper()

	err := provider.Put(vaultID, documents...)
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
