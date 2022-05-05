/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/log/mocklogger"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/edvutils"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	testReferenceID = "testReferenceID"
	testVaultID     = "Sr7yHjomhn1aeaFnxREfRN"
	testInvalidURI  = "invalidURI"
	testValidURI    = "did:example:123456789"
	testKEKType     = "AesKeyWrappingKey2019"
	testHMACType    = "Sha256HmacKey2019"

	testDataVaultConfiguration = `{
  "sequence": 0,
  "controller": "` + testValidURI + `",
  "referenceId": "` + testReferenceID + `",
  "kek": {
    "id": "https://example.com/kms/12345",
    "type": "AesKeyWrappingKey2019"
  },
  "hmac": {
    "id": "https://example.com/kms/67891",
    "type": "Sha256HmacKey2019"
  }
}`

	testHasQuery = `{
  "has": "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ"
}`

	testHasQueryWithReturnFullDocuments = `{
  "returnFullDocuments": true,
  "has": "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ"
}`

	testDocID               = "VJYHHJx4C8J9Fsgz7rZqSp"
	testDocID2              = "AJYHHJx4C8J9Fsgz7rZqSp"
	testDocID3              = "CJYHHJx4C8J9Fsgz7rZqSp"
	mockDocID1              = "docID1"
	mockDocID2              = "docID2"
	encryptedAttributeName1 = "attributeName1"
	encryptedAttributeName2 = "attributeName2"
	encryptedAttributeName3 = "attributeName3"

	testJWE1 = `{"protected":"eyJlbmMiOiJDMjBQIn0","recipients":[{"header":{"alg":"A256KW","kid":"https://exam` +
		`ple.com/kms/z7BgF536GaR"},"encrypted_key":"OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"}],` +
		`"iv":"i8Nins2vTI3PlrYW","ciphertext":"Cb-963UCXblINT8F6MDHzMJN9EAhK3I","tag":"pfZO0JulJcrc3trOZy8rjA"}`
	testJWE2 = `{"protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","encrypted_k` +
		`ey":"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKA` +
		`q7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfw` +
		`X7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWX` +
		`RcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg","iv":"48V1_ALb6US04U3b","ciphertext":"5eym8TW_c8SuK0ltJ` +
		`3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A","tag":"XFBoMYUZodetZdvTiFvSkQ"}`

	testIndexedAttributeCollections1 = `[{"sequence":0,"hmac":{"id":"","type":""},"attributes":[{"name":"` +
		encryptedAttributeName1 + `","value":"testVal","unique":true},{"name":"` + encryptedAttributeName2 +
		`","value":"testVal","unique":true}]}]`
	testIndexedAttributeCollections2 = `[{"sequence":0,"hmac":{"id":"","type":""},"attributes":[{"name":"` +
		encryptedAttributeName2 + `","value":"testVal","unique":true},{"name":"` + encryptedAttributeName3 +
		`","value":"testVal","unique":true}]}]`

	testEncryptedDocument = `{"id":"` + testDocID + `","sequence":0,"indexed":null,` +
		`"jwe":` + testJWE1 + `}`
	testEncryptedDocument2 = `{"id":"` + testDocID2 + `","sequence":0,"indexed":null,` +
		`"jwe":` + testJWE2 + `}`

	// All of the characters in the ID below are NOT in the base58 alphabet, so this ID is not base58 encoded
	testEncryptedDocumentWithNonBase58ID = `{
  "id": "0OIl"
}`

	testEncryptedDocumentWithIDThatWasNot128BitsBeforeBase58Encoding = `{
  "id": "2CHi6"
}`

	testEncryptedDocumentWithNoJWE = `{
	"id": "BJYHHJx4C8J9Fsgz7rZqSa"
}`

	mongoDBConnString    = "mongodb://localhost:27017"
	dockerMongoDBImage   = "mongo"
	dockerMongoDBTagV400 = "4.0.0"
)

var (
	mockLoggerProvider       = mocklogger.Provider{MockLogger: &mocklogger.MockLogger{}} //nolint: gochecknoglobals
	errFailingResponseWriter = errors.New("failingResponseWriter always fails")
	errFailingReadCloser     = errors.New("failingReadCloser always fails")
)

type failingResponseWriter struct {
}

func (f failingResponseWriter) Header() http.Header {
	return nil
}

func (f failingResponseWriter) Write([]byte) (int, error) {
	return 0, errFailingResponseWriter
}

func (f failingResponseWriter) WriteHeader(int) {
}

type failingReadCloser struct{}

func (m failingReadCloser) Read([]byte) (n int, err error) {
	return 0, errFailingReadCloser
}

func (m failingReadCloser) Close() error {
	return nil
}

type mockContext struct {
	valueToReturnWhenValueMethodCalled interface{}
}

func (m mockContext) Deadline() (deadline time.Time, ok bool) {
	panic("implement me")
}

func (m mockContext) Done() <-chan struct{} {
	panic("implement me")
}

func (m mockContext) Err() error {
	panic("implement me")
}

func (m mockContext) Value(interface{}) interface{} {
	return m.valueToReturnWhenValueMethodCalled
}

type mockProvider struct {
	errStoreDelete                   error
	errOpenStore                     error
	numTimesOpenStoreCalled          int
	numTimesOpenStoreCalledBeforeErr int
	errSetStoreConfig                error
	errGetStoreConfig                error
	errStoreBatch                    error
}

func (m *mockProvider) OpenStore(string) (storage.Store, error) {
	if m.numTimesOpenStoreCalled == m.numTimesOpenStoreCalledBeforeErr {
		return nil, m.errOpenStore
	}

	m.numTimesOpenStoreCalled++

	encryptedDoc1 := models.EncryptedDocument{ID: mockDocID1}

	encryptedDoc1Bytes, err := json.Marshal(encryptedDoc1)
	if err != nil {
		return nil, err
	}

	return &mock.Store{
		ErrDelete:   m.errStoreDelete,
		ErrBatch:    m.errStoreBatch,
		QueryReturn: &mock.Iterator{ValueReturn: encryptedDoc1Bytes},
	}, nil
}

func (m *mockProvider) SetStoreConfig(string, storage.StoreConfiguration) error {
	return m.errSetStoreConfig
}

func (m *mockProvider) GetStoreConfig(string) (storage.StoreConfiguration, error) {
	return storage.StoreConfiguration{}, m.errGetStoreConfig
}

func (m *mockProvider) GetOpenStores() []storage.Store {
	panic("implement me")
}

func (m *mockProvider) Close() error {
	panic("implement me")
}

func TestMain(m *testing.M) {
	log.Initialize(&mockLoggerProvider)

	log.SetLevel(logModuleName, log.DEBUG)

	os.Exit(m.Run())
}

func TestNew(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		o := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})
		require.NotNil(t, o)
	})
}

func TestCreateDataVault(t *testing.T) {
	testValidateIncomingDataVaultConfiguration(t)
	t.Run("Success: without prefix", func(t *testing.T) {
		op := New(&Config{
			Provider: edvprovider.NewProvider(mem.NewProvider(), 100), AuthEnable: true,
			AuthService: &mockAuthService{createValue: []byte("authData")},
		})

		_, resp := createDataVaultExpectSuccess(t, op, "")

		require.Equal(t, string(resp), "authData")
	})
	t.Run("error from creating auth payload", func(t *testing.T) {
		op := New(&Config{
			Provider: edvprovider.NewProvider(mem.NewProvider(), 100), AuthEnable: true,
			AuthService: &mockAuthService{createErr: fmt.Errorf("failed to create auth")},
		})

		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(testDataVaultConfiguration)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost, "")
		createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Contains(t, rr.Body.String(), "failed to create auth")
	})
	t.Run("Invalid Data Vault Configuration JSON", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		createVaultHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost, "")

		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		createVaultHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.InvalidVaultConfig, "unexpected end of JSON input"),
			rr.Body.String())
	})
	t.Run("Response writer fails while writing request read error", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		op.createDataVaultHandler(failingResponseWriter{}, &http.Request{Body: failingReadCloser{}})

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(messages.CreateVaultFailReadRequestBody+messages.FailWriteResponse,
				errFailingReadCloser, errFailingResponseWriter))
	})
	t.Run("Fail to store data vault configuration", func(t *testing.T) {
		errTest := errors.New("put error")

		mockProvider := mock.Provider{OpenStoreReturn: &mock.Store{ErrPut: errTest, QueryReturn: &mock.Iterator{}}}

		edvProvider := edvprovider.NewProvider(&mockProvider, 100)

		op := New(&Config{Provider: edvProvider})

		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(testDataVaultConfiguration)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost, "")
		createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, "Failed to create a new data vault: failed to store data vault configuration: "+
			"put error.", rr.Body.String())
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("Fail to open store for vault", func(t *testing.T) {
		mockProv := mockProvider{
			errOpenStore: errors.New("open store failure"),
		}

		edvProvider := edvprovider.NewProvider(&mockProv, 100)

		op := New(&Config{Provider: edvProvider})

		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(testDataVaultConfiguration)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost, "")
		createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, "Failed to create a new data vault: "+
			"failed to open store for vault: open store failure.", rr.Body.String())
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func testValidateIncomingDataVaultConfiguration(t *testing.T) {
	t.Helper()

	t.Run("Invalid incoming data vault configuration - missing controller", func(t *testing.T) {
		config := getDataVaultConfig("", testValidURI, testKEKType, testValidURI,
			testHMACType, []string{}, []string{})
		createDataVaultExpectError(t, config, fmt.Sprintf(messages.InvalidVaultConfig, messages.BlankController))
	})
	t.Run("Invalid incoming data vault configuration - missing KEK ID", func(t *testing.T) {
		config := getDataVaultConfig(testValidURI, "", testKEKType, testValidURI,
			testHMACType, []string{}, []string{})
		createDataVaultExpectError(t, config, fmt.Sprintf(messages.InvalidVaultConfig, messages.BlankKEKID))
	})
	t.Run("Invalid incoming data vault configuration - missing KEK type", func(t *testing.T) {
		config := getDataVaultConfig(testValidURI, testValidURI, "", testValidURI,
			testHMACType, []string{}, []string{})
		createDataVaultExpectError(t, config, fmt.Sprintf(messages.InvalidVaultConfig, messages.BlankKEKType))
	})
	t.Run("Invalid incoming data vault configuration - missing HMAC ID", func(t *testing.T) {
		config := getDataVaultConfig(testValidURI, testValidURI, testKEKType, "",
			testHMACType, []string{}, []string{})
		createDataVaultExpectError(t, config, fmt.Sprintf(messages.InvalidVaultConfig, messages.BlankHMACID))
	})
	t.Run("Invalid incoming data vault configuration - missing HMAC type", func(t *testing.T) {
		config := getDataVaultConfig(testValidURI, testValidURI, testKEKType, testValidURI,
			"", []string{}, []string{})
		createDataVaultExpectError(t, config, fmt.Sprintf(messages.InvalidVaultConfig, messages.BlankHMACType))
	})
	t.Run("Invalid incoming data vault configuration - controller is an invalid URI", func(t *testing.T) {
		config := getDataVaultConfig(testInvalidURI, testValidURI, testKEKType, testValidURI,
			testHMACType, []string{}, []string{})
		createDataVaultExpectError(t, config,
			fmt.Sprintf(messages.InvalidVaultConfig, fmt.Errorf(messages.InvalidControllerString,
				fmt.Errorf(messages.InvalidURI, testInvalidURI))))
	})
	t.Run("Invalid incoming data vault configuration - KEK id is an invalid URI", func(t *testing.T) {
		config := getDataVaultConfig(testValidURI, testInvalidURI, testKEKType, testValidURI,
			testHMACType, []string{}, []string{})
		createDataVaultExpectError(t, config,
			fmt.Sprintf(messages.InvalidVaultConfig, fmt.Errorf(messages.InvalidKEKIDString,
				fmt.Errorf(messages.InvalidURI, testInvalidURI))))
	})
	t.Run("Invalid incoming data vault configuration - invoker contains invalid URIs", func(t *testing.T) {
		config := getDataVaultConfig(testValidURI, testValidURI, testKEKType, testValidURI,
			testHMACType, []string{}, []string{testInvalidURI})
		createDataVaultExpectError(t, config,
			fmt.Sprintf(messages.InvalidVaultConfig, fmt.Errorf(messages.InvalidInvokerStringArray,
				fmt.Errorf(messages.InvalidURI, testInvalidURI))))
	})
	t.Run("Invalid incoming data vault configuration - delegator contains invalid URIs", func(t *testing.T) {
		config := getDataVaultConfig(testValidURI, testValidURI, testKEKType, testValidURI,
			testHMACType, []string{testInvalidURI}, []string{})
		createDataVaultExpectError(t, config,
			fmt.Sprintf(messages.InvalidVaultConfig, fmt.Errorf(messages.InvalidDelegatorStringArray,
				fmt.Errorf(messages.InvalidURI, testInvalidURI))))
	})
}

func TestQueryVault(t *testing.T) {
	mongoDBProvider, err := mongodb.NewProvider(mongoDBConnString)
	require.NoError(t, err)

	pool, mongoDBResource := startMongoDBContainer(t, mongoDBProvider)

	defer func() {
		require.NoError(t, pool.Purge(mongoDBResource), "failed to purge MongoDB resource")
	}()

	t.Run("Success, returning only document locations", func(t *testing.T) {
		t.Run("Various single and multiple attribute queries", func(t *testing.T) {
			type queryTestEntry struct {
				testName          string
				query             interface{}
				storedDocuments   [][]byte
				expectedDocuments [][]byte
			}

			testDocument1 := []byte(`{
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

			testDocument2 := []byte(`{
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

			testDocument3 := []byte(`{
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

			testDocument4 := []byte(`{
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

			testDocument5 := []byte(`{
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

			testQuery1 := models.Query{
				ReturnFullDocuments: false,
				Equals: []map[string]string{
					{
						"AUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
					},
				},
			}

			testQuery2 := models.Query{
				ReturnFullDocuments: false,
				Equals: []map[string]string{
					{
						"B2UQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "BV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
					},
				},
			}

			testQuery3 := models.Query{
				ReturnFullDocuments: false,
				Equals: []map[string]string{
					{
						"BUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ":  "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
						"B2UQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "BV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
					},
				},
			}

			testQuery4 := models.Query{
				ReturnFullDocuments: false,
				Equals: []map[string]string{
					{
						"BUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro",
						"CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "",
					},
				},
			}

			testQuery5 := models.Query{
				ReturnFullDocuments: false,
				Equals: []map[string]string{
					{
						"B2UQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ": "",
					},
				},
			}

			testTable := []queryTestEntry{
				{
					testName:          "Store a single document - query for one attribute pair - one result.",
					query:             testQuery1,
					storedDocuments:   [][]byte{testDocument1},
					expectedDocuments: [][]byte{testDocument1},
				},
				{
					testName:          "Store three documents - query for one attribute pair - one result.",
					query:             testQuery1,
					storedDocuments:   [][]byte{testDocument1, testDocument2, testDocument3},
					expectedDocuments: [][]byte{testDocument1},
				},
				{
					testName:          "Store three documents - query for one attribute pair - two results.",
					query:             testQuery2,
					storedDocuments:   [][]byte{testDocument1, testDocument2, testDocument3},
					expectedDocuments: [][]byte{testDocument1, testDocument2},
				},
				{
					testName:          "Store three documents - query for two attribute pairs (AND) - one result.",
					query:             testQuery3,
					storedDocuments:   [][]byte{testDocument1, testDocument2, testDocument3},
					expectedDocuments: [][]byte{testDocument2},
				},
				{
					testName: "Store five documents - query for an attribute name AND another attribute pair" +
						" - two results.",
					query: testQuery4,
					storedDocuments: [][]byte{
						testDocument1, testDocument2, testDocument3, testDocument4,
						testDocument5,
					},
					expectedDocuments: [][]byte{testDocument4, testDocument5},
				},
				{
					testName: "Store five documents - query for an attribute name only - three results.",
					query:    testQuery5,
					storedDocuments: [][]byte{
						testDocument1, testDocument2, testDocument3, testDocument4,
						testDocument5,
					},
					expectedDocuments: [][]byte{testDocument1, testDocument2, testDocument3},
				},
			}

			edvProvider := edvprovider.NewProvider(mongoDBProvider, 100)

			op := New(&Config{Provider: edvProvider, UsingMongoDB: true})

			// For each test, we:
			// 1. Create a fresh (empty) vault.
			// 2. Store the test documents in it.
			// 3. Do the test query.
			// 4. Check if we got the expected results back.
			for _, queryTest := range testTable {
				testFailureExtraInfo := fmt.Sprintf("Scenario: %s", queryTest.testName)

				vaultID, _ := createDataVaultExpectSuccess(t, op, testFailureExtraInfo)

				storeDocuments(t, op, vaultID, queryTest.storedDocuments, testFailureExtraInfo)

				queryBytes, err := json.Marshal(queryTest.query)
				require.NoError(t, err, testFailureExtraInfo)

				req, err := http.NewRequest("POST", "", bytes.NewBuffer(queryBytes))
				require.NoError(t, err, testFailureExtraInfo)

				urlVars := make(map[string]string)
				urlVars[vaultIDPathVariable] = vaultID

				req = mux.SetURLVars(req, urlVars)

				rr := httptest.NewRecorder()

				queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost,
					testFailureExtraInfo)
				queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

				expectedDocumentLocations := generateExpectedDocumentLocations(t, vaultID,
					queryTest.expectedDocuments)

				var actualDocumentLocations []string

				err = json.Unmarshal(rr.Body.Bytes(), &actualDocumentLocations)
				require.NoError(t, err, testFailureExtraInfo)

				verifyActualDocumentLocationsMatchExpected(t, actualDocumentLocations, expectedDocumentLocations,
					testFailureExtraInfo)

				require.Equal(t, http.StatusOK, rr.Code)
			}
		})
		t.Run(`"has" query`, func(t *testing.T) {
			provider := mem.NewProvider()

			edvProvider := edvprovider.NewProvider(provider, 100)

			op := New(&Config{Provider: edvProvider})

			vaultID, _ := createDataVaultExpectSuccess(t, op, "")

			storeTestDataForQueryTests(t, vaultID, provider,
				"SomeArbitraryValue1",
				"SomeArbitraryValue2")

			req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testHasQuery)))
			require.NoError(t, err)

			urlVars := make(map[string]string)
			urlVars[vaultIDPathVariable] = vaultID

			req = mux.SetURLVars(req, urlVars)

			rr := httptest.NewRecorder()

			queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost, "")
			queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

			expectedResponseOrder1 := `["/encrypted-data-vaults/` + vaultID + `/documents/` +
				`docID1","/encrypted-data-vaults/` + vaultID + `/documents/docID2"]`
			expectedResponseOrder2 := `["/encrypted-data-vaults/` + vaultID + `/documents/` +
				`docID2","/encrypted-data-vaults/` + vaultID + `/documents/docID1"]`

			var gotExpectedResultAnyOrder bool

			if rr.Body.String() == expectedResponseOrder1 || rr.Body.String() == expectedResponseOrder2 {
				gotExpectedResultAnyOrder = true
			}

			require.Truef(t, gotExpectedResultAnyOrder,
				"Got unexpected response. Was expecting %s or %s but got %s instead.",
				expectedResponseOrder1, expectedResponseOrder2, rr.Body.String())
			require.Equal(t, http.StatusOK, rr.Code)
		})
	})
	t.Run("Success, returning full documents", func(t *testing.T) {
		t.Run(`"has" query`, func(t *testing.T) {
			provider := mem.NewProvider()

			edvProvider := edvprovider.NewProvider(provider, 100)

			op := New(&Config{
				Provider: edvProvider,
			})

			vaultID, _ := createDataVaultExpectSuccess(t, op, "")

			storeTestDataForQueryTests(t, vaultID, provider,
				"SomeArbitraryValue1",
				"SomeArbitraryValue2")

			req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testHasQueryWithReturnFullDocuments)))
			require.NoError(t, err)

			urlVars := make(map[string]string)
			urlVars[vaultIDPathVariable] = vaultID

			req = mux.SetURLVars(req, urlVars)

			rr := httptest.NewRecorder()

			queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost, "")
			queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

			docsBytes := rr.Body.Bytes()

			var docs []models.EncryptedDocument

			err = json.Unmarshal(docsBytes, &docs)
			require.NoError(t, err)

			require.Len(t, docs, 2)

			var gotExpectedResultAnyOrder bool

			if docs[0].ID == mockDocID1 {
				if docs[1].ID == mockDocID2 {
					gotExpectedResultAnyOrder = true
				}
			} else if docs[0].ID == mockDocID2 {
				if docs[1].ID == mockDocID1 {
					gotExpectedResultAnyOrder = true
				}
			}

			require.Truef(t, gotExpectedResultAnyOrder,
				"Got unexpected response. Was expecting docID1 and docID2 but got %s and %s instead.",
				docs[0].ID, docs[1].ID)

			require.Equal(t, http.StatusOK, rr.Code)
		})
	})
	t.Run("Error: multiple-attribute queries not supported for in-memory or CouchDB", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		storeSampleConfigExpectSuccess(t, op)

		query := models.Query{Equals: []map[string]string{{"name1": "value1", "name2": "value2"}}}

		queryBytes, err := json.Marshal(query)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer(queryBytes))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost, "")
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(messages.InvalidQuery, testVaultID,
			"multiple-attribute queries not supported when using in-memory or CouchDB storage"), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Error: multiple subfilters (OR operations) not implemented", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		storeSampleConfigExpectSuccess(t, op)

		query := models.Query{Equals: []map[string]string{{"name1": "value1"}, {"name2": "value2"}}}

		queryBytes, err := json.Marshal(query)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer(queryBytes))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost, "")
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(messages.InvalidQuery, testVaultID,
			"support for multiple subfilters (OR operations) not implemented"), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run(`Error: empty query`, func(t *testing.T) {
		op := New(&Config{
			Provider: edvprovider.NewProvider(mem.NewProvider(), 100),
		})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte("{}")))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost, "")
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, "Received invalid query for data vault "+vaultID+": "+
			`query cannot be empty.`, rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Error: vault not found", func(t *testing.T) {
		mockProv := &mock.Provider{
			ErrGetStoreConfig: storage.ErrStoreNotFound,
			OpenStoreReturn:   &mock.Store{QueryReturn: &mock.Iterator{}},
		}

		edvProvider := edvprovider.NewProvider(mockProv, 100)

		op := New(&Config{Provider: edvProvider})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		query := models.Query{Equals: []map[string]string{{"name": "value"}}}

		queryBytes, err := json.Marshal(query)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer(queryBytes))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost, "")
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(messages.QueryFailure, vaultID, messages.ErrVaultNotFound), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Error: fail to open store", func(t *testing.T) {
		testErr := errors.New("fail to open store")

		provider := &mockProvider{numTimesOpenStoreCalledBeforeErr: 1, errOpenStore: testErr}
		op := New(&Config{Provider: edvprovider.NewProvider(provider, 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		query := models.Query{Equals: []map[string]string{{"name": "value"}}}

		queryBytes, err := json.Marshal(query)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer(queryBytes))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost, "")
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(messages.QueryFailure, vaultID, testErr), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Unable to unmarshal query JSON", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		storeSampleConfigExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost, "")
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(messages.InvalidQuery, testVaultID,
			"unexpected end of JSON input"), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Fail to write response when unable to unmarshal query JSON", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		req, err := http.NewRequest("POST", "", failingReadCloser{})
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		op.queryVaultHandler(failingResponseWriter{}, req)

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(messages.QueryFailReadRequestBody+messages.FailWriteResponse,
				testVaultID, errFailingReadCloser, errFailingResponseWriter))
	})
	t.Run("Fail to unescape path var", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		query := models.Query{Equals: []map[string]string{{"name": "value"}}}

		queryBytes, err := json.Marshal(query)
		require.NoError(t, err)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer(queryBytes))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = "%"

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost, "")
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t,
			fmt.Sprintf(messages.UnescapeFailure, vaultIDPathVariable, `invalid URL escape "%"`),
			rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Fail to write response when matching documents are found (only IDs returned)", func(t *testing.T) {
		encryptedDoc1 := models.EncryptedDocument{ID: mockDocID1}
		encryptedDoc2 := models.EncryptedDocument{ID: mockDocID2}

		writeQueryResponse(failingResponseWriter{}, []models.EncryptedDocument{encryptedDoc1, encryptedDoc2},
			testVaultID, nil, false, "TestHost")

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(messages.QuerySuccess+messages.FailWriteResponse, testVaultID, errFailingResponseWriter))
	})
	t.Run("Fail to write response when matching documents are found (full docs returned)", func(t *testing.T) {
		encryptedDoc1 := models.EncryptedDocument{ID: mockDocID1}
		encryptedDoc2 := models.EncryptedDocument{ID: mockDocID2}

		writeQueryResponse(failingResponseWriter{}, []models.EncryptedDocument{encryptedDoc1, encryptedDoc2},
			testVaultID, nil, true, "TestHost")

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(messages.QuerySuccess+messages.FailWriteResponse, testVaultID, errFailingResponseWriter))
	})
}

func verifyActualDocumentLocationsMatchExpected(t *testing.T, actualLocations, expectedLocations []string,
	testFailureExtraInfo string) {
	t.Helper()

	require.Equal(t, len(expectedLocations), len(actualLocations),
		"Unexpected number of locations received. Expected: %d. Actual: %d. %s",
		len(expectedLocations), len(actualLocations), testFailureExtraInfo)

	ensureNoDuplicates(t, actualLocations,
		fmt.Sprintf("%s. %s", "server returned duplicate locations", testFailureExtraInfo))
	ensureNoDuplicates(t, expectedLocations,
		fmt.Sprintf("%s. %s", "expected locations cannot have duplicates", testFailureExtraInfo))

	checklist := make([]bool, len(expectedLocations))

	for i, expectedLocation := range expectedLocations {
		for _, actualLocation := range actualLocations {
			if actualLocation == expectedLocation {
				checklist[i] = true
				break
			}
		}
	}

	for i, locationReceived := range checklist {
		require.True(t, locationReceived,
			"Document location %s (and possibly others) was expected but was not returned by the "+
				"server. %s",
			expectedLocations[i], testFailureExtraInfo)
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

func generateExpectedDocumentLocations(t *testing.T, vaultID string, expectedDocuments [][]byte) []string {
	t.Helper()

	expectedDocumentLocations := make([]string, len(expectedDocuments))

	for i, expectedDocument := range expectedDocuments {
		documentID := getIDFromDocument(t, expectedDocument)

		expectedDocumentLocations[i] = fmt.Sprintf(`/encrypted-data-vaults/%s/documents/%s`, vaultID, documentID)
	}

	return expectedDocumentLocations
}

func getIDFromDocument(t *testing.T, document []byte) string {
	t.Helper()

	var encryptedDocument models.EncryptedDocument

	err := json.Unmarshal(document, &encryptedDocument)
	require.NoError(t, err)

	return encryptedDocument.ID
}

func TestCreateDocument(t *testing.T) {
	t.Run("Success: without prefix", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument, vaultID)
		storeEncryptedDocumentExpectSuccess(t, op, testDocID2, testEncryptedDocument2, vaultID)
	})
	t.Run("Invalid encrypted document JSON", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		storeSampleConfigExpectSuccess(t, op)

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost, "")

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.InvalidDocumentForDocCreation, testVaultID, "unexpected end of JSON input"),
			rr.Body.String())
	})
	t.Run("Document ID is not base58 encoded", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testEncryptedDocumentWithNonBase58ID)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost, "")

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.InvalidDocumentForDocCreation, vaultID, messages.ErrNotBase58Encoded),
			rr.Body.String())
	})
	t.Run("Document ID was not 128 bits long before being base58 encoded", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		req, err := http.NewRequest("POST", "",
			bytes.NewBuffer([]byte(testEncryptedDocumentWithIDThatWasNot128BitsBeforeBase58Encoding)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost, "")

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.InvalidDocumentForDocCreation, vaultID, messages.ErrNot128BitValue),
			rr.Body.String())
	})
	t.Run("Empty JWE", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		req, err := http.NewRequest("POST", "",
			bytes.NewBuffer([]byte(testEncryptedDocumentWithNoJWE)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost, "")

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.InvalidDocumentForDocCreation, vaultID,
			fmt.Sprintf(messages.InvalidRawJWE, messages.BlankJWE)), rr.Body.String())
	})
	t.Run("Duplicate document", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument, vaultID)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testEncryptedDocument)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost, "")
		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusConflict, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.CreateDocumentFailure, vaultID, messages.ErrDuplicateDocument),
			rr.Body.String())
	})
	t.Run("Response writer fails while writing duplicate document error", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument, vaultID)

		op.createDocument(&failingResponseWriter{}, []byte(testEncryptedDocument), "", vaultID)

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(messages.CreateDocumentFailure+messages.FailWriteResponse,
				vaultID, messages.ErrDuplicateDocument, errFailingResponseWriter))
	})
	t.Run("Vault does not exist", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		storeSampleConfigExpectSuccess(t, op)

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost, "")

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testEncryptedDocument)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.CreateDocumentFailure, testVaultID, messages.ErrVaultNotFound),
			rr.Body.String())
	})
	t.Run("Unable to escape vault ID path variable", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testEncryptedDocument)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = "%"

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost, "")

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, "", rr.Header().Get("Location"))
		require.Equal(t,
			fmt.Sprintf(messages.UnescapeFailure, vaultIDPathVariable, `invalid URL escape "%"`),
			rr.Body.String())
	})
	t.Run("Response writer fails while writing unescape Vault ID error", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		createDataVaultExpectSuccess(t, op, "")

		request := http.Request{}

		op.createDocumentHandler(failingResponseWriter{},
			request.WithContext(mockContext{valueToReturnWhenValueMethodCalled: getMapWithVaultIDThatCannotBeEscaped()}))

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(messages.UnescapeFailure+messages.FailWriteResponse, vaultIDPathVariable,
				errFailingResponseWriter, errFailingResponseWriter))
	})
	t.Run("Response writer fails while writing request read error", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		storeSampleConfigExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "", failingReadCloser{})
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		op.createDocumentHandler(failingResponseWriter{}, req)

		require.Contains(t,
			mockLoggerProvider.MockLogger.AllLogContents, fmt.Sprintf(
				messages.CreateDocumentFailReadRequestBody+messages.FailWriteResponse,
				testVaultID, errFailingReadCloser, errFailingResponseWriter))
	})
}

func TestReadDocument(t *testing.T) {
	t.Run("Success: without prefix", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		readDocumentExpectSuccess(t, op)
	})
	t.Run("Vault does not exist", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		storeSampleConfigExpectSuccess(t, op)

		readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet, "")

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID
		urlVars[docIDPathVariable] = testDocID

		req = mux.SetURLVars(req, urlVars)

		readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusNotFound, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.ReadDocumentFailure, testDocID, testVaultID, messages.ErrVaultNotFound),
			rr.Body.String())
	})
	t.Run("Document does not exist", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet, "")

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID
		urlVars[docIDPathVariable] = testDocID

		req = mux.SetURLVars(req, urlVars)

		readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusNotFound, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.ReadDocumentFailure,
			testDocID, vaultID, messages.ErrDocumentNotFound), rr.Body.String())
	})
	t.Run("Unable to escape vault ID path variable", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument, vaultID)

		readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet, "")

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = "%"
		urlVars[docIDPathVariable] = testDocID

		req = mux.SetURLVars(req, urlVars)

		readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		require.Equal(t, fmt.Sprintf(messages.UnescapeFailure, vaultIDPathVariable, `invalid URL escape "%"`),
			rr.Body.String())
	})
	t.Run("Unable to escape document ID path variable", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument, vaultID)

		readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet, "")

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID
		urlVars[docIDPathVariable] = "%"

		req = mux.SetURLVars(req, urlVars)

		readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)

		require.Equal(t, fmt.Sprintf(messages.UnescapeFailure, docIDPathVariable, `invalid URL escape "%"`),
			rr.Body.String())
	})
	t.Run("Response writer fails while writing unescape vault ID error", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument, vaultID)

		request := http.Request{}

		op.readDocumentHandler(failingResponseWriter{},
			request.WithContext(mockContext{valueToReturnWhenValueMethodCalled: getMapWithVaultIDThatCannotBeEscaped()}))

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(messages.UnescapeFailure+messages.FailWriteResponse,
				vaultIDPathVariable, errFailingResponseWriter, errFailingResponseWriter))
	})
	t.Run("Response writer fails while writing unescape document ID error", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument, vaultID)

		request := http.Request{}

		op.readDocumentHandler(failingResponseWriter{},
			request.WithContext(mockContext{valueToReturnWhenValueMethodCalled: getMapWithDocIDThatCannotBeEscaped()}))

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(messages.UnescapeFailure+messages.FailWriteResponse,
				docIDPathVariable, errFailingResponseWriter, errFailingResponseWriter))
	})
	t.Run("Response writer fails while writing read document error", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID
		urlVars[docIDPathVariable] = testDocID

		req = mux.SetURLVars(req, urlVars)

		op.readDocumentHandler(failingResponseWriter{}, req)

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(messages.ReadDocumentFailure, testDocID, testVaultID, messages.ErrVaultNotFound))
	})
	t.Run("Response writer fails while writing retrieved document", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument, vaultID)

		request := http.Request{}

		op.readDocumentHandler(failingResponseWriter{},
			request.WithContext(mockContext{valueToReturnWhenValueMethodCalled: getMapWithValidVaultIDAndDocID(vaultID)}))

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(messages.ReadDocumentSuccess+messages.FailWriteResponse,
				testDocID, vaultID, errFailingResponseWriter))
	})
}

func Test_writeReadAllDocumentsSuccess(t *testing.T) {
	t.Run("Fail to marshal all documents", func(t *testing.T) {
		rr := httptest.NewRecorder()

		writeReadAllDocumentsSuccess(rr, []json.RawMessage{[]byte("NotValid")}, testVaultID)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.FailToMarshalAllDocuments, testVaultID, "json: error calling "+
			"MarshalJSON for type json.RawMessage: invalid character 'N' looking for beginning of value"),
			rr.Body.String())
	})
}

func TestUpdateDocument(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		originalEncryptedDoc := `{"id":"` + testDocID + `","sequence":0,"indexed":` + testIndexedAttributeCollections1 +
			`,` + `"jwe":` + testJWE1 + `}`
		storeEncryptedDocumentExpectSuccess(t, op, testDocID, originalEncryptedDoc, vaultID)

		newEncryptedDoc := `{"id":"` + testDocID + `","sequence":0,"indexed":` + testIndexedAttributeCollections2 +
			`,` + `"jwe":` + testJWE1 + `}`
		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(newEncryptedDoc)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID
		urlVars[docIDPathVariable] = testDocID

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler := getHandler(t, op, updateDocumentEndpoint, http.MethodPost, "")

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		getDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet, "")
		getDocumentEndpointHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, newEncryptedDoc, rr.Body.String())
	})
	t.Run("Failure - error while unmarshalling incoming document", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte("notAnEncryptedDocument")))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID
		urlVars[docIDPathVariable] = testDocID

		req = mux.SetURLVars(req, urlVars)
		createDocumentEndpointHandler := getHandler(t, op, updateDocumentEndpoint, http.MethodPost, "")

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "Received a request to update document "+testDocID+
			" in vault "+vaultID+", but the document is invalid:")
	})
	t.Run("Failure - IDs from path variable and incoming document don't match", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		updateDocumentExpectError(t, op, []byte(testEncryptedDocument), vaultID, testDocID2,
			fmt.Sprintf(messages.InvalidDocumentForDocUpdate, testDocID2, vaultID, messages.MismatchedDocIDs),
			http.StatusBadRequest)
	})
	t.Run("Failure - invalid incoming document", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		testInvalidDoc := models.EncryptedDocument{ID: testDocID, JWE: nil}

		testValidDocBytes, err := json.Marshal(testInvalidDoc)
		require.NoError(t, err)

		updateDocumentExpectError(t, op, testValidDocBytes, vaultID, testDocID,
			fmt.Sprintf(messages.InvalidDocumentForDocUpdate, testDocID, vaultID,
				fmt.Sprintf(messages.InvalidRawJWE, messages.BlankJWEAlg)), http.StatusBadRequest)
	})
	t.Run("Failure - vault not found", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})
		updateDocumentExpectError(t, op, []byte(testEncryptedDocument), testVaultID, testDocID,
			fmt.Sprintf(messages.UpdateDocumentFailure, testDocID, testVaultID, messages.ErrVaultNotFound),
			http.StatusNotFound)
	})
	t.Run("Failure - other error while opening store", func(t *testing.T) {
		provider := &mockProvider{
			numTimesOpenStoreCalledBeforeErr: 1,
			errOpenStore:                     errors.New("test error"),
		}

		op := New(&Config{Provider: edvprovider.NewProvider(provider, 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		newEncryptedDoc := `{"id":"` + testDocID + `","sequence":0,"indexed":` + testIndexedAttributeCollections2 +
			`,` + `"jwe":` + testJWE1 + `}`

		updateDocumentExpectError(t, op, []byte(newEncryptedDoc), vaultID, testDocID,
			fmt.Sprintf(messages.UpdateDocumentFailure, testDocID, vaultID, "test error"), http.StatusBadRequest)
	})
	t.Run("Failure - document to be updated does not exist", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		newEncryptedDoc := `{"id":"` + testDocID + `","sequence":0,"indexed":` + testIndexedAttributeCollections2 +
			`,` + `"jwe":` + testJWE1 + `}`

		updateDocumentExpectError(t, op, []byte(newEncryptedDoc), vaultID, testDocID,
			fmt.Sprintf(messages.UpdateDocumentFailure, testDocID, vaultID, messages.ErrDocumentNotFound),
			http.StatusNotFound)
	})
	t.Run("Response writer fails while writing request read error", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		op.updateDocumentHandler(failingResponseWriter{}, &http.Request{Body: failingReadCloser{}})

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents, errFailingReadCloser.Error())
		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents, errFailingResponseWriter.Error())
		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents, "Failed to read request body:")
	})
	t.Run("Response writer fails while writing vault not found error", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		op.updateDocument(&failingResponseWriter{}, []byte(testEncryptedDocument), testDocID, testVaultID)
		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents, "Failed to update document "+
			testDocID+" in vault "+testVaultID+": specified vault does not exist.")
		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents, errFailingResponseWriter.Error())
	})
}

func TestDeleteDocument(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument, vaultID)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID
		urlVars[docIDPathVariable] = testDocID

		req, err := http.NewRequest("DELETE", "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()
		req = mux.SetURLVars(req, urlVars)

		deleteDocumentEndpointHandler := getHandler(t, op, deleteDocumentEndpoint, http.MethodDelete, "")
		deleteDocumentEndpointHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		req, err = http.NewRequest("GET", "", nil)
		require.NoError(t, err)

		rr = httptest.NewRecorder()
		req = mux.SetURLVars(req, urlVars)

		getDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet, "")
		getDocumentEndpointHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusNotFound, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.ReadDocumentFailure, testDocID, vaultID, messages.ErrDocumentNotFound),
			rr.Body.String())
	})
	t.Run("Failure - unable to escape vault ID path variable", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})
		deleteDocumentExpectError(t, op, "%", testDocID, fmt.Sprintf(messages.UnescapeFailure,
			vaultIDPathVariable, `invalid URL escape "%"`), http.StatusBadRequest)
	})
	t.Run("Failure - unable to escape doc ID path variable", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})
		deleteDocumentExpectError(t, op, testVaultID, "%", fmt.Sprintf(messages.UnescapeFailure,
			docIDPathVariable, `invalid URL escape "%"`), http.StatusBadRequest)
	})
	t.Run("Failure - vault does not exist", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		deleteDocumentExpectError(t, op, testVaultID, testDocID, fmt.Sprintf(messages.DeleteDocumentFailure, testDocID,
			testVaultID, messages.ErrVaultNotFound), http.StatusNotFound)
	})
	t.Run("Failure - other error while opening store", func(t *testing.T) {
		provider := &mockProvider{
			numTimesOpenStoreCalledBeforeErr: 1,
			errOpenStore:                     errors.New("test error"),
		}

		op := New(&Config{Provider: edvprovider.NewProvider(provider, 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		deleteDocumentExpectError(t, op, vaultID, testDocID, fmt.Sprintf(messages.DeleteDocumentFailure, testDocID,
			vaultID, "test error"), http.StatusBadRequest)
	})
	t.Run("Failure - document does not exist", func(t *testing.T) {
		op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		deleteDocumentExpectError(t, op, vaultID, testDocID, fmt.Sprintf(messages.DeleteDocumentFailure, testDocID,
			vaultID, messages.ErrDocumentNotFound), http.StatusNotFound)
	})
	t.Run("Response writer fails while writing delete document failure", func(t *testing.T) {
		writeDeleteDocumentFailure(failingResponseWriter{}, errors.New("test error"), testDocID, testVaultID)

		require.Contains(t, mockLoggerProvider.MockLogger.AllLogContents,
			fmt.Sprintf(messages.DeleteDocumentFailure+messages.FailWriteResponse, testDocID, testVaultID, "test error",
				errFailingResponseWriter))
	})
}

func TestBatch(t *testing.T) {
	upsertNewDoc1 := models.VaultOperation{
		Operation:         models.UpsertDocumentVaultOperation,
		EncryptedDocument: models.EncryptedDocument{ID: testDocID, JWE: []byte(testJWE1)},
	}

	upsertNewDoc2 := models.VaultOperation{
		Operation:         models.UpsertDocumentVaultOperation,
		EncryptedDocument: models.EncryptedDocument{ID: testDocID2, JWE: []byte(testJWE2)},
	}

	upsertExistingDoc1 := models.VaultOperation{
		Operation:         models.UpsertDocumentVaultOperation,
		EncryptedDocument: models.EncryptedDocument{ID: testDocID2, JWE: []byte(testJWE1)},
	}

	deleteExistingDoc1 := models.VaultOperation{
		Operation:  models.DeleteDocumentVaultOperation,
		DocumentID: testDocID,
	}

	deleteNonExistentDoc := models.VaultOperation{
		Operation:  models.DeleteDocumentVaultOperation,
		DocumentID: testDocID3,
	}

	invalidOperation := models.VaultOperation{
		Operation: "invalidOperationName",
	}

	upsertInvalidDoc := models.VaultOperation{
		Operation:         models.UpsertDocumentVaultOperation,
		EncryptedDocument: models.EncryptedDocument{},
	}

	deleteMissingDocumentID := models.VaultOperation{
		Operation: models.DeleteDocumentVaultOperation,
	}

	t.Run("Success: upsert (create), upsert (create), upsert (update)", func(t *testing.T) {
		rr, vaultID := doBatchCall(t, &models.Batch{upsertNewDoc1, upsertNewDoc2, upsertExistingDoc1},
			mem.NewProvider())

		require.Equal(t, `["/encrypted-data-vaults/`+vaultID+`/documents/`+testDocID+`"`+
			`,"/encrypted-data-vaults/`+vaultID+`/documents/`+testDocID2+
			`","/encrypted-data-vaults/`+vaultID+`/documents/`+testDocID2+`"]`,
			rr.Body.String())
		require.Equal(t, http.StatusOK, rr.Code)
	})
	t.Run("Success: upsert (create), upsert (create), delete", func(t *testing.T) {
		rr, vaultID := doBatchCall(t, &models.Batch{upsertNewDoc1, upsertNewDoc2, deleteExistingDoc1},
			mem.NewProvider())

		require.Equal(t, `["/encrypted-data-vaults/`+vaultID+`/documents/`+testDocID+`"`+
			`,"/encrypted-data-vaults/`+vaultID+`/documents/`+testDocID2+`",""]`,
			rr.Body.String())
		require.Equal(t, http.StatusOK, rr.Code)
	})
	t.Run("Success: upsert (create), delete non-existent doc, upsert (create)", func(t *testing.T) {
		rr, vaultID := doBatchCall(t, &models.Batch{upsertNewDoc1, deleteNonExistentDoc, upsertNewDoc2},
			mem.NewProvider())

		require.Equal(t, `["/encrypted-data-vaults/`+vaultID+`/documents/`+testDocID+`","`+
			messages.ErrDocumentNotFound.Error()+`","/encrypted-data-vaults/`+vaultID+`/documents/`+testDocID2+`"]`,
			rr.Body.String())
		require.Equal(t, http.StatusOK, rr.Code)
	})
	t.Run("Failure: upsert (create), upsert (create), invalid operation", func(t *testing.T) {
		rr, _ := doBatchCall(t, &models.Batch{upsertNewDoc1, upsertNewDoc2, invalidOperation},
			mem.NewProvider())

		require.Equal(t, `["validated but not executed","validated but not executed",`+
			`"invalidOperationName is not a valid vault operation"]`,
			rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Failure: upsert (create) with an invalid encrypted document", func(t *testing.T) {
		rr, _ := doBatchCall(t, &models.Batch{upsertInvalidDoc}, mem.NewProvider())

		require.Equal(t, `["document ID must be a base58-encoded value"]`,
			rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Failure: unable to escape vault ID", func(t *testing.T) {
		op := New(&Config{
			Provider:          edvprovider.NewProvider(mem.NewProvider(), 100),
			EnabledExtensions: &EnabledExtensions{Batch: true},
		})

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = "%"

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		batchEndpointHandler := getHandler(t, op, batchEndpoint, http.MethodPost, "")
		batchEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t,
			fmt.Sprintf(messages.UnescapeFailure, vaultIDPathVariable, `invalid URL escape "%"`),
			rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Failure: unable to marshal request", func(t *testing.T) {
		op := New(&Config{
			Provider:          edvprovider.NewProvider(mem.NewProvider(), 100),
			EnabledExtensions: &EnabledExtensions{Batch: true},
		})

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte("Incorrect format")))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		batchEndpointHandler := getHandler(t, op, batchEndpoint, http.MethodPost, "")
		batchEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t,
			fmt.Sprintf(messages.InvalidBatch, testVaultID,
				"invalid character 'I' looking for beginning of value"),
			rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Failure: delete with a missing document ID", func(t *testing.T) {
		rr, _ := doBatchCall(t, &models.Batch{
			deleteMissingDocumentID,
		}, mem.NewProvider())

		require.Equal(t, `["document ID cannot be empty for a delete operation"]`,
			rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Failure: unable to upsert document in underlying storage provider", func(t *testing.T) {
		errTestBatch := errors.New("batch error")
		rr, _ := doBatchCall(t, &models.Batch{upsertNewDoc1}, &mockProvider{
			numTimesOpenStoreCalledBeforeErr: 4,
			errStoreBatch:                    errTestBatch,
		})

		require.Equal(t, `["failed to store encrypted document(s): batch error"]`,
			rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Failure: unable to delete document in underlying storage provider", func(t *testing.T) {
		errTestDelete := errors.New("delete error")
		rr, _ := doBatchCall(t, &models.Batch{deleteExistingDoc1}, &mockProvider{
			numTimesOpenStoreCalledBeforeErr: 4,
			errStoreDelete:                   errTestDelete,
		})

		require.Equal(t, `["`+errTestDelete.Error()+`"]`,
			rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestAddIndex(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := New(&Config{
			Provider: edvprovider.NewProvider(mem.NewProvider(), 100),
		})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		addIndexRequest := `{"operation":"add","attributeNames":["EUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ"]}`

		req, err := http.NewRequest("POST", "",
			bytes.NewBuffer([]byte(addIndexRequest)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID

		req = mux.SetURLVars(req, urlVars)

		indexEndpointHandler := getHandler(t, op, indexEndpoint, http.MethodPost, "")

		indexEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
	})
	t.Run("Unsupported index operation", func(t *testing.T) {
		op := New(&Config{
			Provider: edvprovider.NewProvider(mem.NewProvider(), 100),
		})

		vaultID, _ := createDataVaultExpectSuccess(t, op, "")

		addIndexRequest := `{"operation":"ToastBread"}`

		req, err := http.NewRequest("POST", "",
			bytes.NewBuffer([]byte(addIndexRequest)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID

		req = mux.SetURLVars(req, urlVars)

		indexEndpointHandler := getHandler(t, op, indexEndpoint, http.MethodPost, "")

		indexEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf("Received invalid index operation for data vault %s: "+
			"ToastBread is not a supported index operation.", vaultID), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Fail to unescape path var", func(t *testing.T) {
		op := New(&Config{
			Provider: edvprovider.NewProvider(mem.NewProvider(), 100),
		})

		addIndexRequest := ``

		req, err := http.NewRequest("POST", "",
			bytes.NewBuffer([]byte(addIndexRequest)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = "%"

		req = mux.SetURLVars(req, urlVars)

		indexEndpointHandler := getHandler(t, op, indexEndpoint, http.MethodPost, "")

		indexEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t,
			fmt.Sprintf(messages.UnescapeFailure, vaultIDPathVariable, `invalid URL escape "%"`),
			rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Vault not found", func(t *testing.T) {
		op := New(&Config{
			Provider: edvprovider.NewProvider(mem.NewProvider(), 100),
		})

		addIndexRequest := `{"operation":"add"}`

		req, err := http.NewRequest("POST", "",
			bytes.NewBuffer([]byte(addIndexRequest)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)

		vaultID := "NonExistentVault"
		urlVars[vaultIDPathVariable] = vaultID

		req = mux.SetURLVars(req, urlVars)

		indexEndpointHandler := getHandler(t, op, indexEndpoint, http.MethodPost, "")

		indexEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(messages.FailAddIndexes, vaultID, messages.ErrVaultNotFound), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Other error while checking if vault exists", func(t *testing.T) {
		op := New(&Config{
			Provider: edvprovider.NewProvider(&mockProvider{
				errGetStoreConfig: errors.New("get store config failure"),
			}, 100),
		})

		addIndexRequest := `{"operation":"add"}`

		req, err := http.NewRequest("POST", "",
			bytes.NewBuffer([]byte(addIndexRequest)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)

		urlVars[vaultIDPathVariable] = "VaultID"

		req = mux.SetURLVars(req, urlVars)

		indexEndpointHandler := getHandler(t, op, indexEndpoint, http.MethodPost, "")

		indexEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, "Failed to add indexes to data vault VaultID: unexpected failure while checking if "+
			"vault exists: unexpected error while getting store config: get store config failure.", rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Failed to add indexes", func(t *testing.T) {
		op := New(&Config{
			Provider: edvprovider.NewProvider(&mockProvider{
				errSetStoreConfig: errors.New("set store config failure"),
			}, 100),
		})

		addIndexRequest := `{"operation":"add","attributeNames":["EUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ"]}`

		req, err := http.NewRequest("POST", "",
			bytes.NewBuffer([]byte(addIndexRequest)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)

		urlVars[vaultIDPathVariable] = "VaultID"

		req = mux.SetURLVars(req, urlVars)

		indexEndpointHandler := getHandler(t, op, indexEndpoint, http.MethodPost, "")

		indexEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, "Failed to add indexes to data vault VaultID: set store config failure.",
			rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func doBatchCall(t *testing.T, batch *models.Batch,
	provider storage.Provider) (*httptest.ResponseRecorder, string) {
	t.Helper()

	edvProvider := edvprovider.NewProvider(provider, 100)

	op := New(&Config{
		Provider:          edvProvider,
		EnabledExtensions: &EnabledExtensions{Batch: true},
	})

	vaultID, _ := createDataVaultExpectSuccess(t, op, "")

	batchBytes, err := json.Marshal(batch)
	require.NoError(t, err)

	req, err := http.NewRequest("POST", "", bytes.NewBuffer(batchBytes))
	require.NoError(t, err)

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = vaultID

	req = mux.SetURLVars(req, urlVars)

	rr := httptest.NewRecorder()

	batchEndpointHandler := getHandler(t, op, batchEndpoint, http.MethodPost, "")
	batchEndpointHandler.Handle().ServeHTTP(rr, req)

	return rr, vaultID
}

func updateDocumentExpectError(t *testing.T, op *Operation, requestBody []byte, pathVarVaultID,
	pathVarDocID, expectedErrorString string, expectedErrorCode int) {
	t.Helper()

	req, err := http.NewRequest("POST", "", bytes.NewBuffer(requestBody))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = pathVarVaultID
	urlVars[docIDPathVariable] = pathVarDocID

	req = mux.SetURLVars(req, urlVars)

	createDocumentEndpointHandler := getHandler(t, op, updateDocumentEndpoint, http.MethodPost, "")
	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)
	require.Equal(t, expectedErrorCode, rr.Code)
	require.Equal(t, expectedErrorString, rr.Body.String())
}

func deleteDocumentExpectError(t *testing.T, op *Operation, pathVarVaultID, pathVarDocID, expectedErrorString string,
	expectedErrorCode int) {
	t.Helper()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = pathVarVaultID
	urlVars[docIDPathVariable] = pathVarDocID

	req, err := http.NewRequest("DELETE", "", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	req = mux.SetURLVars(req, urlVars)

	deleteDocumentEndpointHandler := getHandler(t, op, deleteDocumentEndpoint, http.MethodDelete, "")
	deleteDocumentEndpointHandler.Handle().ServeHTTP(rr, req)
	require.Equal(t, expectedErrorCode, rr.Code)
	require.Equal(t, expectedErrorString, rr.Body.String())
}

func storeSampleConfigExpectSuccess(t *testing.T, op *Operation) {
	t.Helper()

	store, err := op.vaultCollection.provider.OpenStore("Vault")
	require.NoError(t, err)

	err = store.StoreDataVaultConfiguration(&models.DataVaultConfiguration{ReferenceID: testReferenceID})
	require.NoError(t, err)
}

// returns created test vault ID
func createDataVaultExpectSuccess(t *testing.T, op *Operation, testFailureExtraInfo string) (string, []byte) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(testDataVaultConfiguration)))
	require.NoError(t, err, testFailureExtraInfo)

	rr := httptest.NewRecorder()

	createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost, testFailureExtraInfo)
	createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code)
	require.Contains(t, rr.Header().Get("Location"), "/encrypted-data-vaults/", testFailureExtraInfo)

	vaultID := getVaultIDFromURL(rr.Header().Get("Location"))

	return vaultID, rr.Body.Bytes()
}

func createDataVaultExpectError(t *testing.T, request *models.DataVaultConfiguration, expectedError string) {
	t.Helper()

	op := New(&Config{Provider: edvprovider.NewProvider(mem.NewProvider(), 100)})

	configBytes, err := json.Marshal(request)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer(configBytes))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost, "")
	createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, expectedError, rr.Body.String())
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func storeEncryptedDocumentExpectSuccess(t *testing.T, op *Operation, testDocID, encryptedDoc, vaultID string) {
	t.Helper()

	req, err := http.NewRequest("POST", "",
		bytes.NewBuffer([]byte(encryptedDoc)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = vaultID

	req = mux.SetURLVars(req, urlVars)

	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost, "")

	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Empty(t, rr.Body.String())
	require.Equal(t, http.StatusCreated, rr.Code)
	require.Equal(t, "/encrypted-data-vaults/"+vaultID+"/"+"documents/"+testDocID, rr.Header().Get("Location"))
}

func readDocumentExpectSuccess(t *testing.T, op *Operation) {
	t.Helper()

	vaultID, _ := createDataVaultExpectSuccess(t, op, "")

	storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument, vaultID)

	readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet, "")

	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = vaultID
	urlVars[docIDPathVariable] = testDocID

	req = mux.SetURLVars(req, urlVars)

	readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	require.Equal(t, testEncryptedDocument, rr.Body.String())
}

func getHandler(t *testing.T, op *Operation, pathToLookup, methodToLookup, testFailureExtraInfo string) Handler {
	t.Helper()

	return getHandlerWithError(t, op, pathToLookup, methodToLookup, testFailureExtraInfo)
}

func getHandlerWithError(t *testing.T, op *Operation, pathToLookup, methodToLookup,
	testFailureExtraInfo string) Handler {
	t.Helper()

	return handlerLookup(t, op, pathToLookup, methodToLookup, testFailureExtraInfo)
}

func handlerLookup(t *testing.T, op *Operation, pathToLookup, methodToLookup, testFailureExtraInfo string) Handler {
	t.Helper()

	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == pathToLookup && h.Method() == methodToLookup {
			return h
		}
	}

	if testFailureExtraInfo != "" {
		require.Fail(t, "unable to find handler. %s", testFailureExtraInfo)
	} else {
		require.Fail(t, "unable to find handler")
	}

	return nil
}

func storeDocuments(t *testing.T, operation *Operation, vaultID string, documents [][]byte,
	testFailureExtraInfo string) {
	t.Helper()

	for _, document := range documents {
		req, err := http.NewRequest("POST", "", bytes.NewBuffer(document))
		require.NoError(t, err, testFailureExtraInfo)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = vaultID

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler := getHandler(t, operation, createDocumentEndpoint, http.MethodPost, "")

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Empty(t, rr.Body.String())
		require.Equal(t, http.StatusCreated, rr.Code, testFailureExtraInfo)
	}
}

func storeTestDataForQueryTests(t *testing.T, vaultID string, provider storage.Provider,
	encryptedDoc1TagValue, encryptedDoc2TagValue string) {
	t.Helper()

	storeName, err := edvutils.Base58Encoded128BitToUUID(vaultID)
	require.NoError(t, err)

	vaultStore, err := provider.OpenStore(storeName)
	require.NoError(t, err)

	encryptedDoc1 := models.EncryptedDocument{
		ID: mockDocID1,
		IndexedAttributeCollections: []models.IndexedAttributeCollection{
			{IndexedAttributes: []models.IndexedAttribute{
				{
					Name:  "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
					Value: encryptedDoc1TagValue,
				},
			}},
		},
	}

	encryptedDoc1Bytes, err := json.Marshal(encryptedDoc1)
	require.NoError(t, err)

	err = vaultStore.Put(mockDocID1, encryptedDoc1Bytes,
		storage.Tag{
			Name:  "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
			Value: encryptedDoc1TagValue,
		})
	require.NoError(t, err)

	encryptedDoc2 := models.EncryptedDocument{
		ID: mockDocID2,
		IndexedAttributeCollections: []models.IndexedAttributeCollection{
			{IndexedAttributes: []models.IndexedAttribute{
				{
					Name:  "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
					Value: encryptedDoc2TagValue,
				},
			}},
		},
	}

	encryptedDoc2Bytes, err := json.Marshal(encryptedDoc2)
	require.NoError(t, err)

	err = vaultStore.Put(mockDocID2, encryptedDoc2Bytes,
		storage.Tag{
			Name:  "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
			Value: encryptedDoc2TagValue,
		})
	require.NoError(t, err)
}

// Extract and return vaultID from vaultLocationURL: /encrypted-data-vaults/{vaultID}
func getVaultIDFromURL(vaultLocationURL string) string {
	vaultLocationSplitUp := strings.Split(vaultLocationURL, "/")

	return vaultLocationSplitUp[len(vaultLocationSplitUp)-1]
}

func getDataVaultConfig(controller, kekID, kekType, hmacID, hmacType string,
	delegator, invoker []string) *models.DataVaultConfiguration {
	config := &models.DataVaultConfiguration{
		Sequence:    0,
		Controller:  controller,
		Invoker:     invoker,
		Delegator:   delegator,
		ReferenceID: testReferenceID,
		KEK: models.IDTypePair{
			ID:   kekID,
			Type: kekType,
		},
		HMAC: models.IDTypePair{
			ID:   hmacID,
			Type: hmacType,
		},
	}

	return config
}

func getMapWithValidVaultIDAndDocID(testVaultID string) map[string]string {
	return map[string]string{
		"vaultID": testVaultID,
		"docID":   testDocID,
	}
}

func getMapWithVaultIDThatCannotBeEscaped() map[string]string {
	return map[string]string{
		"vaultID": "%",
	}
}

func getMapWithDocIDThatCannotBeEscaped() map[string]string {
	return map[string]string{
		"docID": "%",
	}
}

type mockAuthService struct {
	createValue []byte
	createErr   error
}

func (m *mockAuthService) Create(resourceID, verificationMethod string) ([]byte, error) {
	return m.createValue, m.createErr
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
