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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/edvprovider/memedvprovider"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	testVaultID = "urn:uuid:abc5a436-21f9-4b4c-857d-1f5569b2600d"

	testDataVaultConfigurationWithBlankReferenceID = `{
  "sequence": 0,
  "controller": "did:example:123456789",
  "referenceId": "",
  "kek": {
    "id": "https://example.com/kms/12345",
    "type": "AesKeyWrappingKey2019"
  },
  "hmac": {
    "id": "https://example.com/kms/67891",
    "type": "Sha256HmacKey2019"
  }
}`

	testDataVaultConfiguration = `{
  "sequence": 0,
  "controller": "did:example:123456789",
  "referenceId": "` + testVaultID + `",
  "kek": {
    "id": "https://example.com/kms/12345",
    "type": "AesKeyWrappingKey2019"
  },
  "hmac": {
    "id": "https://example.com/kms/67891",
    "type": "Sha256HmacKey2019"
  }
}`

	testQuery = `{
  "index": "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
  "equals": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
}`

	testDocID  = "VJYHHJx4C8J9Fsgz7rZqSp"
	testDocID2 = "AJYHHJx4C8J9Fsgz7rZqSp"

	testJWE1 = `{"protected":"eyJlbmMiOiJDMjBQIn0","recipients":[{"header":{"alg":"A256KW","kid":"https://exam` +
		`ple.com/kms/z7BgF536GaR"},"encrypted_key":"OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"}],` +
		`"iv":"i8Nins2vTI3PlrYW","ciphertext":"Cb-963UCXblINT8F6MDHzMJN9EAhK3I","tag":"pfZO0JulJcrc3trOZy8rjA"}`
	testJWE2 = `{"protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","encrypted_k` +
		`ey":"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKA` +
		`q7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfw` +
		`X7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWX` +
		`RcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg","iv":"48V1_ALb6US04U3b","ciphertext":"5eym8TW_c8SuK0ltJ` +
		`3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A","tag":"XFBoMYUZodetZdvTiFvSkQ"}`

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
)

var testLoggerProvider = TestLoggerProvider{}
var errFailingResponseWriter = errors.New("failingResponseWriter always fails")
var errFailingReadCloser = errors.New("failingReadCloser always fails")

type TestLoggerProvider struct {
	logContents bytes.Buffer
}

func (t *TestLoggerProvider) GetLogger(string) log.Logger {
	logrusLogger := logrus.New()
	logrusLogger.SetOutput(&t.logContents)
	logrusLogger.SetLevel(logrus.DebugLevel)

	return logrusLogger
}

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

type mockEDVProvider struct {
	errStoreCreateEDVIndex           error
	errStoreGetAll                   error
	errCreateStore                   error
	errOpenStore                     error
	numTimesOpenStoreCalled          int
	numTimesOpenStoreCalledBeforeErr int
}

func (m *mockEDVProvider) CreateStore(string) error {
	return m.errCreateStore
}

func (m *mockEDVProvider) OpenStore(string) (edvprovider.EDVStore, error) {
	if m.numTimesOpenStoreCalled == m.numTimesOpenStoreCalledBeforeErr {
		return nil, m.errOpenStore
	}

	m.numTimesOpenStoreCalled++

	return &mockEDVStore{errCreateEDVIndex: m.errStoreCreateEDVIndex, errGetAll: m.errStoreGetAll}, nil
}

type mockEDVStore struct {
	errCreateEDVIndex error
	errGetAll         error
}

func (m *mockEDVStore) Put(models.EncryptedDocument) error {
	panic("implement me")
}

func (m *mockEDVStore) GetAll() ([][]byte, error) {
	return nil, m.errGetAll
}

func (m *mockEDVStore) Get(string) ([]byte, error) {
	panic("implement me")
}

func (m *mockEDVStore) CreateEDVIndex() error {
	return m.errCreateEDVIndex
}

func (m *mockEDVStore) Query(*models.Query) ([]string, error) {
	return []string{"docID1", "docID2"}, nil
}

func TestMain(m *testing.M) {
	log.Initialize(&testLoggerProvider)

	log.SetLevel(logModuleName, log.DEBUG)

	os.Exit(m.Run())
}

func TestCreateDataVault(t *testing.T) {
	t.Run("Success: without prefix", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)
	})
	t.Run("Invalid Data Vault Configuration JSON", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createVaultHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost)

		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		createVaultHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.InvalidVaultConfig, "unexpected end of JSON input"),
			rr.Body.String())
	})
	t.Run("Blank reference ID", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest(http.MethodPost, "",
			bytes.NewBuffer([]byte(testDataVaultConfigurationWithBlankReferenceID)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost)
		createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		resp, err := ioutil.ReadAll(rr.Body)
		require.NoError(t, err)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.InvalidVaultConfig, messages.BlankReferenceID), string(resp))
	})
	t.Run("Response writer fails while writing blank reference ID error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		op.createDataVault(&failingResponseWriter{}, &models.DataVaultConfiguration{}, "",
			nil)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.InvalidVaultConfig+messages.FailWriteResponse,
				messages.BlankReferenceID, errFailingResponseWriter))
	})
	t.Run("Response writer fails while writing request read error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		op.createDataVaultHandler(failingResponseWriter{}, &http.Request{Body: failingReadCloser{}})

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.CreateVaultFailReadRequestBody+messages.FailWriteResponse,
				errFailingReadCloser, errFailingResponseWriter))
	})
	t.Run("Error when creating new store: duplicate data vault", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testDataVaultConfiguration)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost)
		createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusConflict, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.VaultCreationFailure, messages.ErrDuplicateVault.Error()),
			rr.Body.String())
	})
	t.Run("Other error when creating new store", func(t *testing.T) {
		errTest := errors.New("some other create store error")
		op := New(&mockEDVProvider{errCreateStore: errTest})

		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(testDataVaultConfiguration)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost)
		createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.VaultCreationFailure, errTest), rr.Body.String())
	})
	t.Run("Response writer fails while writing duplicate data vault error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		op.createDataVault(&failingResponseWriter{},
			&models.DataVaultConfiguration{ReferenceID: testVaultID}, "", nil)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.VaultCreationFailure+messages.FailWriteResponse,
				messages.ErrDuplicateVault, errFailingResponseWriter))
	})
	t.Run("Fail to create EDV index", func(t *testing.T) {
		errTest := errors.New("create EDV index error")
		op := New(&mockEDVProvider{errStoreCreateEDVIndex: errTest, numTimesOpenStoreCalledBeforeErr: 1})

		req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(testDataVaultConfiguration)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost)
		createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(messages.VaultCreationFailure, errTest), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestQueryVault(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := New(&mockEDVProvider{numTimesOpenStoreCalledBeforeErr: 2})

		createDataVaultExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testQuery)))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, `["/encrypted-data-vaults/`+testVaultID+`/documents/`+
			`docID1","/encrypted-data-vaults/`+testVaultID+`/documents/docID2"]`,
			rr.Body.String())
		require.Equal(t, http.StatusOK, rr.Code)
	})
	t.Run("Provider doesn't support querying", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testQuery)))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(messages.QueryFailure, testVaultID, memedvprovider.ErrQueryingNotSupported),
			rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Error: vault not found", func(t *testing.T) {
		op := New(&mockEDVProvider{
			numTimesOpenStoreCalledBeforeErr: 1, errOpenStore: storage.ErrStoreNotFound})

		createDataVaultExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testQuery)))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(messages.QueryFailure, testVaultID, messages.ErrVaultNotFound), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Error: fail to open store", func(t *testing.T) {
		testErr := errors.New("fail to open store")
		op := New(&mockEDVProvider{numTimesOpenStoreCalledBeforeErr: 1, errOpenStore: testErr})

		createDataVaultExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testQuery)))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(messages.QueryFailure, testVaultID, testErr), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Error when writing response after an error happens while querying vault", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testQuery)))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost)
		queryVaultEndpointHandler.Handle().ServeHTTP(failingResponseWriter{}, req)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.QueryFailure+messages.FailWriteResponse, testVaultID,
				memedvprovider.ErrQueryingNotSupported, errFailingResponseWriter))
	})
	t.Run("Unable to unmarshal query JSON", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(messages.InvalidQuery, testVaultID, "unexpected end of JSON input"), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Fail to write response when unable to unmarshal query JSON", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest("POST", "", failingReadCloser{})
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		op.queryVaultHandler(failingResponseWriter{}, req)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.QueryFailReadRequestBody+messages.FailWriteResponse,
				testVaultID, errFailingReadCloser, errFailingResponseWriter))
	})
	t.Run("Fail to unescape path var", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testQuery)))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = "%"

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint, http.MethodPost)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t,
			fmt.Sprintf(messages.UnescapeFailure, vaultIDPathVariable, `invalid URL escape "%"`),
			rr.Body.String())
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("No matching documents", func(t *testing.T) {
		rr := httptest.NewRecorder()

		writeQueryResponse(rr, nil, testVaultID, nil)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.QueryNoMatchingDocs, testVaultID), rr.Body.String())
	})
	t.Run("Fail to write response when no matching documents found", func(t *testing.T) {
		writeQueryResponse(failingResponseWriter{}, nil, testVaultID, nil)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.QueryNoMatchingDocs+messages.FailWriteResponse, testVaultID, errFailingResponseWriter))
	})
	t.Run("Fail to write response when matching documents are found", func(t *testing.T) {
		writeQueryResponse(failingResponseWriter{}, []string{"docID1", "docID2"}, testVaultID, nil)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.QuerySuccess+messages.FailWriteResponse, testVaultID, errFailingResponseWriter))
	})
}

func TestCreateDocument(t *testing.T) {
	t.Run("Success: without prefix", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument)
	})
	t.Run("Invalid encrypted document JSON", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.InvalidDocument, testVaultID, "unexpected end of JSON input"),
			rr.Body.String())
	})
	t.Run("Document ID is not base58 encoded", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testEncryptedDocumentWithNonBase58ID)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost)

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.CreateDocumentFailure, testVaultID, messages.ErrNotBase58Encoded),
			rr.Body.String())
	})
	t.Run("Document ID was not 128 bits long before being base58 encoded", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "",
			bytes.NewBuffer([]byte(testEncryptedDocumentWithIDThatWasNot128BitsBeforeBase58Encoding)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost)

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.CreateDocumentFailure, testVaultID, messages.ErrNot128BitValue),
			rr.Body.String())
	})
	t.Run("Duplicate document", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testEncryptedDocument)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost)
		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusConflict, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.CreateDocumentFailure, testVaultID, messages.ErrDuplicateDocument),
			rr.Body.String())
	})
	t.Run("Response writer fails while writing duplicate document error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument)

		op.createDocument(&failingResponseWriter{}, []byte(testEncryptedDocument), "", testVaultID)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.CreateDocumentFailure+messages.FailWriteResponse,
				testVaultID, messages.ErrDuplicateDocument, errFailingResponseWriter))
	})
	t.Run("Vault does not exist", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())
		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost)

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
		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testEncryptedDocument)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = "%"

		req = mux.SetURLVars(req, urlVars)

		createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost)

		createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
		require.Equal(t, "", rr.Header().Get("Location"))
		require.Equal(t,
			fmt.Sprintf(messages.UnescapeFailure, vaultIDPathVariable, `invalid URL escape "%"`),
			rr.Body.String())
	})
	t.Run("Response writer fails while writing unescape Vault ID error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		request := http.Request{}

		op.createDocumentHandler(failingResponseWriter{},
			request.WithContext(mockContext{valueToReturnWhenValueMethodCalled: getMapWithVaultIDThatCannotBeEscaped()}))

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.UnescapeFailure+messages.FailWriteResponse, vaultIDPathVariable,
				errFailingResponseWriter, errFailingResponseWriter))
	})
	t.Run("Response writer fails while writing request read error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest("POST", "", failingReadCloser{})
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		op.createDocumentHandler(failingResponseWriter{}, req)

		require.Contains(t,
			testLoggerProvider.logContents.String(), fmt.Sprintf(
				messages.CreateDocumentFailReadRequestBody+messages.FailWriteResponse,
				testVaultID, errFailingReadCloser, errFailingResponseWriter))
	})
}

func TestReadAllDocuments(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)
		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument)
		storeEncryptedDocumentExpectSuccess(t, op, testDocID2, testEncryptedDocument2)

		readAllDocumentsEndpointHandler := getHandler(t, op, readAllDocumentsEndpoint, http.MethodGet)

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		readAllDocumentsEndpointHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		// This unmarshalling and remarshalling is done so that we can directly compare the expected output
		// with the output from the EDV service.
		var expectedEncryptedDoc1 models.EncryptedDocument

		err = json.Unmarshal([]byte(testEncryptedDocument), &expectedEncryptedDoc1)
		require.NoError(t, err)

		var expectedEncryptedDoc2 models.EncryptedDocument

		err = json.Unmarshal([]byte(testEncryptedDocument2), &expectedEncryptedDoc2)
		require.NoError(t, err)

		expectedEncryptedDocs := []models.EncryptedDocument{expectedEncryptedDoc1, expectedEncryptedDoc2}

		expectedEncryptedDocsBytes, err := json.Marshal(expectedEncryptedDocs)
		require.NoError(t, err)

		require.Equal(t, string(expectedEncryptedDocsBytes), rr.Body.String())
	})
	t.Run("Vault does not exist", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		readAllDocumentsEndpointHandler := getHandler(t, op, readAllDocumentsEndpoint, http.MethodGet)

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		readAllDocumentsEndpointHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusNotFound, rr.Code)

		require.Equal(t, fmt.Sprintf(messages.ReadAllDocumentsFailure, testVaultID, messages.ErrVaultNotFound),
			rr.Body.String())
	})
	t.Run("Error while getting all docs from store", func(t *testing.T) {
		errGetAll := errors.New("some get all error")
		op := New(&mockEDVProvider{numTimesOpenStoreCalledBeforeErr: 1, errStoreGetAll: errGetAll})

		readAllDocumentsEndpointHandler := getHandler(t, op, readAllDocumentsEndpoint, http.MethodGet)

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		readAllDocumentsEndpointHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)

		require.Equal(t, fmt.Sprintf(messages.ReadAllDocumentsFailure,
			testVaultID, fmt.Errorf(messages.FailWhileGetAllDocsFromStoreErrMsg, errGetAll).Error()),
			rr.Body.String())
	})
	t.Run("Unable to escape vault ID path variable", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		readAllDocumentsEndpointHandler := getHandler(t, op, readAllDocumentsEndpoint, http.MethodGet)

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = "%"

		req = mux.SetURLVars(req, urlVars)

		readAllDocumentsEndpointHandler.Handle().ServeHTTP(rr, req)
		require.Equal(t, http.StatusInternalServerError, rr.Code)

		require.Equal(t, fmt.Sprintf(messages.UnescapeFailure, vaultIDPathVariable, `invalid URL escape "%"`),
			rr.Body.String())
	})
}

func TestReadDocument(t *testing.T) {
	t.Run("Success: without prefix", func(t *testing.T) {
		readDocumentExpectSuccess(t)
	})
	t.Run("Vault does not exist", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())
		readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet)

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
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet)

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID
		urlVars[docIDPathVariable] = testDocID

		req = mux.SetURLVars(req, urlVars)

		readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusNotFound, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.ReadDocumentFailure,
			testDocID, testVaultID, messages.ErrDocumentNotFound), rr.Body.String())
	})
	t.Run("Unable to escape vault ID path variable", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument)

		readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet)

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = "%"
		urlVars[docIDPathVariable] = testDocID

		req = mux.SetURLVars(req, urlVars)

		readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)

		require.Equal(t, fmt.Sprintf(messages.UnescapeFailure, vaultIDPathVariable, `invalid URL escape "%"`),
			rr.Body.String())
	})
	t.Run("Unable to escape document ID path variable", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument)

		readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet)

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID
		urlVars[docIDPathVariable] = "%"

		req = mux.SetURLVars(req, urlVars)

		readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)

		require.Equal(t, fmt.Sprintf(messages.UnescapeFailure, docIDPathVariable, `invalid URL escape "%"`),
			rr.Body.String())
	})
	t.Run("Response writer fails while writing unescape vault ID error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument)

		request := http.Request{}

		op.readDocumentHandler(failingResponseWriter{},
			request.WithContext(mockContext{valueToReturnWhenValueMethodCalled: getMapWithVaultIDThatCannotBeEscaped()}))

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.UnescapeFailure+messages.FailWriteResponse,
				vaultIDPathVariable, errFailingResponseWriter, errFailingResponseWriter))
	})
	t.Run("Response writer fails while writing unescape document ID error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument)

		request := http.Request{}

		op.readDocumentHandler(failingResponseWriter{},
			request.WithContext(mockContext{valueToReturnWhenValueMethodCalled: getMapWithDocIDThatCannotBeEscaped()}))

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.UnescapeFailure+messages.FailWriteResponse,
				docIDPathVariable, errFailingResponseWriter, errFailingResponseWriter))
	})
	t.Run("Response writer fails while writing read document error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID
		urlVars[docIDPathVariable] = testDocID

		req = mux.SetURLVars(req, urlVars)

		op.readDocumentHandler(failingResponseWriter{}, req)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.ReadDocumentFailure, testDocID, testVaultID, messages.ErrVaultNotFound))
	})
	t.Run("Response writer fails while writing retrieved document", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument)

		request := http.Request{}

		op.readDocumentHandler(failingResponseWriter{},
			request.WithContext(mockContext{valueToReturnWhenValueMethodCalled: getMapWithValidVaultIDAndDocID()}))

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.ReadDocumentSuccess+messages.FailWriteResponse,
				testDocID, testVaultID, errFailingResponseWriter))
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

func createDataVaultExpectSuccess(t *testing.T, op *Operation) {
	req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(testDataVaultConfiguration)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint, http.MethodPost)
	createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code)
	require.Equal(t, "/encrypted-data-vaults/"+testVaultID, rr.Header().Get("Location"))
}

func storeEncryptedDocumentExpectSuccess(t *testing.T, op *Operation, testDocID, encryptedDoc string) {
	req, err := http.NewRequest("POST", "",
		bytes.NewBuffer([]byte(encryptedDoc)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID

	req = mux.SetURLVars(req, urlVars)

	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint, http.MethodPost)

	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Empty(t, rr.Body.String())
	require.Equal(t, http.StatusCreated, rr.Code)
	require.Equal(t, "/encrypted-data-vaults/"+testVaultID+"/"+"documents/"+testDocID, rr.Header().Get("Location"))
}

func readDocumentExpectSuccess(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	createDataVaultExpectSuccess(t, op)

	storeEncryptedDocumentExpectSuccess(t, op, testDocID, testEncryptedDocument)

	readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint, http.MethodGet)

	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID
	urlVars[docIDPathVariable] = testDocID

	req = mux.SetURLVars(req, urlVars)

	readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	require.Equal(t, testEncryptedDocument, rr.Body.String())
}

func getHandler(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	return getHandlerWithError(t, op, pathToLookup, methodToLookup)
}

func getHandlerWithError(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	return handlerLookup(t, op, pathToLookup, methodToLookup)
}

func handlerLookup(t *testing.T, op *Operation, pathToLookup, methodToLookup string) Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == pathToLookup && h.Method() == methodToLookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}

func getMapWithValidVaultIDAndDocID() map[string]string {
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
