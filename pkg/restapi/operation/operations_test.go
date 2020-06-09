/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

	testDocID = "VJYHHJx4C8J9Fsgz7rZqSp"

	testEncryptedDocument = `{"id":"` + testDocID + `","sequence":0,"indexed":null,` +
		`"jwe":{"protected":"eyJlbmMiOiJDMjBQIn0",` +
		`"recipients":[{"header":{"alg":"A256KW","kid":"https://example.com/kms/z7BgF536GaR"},"encrypted_key"` +
		`:"OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug"}],"iv":"i8Nins2vTI3PlrYW","ciphertext"` +
		`:"Cb-963UCXblINT8F6MDHzMJN9EAhK3I","tag":"pfZO0JulJcrc3trOZy8rjA"}}`

	// All of the characters in the ID below are NOT in the base58 alphabet, so this ID is not base58 encoded
	testEncryptedDocumentWithNonBase58ID = `{
  "id": "0OIl"
}`

	testEncryptedDocumentWithIDThatWasNot128BitsBeforeBase58Encoding = `{
  "id": "2CHi6"
}`

	testLogSpec = `{"spec":"restapi=debug:edv-rest=critical:error"}`
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

type alwaysReturnBarebonesDataVaultConfigurationReadCloser struct{}

func (a alwaysReturnBarebonesDataVaultConfigurationReadCloser) Read(p []byte) (n int, err error) {
	dataVaultConfigBytes := []byte(`{
 "referenceId": "` + testVaultID + `"
}`)

	_ = copy(p, dataVaultConfigBytes)

	return 68, io.EOF
}

func (a alwaysReturnBarebonesDataVaultConfigurationReadCloser) Close() error {
	return nil
}

type alwaysReturnBarebonesEncryptedDocumentReadCloser struct{}

func (a alwaysReturnBarebonesEncryptedDocumentReadCloser) Read(p []byte) (n int, err error) {
	documentBytes := []byte(`{
 "id": "` + testDocID + `"
}`)

	_ = copy(p, documentBytes)

	return 59, io.EOF
}

func (a alwaysReturnBarebonesEncryptedDocumentReadCloser) Close() error {
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
	errOpenStore                     error
	numTimesOpenStoreCalled          int
	numTimesOpenStoreCalledBeforeErr int
}

func (m *mockEDVProvider) CreateStore(string) error {
	return nil
}

func (m *mockEDVProvider) OpenStore(string) (edvprovider.EDVStore, error) {
	if m.numTimesOpenStoreCalled == m.numTimesOpenStoreCalledBeforeErr {
		return nil, m.errOpenStore
	}

	m.numTimesOpenStoreCalled++

	return &mockEDVStore{errCreateEDVIndex: m.errStoreCreateEDVIndex}, nil
}

type mockEDVStore struct {
	errCreateEDVIndex error
}

func (m *mockEDVStore) Put(models.EncryptedDocument) error {
	panic("implement me")
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

type mockStringBuilder struct {
	numWrites          int
	numWritesBeforeErr int
}

func (m *mockStringBuilder) Write(p []byte) (int, error) {
	if m.numWrites == m.numWritesBeforeErr {
		return 0, errors.New("mockStringBuilder write failure")
	}

	m.numWrites++

	return 0, nil
}

func (m *mockStringBuilder) String() string {
	panic("implement me")
}

func (m *mockStringBuilder) Reset() {}

func TestMain(m *testing.M) {
	log.Initialize(&testLoggerProvider)

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
		require.Equal(t, "referenceId can't be blank", string(resp))
	})
	t.Run("Response writer fails while writing request read error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		op.createDataVaultHandler(failingResponseWriter{}, &http.Request{Body: failingReadCloser{}})

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.CreateVaultFailReadResponseBody+messages.FailWriteResponse,
				errFailingReadCloser, errFailingResponseWriter))
	})
	t.Run("Response writer fails while writing create data vault error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		op.createDataVaultHandler(failingResponseWriter{},
			&http.Request{Body: alwaysReturnBarebonesDataVaultConfigurationReadCloser{}})

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.InvalidVaultConfig+messages.FailWriteResponse,
				`invalid character '\\x00' after top-level value`,
				errFailingResponseWriter))
	})
	t.Run("Duplicate data vault", func(t *testing.T) {
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

		writeQueryResponse(rr, nil, testVaultID)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, fmt.Sprintf(messages.QueryNoMatchingDocs, testVaultID), rr.Body.String())
	})
	t.Run("Fail to write response when no matching documents found", func(t *testing.T) {
		writeQueryResponse(failingResponseWriter{}, nil, testVaultID)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.QueryNoMatchingDocs+messages.FailWriteResponse, testVaultID, errFailingResponseWriter))
	})
	t.Run("Fail to write response when matching documents are found", func(t *testing.T) {
		writeQueryResponse(failingResponseWriter{}, []string{"docID1", "docID2"}, testVaultID)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.QuerySuccess+messages.FailWriteResponse, testVaultID, errFailingResponseWriter))
	})
}

func TestCreateDocument(t *testing.T) {
	t.Run("Success: without prefix", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		storeEncryptedDocumentExpectSuccess(t, op)
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

		storeEncryptedDocumentExpectSuccess(t, op)

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

		request := http.Request{Body: alwaysReturnBarebonesEncryptedDocumentReadCloser{}}

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
	t.Run("Response writer fails while writing create document error", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "", alwaysReturnBarebonesEncryptedDocumentReadCloser{})
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		op.createDocumentHandler(failingResponseWriter{}, req)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.InvalidDocument+messages.FailWriteResponse,
				testVaultID, `invalid character '\\x00' after top-level value`, errFailingResponseWriter))
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

		storeEncryptedDocumentExpectSuccess(t, op)

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

		storeEncryptedDocumentExpectSuccess(t, op)

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

		storeEncryptedDocumentExpectSuccess(t, op)

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

		storeEncryptedDocumentExpectSuccess(t, op)

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

		storeEncryptedDocumentExpectSuccess(t, op)

		request := http.Request{}

		op.readDocumentHandler(failingResponseWriter{},
			request.WithContext(mockContext{valueToReturnWhenValueMethodCalled: getMapWithValidVaultIDAndDocID()}))

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.ReadDocumentSuccess+messages.FailWriteResponse,
				testDocID, testVaultID, errFailingResponseWriter))
	})
}

func TestLogSpecPut(t *testing.T) {
	t.Run("Successfully set logging levels", func(t *testing.T) {
		resetLoggingLevels()

		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer([]byte(testLogSpec)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		logSpecPutEndpointHandler := getHandler(t, op, logSpecEndpoint, http.MethodPut)
		logSpecPutEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, messages.SetLogSpecSuccess, rr.Body.String())

		require.Equal(t, log.DEBUG, log.GetLevel("restapi"))
		require.Equal(t, log.CRITICAL, log.GetLevel("edv-rest"))
		require.Equal(t, log.ERROR, log.GetLevel(""))
	})
	t.Run("Empty request body", func(t *testing.T) {
		resetLoggingLevels()

		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer(nil))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		logSpecPutEndpointHandler := getHandler(t, op, logSpecEndpoint, http.MethodPut)
		logSpecPutEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, messages.InvalidLogSpec, rr.Body.String())

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("restapi"))
		require.Equal(t, log.INFO, log.GetLevel("edv-rest"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Invalid log spec: blank string", func(t *testing.T) {
		resetLoggingLevels()

		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer([]byte(`{"spec":""}`)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		logSpecPutEndpointHandler := getHandler(t, op, logSpecEndpoint, http.MethodPut)
		logSpecPutEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, messages.InvalidLogSpec, rr.Body.String())

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("restapi"))
		require.Equal(t, log.INFO, log.GetLevel("edv-rest"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Invalid log spec: default log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer([]byte(`{"spec":"InvalidLogLevel"}`)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		logSpecPutEndpointHandler := getHandler(t, op, logSpecEndpoint, http.MethodPut)
		logSpecPutEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, messages.InvalidLogSpec, rr.Body.String())

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("restapi"))
		require.Equal(t, log.INFO, log.GetLevel("edv-rest"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Invalid log spec: module log level type is invalid", func(t *testing.T) {
		resetLoggingLevels()

		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest(http.MethodPut, "",
			bytes.NewBuffer([]byte(`{"spec":"Module1=InvalidLogLevel"}`)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		logSpecPutEndpointHandler := getHandler(t, op, logSpecEndpoint, http.MethodPut)
		logSpecPutEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, messages.InvalidLogSpec, rr.Body.String())

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("restapi"))
		require.Equal(t, log.INFO, log.GetLevel("edv-rest"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Invalid log spec: multiple default log levels", func(t *testing.T) {
		resetLoggingLevels()

		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest(http.MethodPut, "", bytes.NewBuffer([]byte(`{"spec":"debug:debug"}`)))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		logSpecPutEndpointHandler := getHandler(t, op, logSpecEndpoint, http.MethodPut)
		logSpecPutEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Equal(t, messages.InvalidLogSpec, rr.Body.String())

		// Log levels should remain at the default setting of "info"
		require.Equal(t, log.INFO, log.GetLevel("restapi"))
		require.Equal(t, log.INFO, log.GetLevel("edv-rest"))
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func TestLogSpecGetHandler(t *testing.T) {
	t.Run("Successfully get logging levels", func(t *testing.T) {
		resetLoggingLevels()

		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		logSpecGetEndpointHandler := getHandler(t, op, logSpecEndpoint, http.MethodGet)
		logSpecGetEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusOK, rr.Code)
		// The two expected strings below are equivalent. Depending on the order of the entries
		//  in the underlying log levels map, either is a possible (and valid) result.
		gotExpectedLevels := rr.Body.String() == "restapi=INFO:edv-rest=INFO:INFO" ||
			rr.Body.String() == "edv-rest=INFO:restapi=INFO:INFO"
		require.True(t, gotExpectedLevels)
	})
	t.Run("Fail to write module name and level to stringBuilder", func(t *testing.T) {
		resetLoggingLevels()

		op := New(memedvprovider.NewProvider())

		op.stringBuilder = func() stringBuilder { return &mockStringBuilder{} }

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		logSpecGetEndpointHandler := getHandler(t, op, logSpecEndpoint, http.MethodGet)
		logSpecGetEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("Fail to write default log level to stringBuilder", func(t *testing.T) {
		resetLoggingLevels()

		op := New(memedvprovider.NewProvider())

		op.stringBuilder = func() stringBuilder { return &mockStringBuilder{numWritesBeforeErr: 2} }

		req, err := http.NewRequest(http.MethodGet, "", nil)
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		logSpecGetEndpointHandler := getHandler(t, op, logSpecEndpoint, http.MethodGet)
		logSpecGetEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
	t.Run("Fail to write response to sender", func(t *testing.T) {
		resetLoggingLevels()

		op := New(memedvprovider.NewProvider())

		op.logSpecGetHandler(failingResponseWriter{}, nil)

		require.Contains(t, testLoggerProvider.logContents.String(),
			fmt.Sprintf(messages.GetLogSpecSuccess+messages.FailWriteResponse, errFailingResponseWriter))
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

func storeEncryptedDocumentExpectSuccess(t *testing.T, op *Operation) {
	req, err := http.NewRequest("POST", "",
		bytes.NewBuffer([]byte(testEncryptedDocument)))
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

	storeEncryptedDocumentExpectSuccess(t, op)

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

func resetLoggingLevels() {
	log.SetLevel("restapi", log.INFO)
	log.SetLevel("edv-rest", log.INFO)
	log.SetLevel("", log.INFO)
}
