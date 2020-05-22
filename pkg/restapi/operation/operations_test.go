/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/edvprovider/memedvprovider"
	"github.com/trustbloc/edv/pkg/restapi/edverrors"
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
)

func TestCreateDataVaultHandler_InvalidDataVaultConfigurationJSON(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	createVaultHandler := getHandler(t, op, createVaultEndpoint)

	req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte("")))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createVaultHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, "Invalid data vault configuration received: unexpected end of JSON input", rr.Body.String())
}

func TestCreateDataVaultHandler_DataVaultConfigurationWithBlankReferenceIDJSON(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	req, err := http.NewRequest(http.MethodPost, "",
		bytes.NewBuffer([]byte(testDataVaultConfigurationWithBlankReferenceID)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint)
	createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

	resp, err := ioutil.ReadAll(rr.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, "Invalid data vault configuration: referenceId can't be blank", string(resp))
}

func TestCreateDataVaultHandler_ValidDataVaultConfigurationJSON(t *testing.T) {
	t.Run("Without prefix", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)
	})
}

func TestCreateDataVaultHandler_DuplicateDataVault(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	createDataVaultExpectSuccess(t, op)

	req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testDataVaultConfiguration)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint)
	createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusConflict, rr.Code)
	require.Equal(t, fmt.Sprintf("Data vault creation failed: %s", edverrors.ErrDuplicateVault.Error()),
		rr.Body.String())
}

type mockEDVProvider struct {
	errStoreCreateEDVIndex           error
	errOpenStore                     error
	numTimesOpenStoreCalled          int
	numTimesOpenStoreCalledBeforeErr int
}

func (m *mockEDVProvider) CreateStore(name string) error {
	return nil
}

func (m *mockEDVProvider) OpenStore(name string) (edvprovider.EDVStore, error) {
	if m.numTimesOpenStoreCalled == m.numTimesOpenStoreCalledBeforeErr {
		return nil, m.errOpenStore
	}

	m.numTimesOpenStoreCalled++

	return &mockEDVStore{errCreateEDVIndex: m.errStoreCreateEDVIndex}, nil
}

type mockEDVStore struct {
	errCreateEDVIndex error
}

func (m *mockEDVStore) Put(document models.EncryptedDocument) error {
	panic("implement me")
}

func (m *mockEDVStore) Get(k string) ([]byte, error) {
	panic("implement me")
}

func (m *mockEDVStore) CreateEDVIndex() error {
	return m.errCreateEDVIndex
}

func (m *mockEDVStore) Query(query *models.Query) ([]string, error) {
	return []string{"docID1", "docID2"}, nil
}

func TestCreateDataVaultHandler_FailToCreateEDVIndex(t *testing.T) {
	errTest := errors.New("create EDV index error")
	op := New(&mockEDVProvider{errStoreCreateEDVIndex: errTest, numTimesOpenStoreCalledBeforeErr: 1})

	req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(testDataVaultConfiguration)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint)
	createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, "Data vault creation failed: "+errTest.Error(), rr.Body.String())
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestQueryVaultHandler(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		op := New(&mockEDVProvider{numTimesOpenStoreCalledBeforeErr: 2})

		createDataVaultExpectSuccess(t, op)

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testQuery)))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = testVaultID

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, `["/encrypted-data-vaults/urn:uuid:abc5a436-21f9-4b4c-857d-1f5569b2600d/documents/`+
			`docID1","/encrypted-data-vaults/urn:uuid:abc5a436-21f9-4b4c-857d-1f5569b2600d/documents/docID2"]`,
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

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, "Failure while querying vault: "+
			memedvprovider.ErrQueryingNotSupported.Error(), rr.Body.String())
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

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, "Failure while querying vault: "+
			edverrors.ErrVaultNotFound.Error(), rr.Body.String())
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

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, "Failure while querying vault: "+testErr.Error(), rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Unable to decode query JSON", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte("")))
		require.NoError(t, err)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, "Invalid query received: unexpected end of JSON input", rr.Body.String())
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})
	t.Run("Fail to unescape path var", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testQuery)))
		require.NoError(t, err)

		urlVars := make(map[string]string)
		urlVars[vaultIDPathVariable] = "%"

		req = mux.SetURLVars(req, urlVars)

		rr := httptest.NewRecorder()

		queryVaultEndpointHandler := getHandler(t, op, queryVaultEndpoint)
		queryVaultEndpointHandler.Handle().ServeHTTP(rr, req)

		require.Equal(t, fmt.Sprintf(`unable to escape %s path variable: invalid URL escape "%%"`, vaultIDPathVariable),
			rr.Body.String())
		require.Equal(t, http.StatusInternalServerError, rr.Code)
	})
}

func TestSendQueryResponse(t *testing.T) {
	t.Run("No matching documents", func(t *testing.T) {
		rr := httptest.NewRecorder()

		sendQueryResponse(rr, nil, "", nil)

		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, "no matching documents found", rr.Body.String())
	})
}

func TestCreateDocumentHandler_ValidEncryptedDocumentJSON(t *testing.T) {
	t.Run("Without prefix", func(t *testing.T) {
		op := New(memedvprovider.NewProvider())

		createDataVaultExpectSuccess(t, op)

		storeEncryptedDocumentExpectSuccess(t, op)
	})
}

func TestCreateDocumentHandler_InvalidEncryptedDocumentJSON(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint)

	req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte("")))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, "Invalid encrypted document received: unexpected end of JSON input", rr.Body.String())
}

func TestCreateDocumentHandler_DocIDIsNotBase58Encoded(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	createDataVaultExpectSuccess(t, op)

	req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testEncryptedDocumentWithNonBase58ID)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID

	req = mux.SetURLVars(req, urlVars)

	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint)

	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, edverrors.ErrNotBase58Encoded.Error(), rr.Body.String())
}

func TestCreateDocumentHandler_DocIDWasNot128BitsBeforeEncodingAsBase58(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	createDataVaultExpectSuccess(t, op)

	req, err := http.NewRequest("POST", "",
		bytes.NewBuffer([]byte(testEncryptedDocumentWithIDThatWasNot128BitsBeforeBase58Encoding)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID

	req = mux.SetURLVars(req, urlVars)

	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint)

	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, edverrors.ErrNot128BitValue.Error(), rr.Body.String())
}

func TestCreateDocumentHandler_DuplicateDocuments(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	createDataVaultExpectSuccess(t, op)

	storeEncryptedDocumentExpectSuccess(t, op)

	req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testEncryptedDocument)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID

	req = mux.SetURLVars(req, urlVars)

	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint)
	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusConflict, rr.Code)
	require.Contains(t, rr.Body.String(), edverrors.ErrDuplicateDocument.Error())
}

func TestCreateDocumentHandler_VaultDoesNotExist(t *testing.T) {
	op := New(memedvprovider.NewProvider())
	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint)

	req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testEncryptedDocument)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID

	req = mux.SetURLVars(req, urlVars)

	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), edverrors.ErrVaultNotFound.Error())
}

func TestCreateDocumentHandler_UnableToEscape(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	req, err := http.NewRequest("POST", "", bytes.NewBuffer([]byte(testEncryptedDocument)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = "%"

	req = mux.SetURLVars(req, urlVars)

	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint)

	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	require.Equal(t, "", rr.Header().Get("Location"))
	require.Equal(t, fmt.Sprintf(`unable to escape %s path variable: invalid URL escape "%%"`, vaultIDPathVariable),
		rr.Body.String())
}

func TestReadDocumentHandler_DocumentExists(t *testing.T) {
	t.Run("Without prefix", func(t *testing.T) {
		readDocumentExpectSuccess(t)
	})
}

func readDocumentExpectSuccess(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	createDataVaultExpectSuccess(t, op)

	storeEncryptedDocumentExpectSuccess(t, op)

	readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint)

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

func TestReadDocumentHandler_VaultDoesNotExist(t *testing.T) {
	op := New(memedvprovider.NewProvider())
	readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint)

	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID
	urlVars[docIDPathVariable] = testDocID

	req = mux.SetURLVars(req, urlVars)

	readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusNotFound, rr.Code)
	require.Contains(t, rr.Body.String(), edverrors.ErrVaultNotFound.Error())
}

func TestReadDocumentHandler_DocumentDoesNotExist(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	createDataVaultExpectSuccess(t, op)

	readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint)

	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID
	urlVars[docIDPathVariable] = testDocID

	req = mux.SetURLVars(req, urlVars)

	readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusNotFound, rr.Code)
	require.Contains(t, rr.Body.String(), edverrors.ErrDocumentNotFound.Error())
}

func TestReadDocumentHandler_UnableToEscapeVaultIDPathVariable(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	createDataVaultExpectSuccess(t, op)

	storeEncryptedDocumentExpectSuccess(t, op)

	readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint)

	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = "%"
	urlVars[docIDPathVariable] = testDocID

	req = mux.SetURLVars(req, urlVars)

	readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)

	require.Equal(t, fmt.Sprintf(`unable to escape %s path variable: invalid URL escape "%%"`, vaultIDPathVariable),
		rr.Body.String())
}

func TestReadDocumentHandler_UnableToEscapeDocumentIDPathVariable(t *testing.T) {
	op := New(memedvprovider.NewProvider())

	createDataVaultExpectSuccess(t, op)

	storeEncryptedDocumentExpectSuccess(t, op)

	readDocumentEndpointHandler := getHandler(t, op, readDocumentEndpoint)

	req, err := http.NewRequest(http.MethodGet, "", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = vaultIDPathVariable
	urlVars[docIDPathVariable] = "%"

	req = mux.SetURLVars(req, urlVars)

	readDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusInternalServerError, rr.Code)

	require.Equal(t, fmt.Sprintf(`unable to escape %s path variable: invalid URL escape "%%"`, docIDPathVariable),
		rr.Body.String())
}

func createDataVaultExpectSuccess(t *testing.T, op *Operation) {
	req, err := http.NewRequest(http.MethodPost, "", bytes.NewBuffer([]byte(testDataVaultConfiguration)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint)
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

	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint)

	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Empty(t, rr.Body.String())
	require.Equal(t, http.StatusCreated, rr.Code)
	require.Equal(t, "/encrypted-data-vaults/"+testVaultID+"/"+"documents/"+testDocID, rr.Header().Get("Location"))
}

func getHandler(t *testing.T, op *Operation, lookup string) Handler {
	return getHandlerWithError(t, op, lookup)
}

func getHandlerWithError(t *testing.T, op *Operation, lookup string) Handler {
	return handlerLookup(t, op, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}
