/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/stretchr/testify/require"
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

	testDocID = "urn:uuid:94684128-c42c-4b28-adb0-aec77bf76045"

	testStructuredDocument = `{
  "id":"` + testDocID + `",
  "meta": {
    "created": "2019-06-18"
  },
  "content": {
    "message": "Hello World!"
  }
}`
)

func TestCreateDataVaultHandler_InvalidDataVaultConfigurationJSON(t *testing.T) {
	op := New(memstore.NewProvider())

	createVaultHandler := getHandler(t, op, createVaultEndpoint)

	req, err := http.NewRequest(http.MethodPost, "/data-vaults", bytes.NewBuffer([]byte("")))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createVaultHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "EOF")
}

func TestCreateDataVaultHandler_DataVaultConfigurationWithBlankReferenceIDJSON(t *testing.T) {
	op := New(memstore.NewProvider())

	req, err := http.NewRequest(http.MethodPost, createVaultEndpoint,
		bytes.NewBuffer([]byte(testDataVaultConfigurationWithBlankReferenceID)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint)
	createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

	resp, err := ioutil.ReadAll(rr.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Equal(t, "referenceId can't be blank", string(resp))
}

func TestCreateDataVaultHandler_ValidDataVaultConfigurationJSON(t *testing.T) {
	op := New(memstore.NewProvider())

	createDataVaultExpectSuccess(t, op)
}

func TestCreateDataVaultHandler_DuplicateDataVault(t *testing.T) {
	op := New(memstore.NewProvider())

	createDataVaultExpectSuccess(t, op)

	req, err := http.NewRequest("POST", createVaultEndpoint, bytes.NewBuffer([]byte(testDataVaultConfiguration)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint)
	createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusConflict, rr.Code)
	require.Equal(t, "Data vault creation failed: vault already exists", rr.Body.String())
}

func TestCreateDocumentHandler_InvalidStructuredDocumentJSON(t *testing.T) {
	op := New(memstore.NewProvider())

	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint)

	req, err := http.NewRequest("POST", createDocumentEndpoint, bytes.NewBuffer([]byte("")))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "EOF")
}

func TestCreateDocumentHandler_ValidStructuredDocumentJSON(t *testing.T) {
	op := New(memstore.NewProvider())

	createDataVaultExpectSuccess(t, op)

	storeStructuredDocumentExpectSuccess(t, op)
}

func TestCreateDocumentHandler_DuplicateDocuments(t *testing.T) {
	op := New(memstore.NewProvider())

	createDataVaultExpectSuccess(t, op)

	storeStructuredDocumentExpectSuccess(t, op)

	req, err := http.NewRequest("POST", "/encrypted-data-vaults/"+testVaultID+"/docs",
		bytes.NewBuffer([]byte(testStructuredDocument)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID

	req = mux.SetURLVars(req, urlVars)

	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint)
	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "a document with the given id already exists")
}

func TestCreateDocumentHandler_VaultDoesNotExist(t *testing.T) {
	op := New(memstore.NewProvider())
	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint)

	req, err := http.NewRequest("POST", "/encrypted-data-vaults/"+testVaultID+"/docs",
		bytes.NewBuffer([]byte(testStructuredDocument)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID

	req = mux.SetURLVars(req, urlVars)

	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "specified vault does not exist")
}

func TestRetrieveDocumentHandler_VaultDoesNotExist(t *testing.T) {
	op := New(memstore.NewProvider())
	retrieveDocumentEndpointHandler := getHandler(t, op, retrieveDocumentEndpoint)

	req, err := http.NewRequest(http.MethodPost,
		"/encrypted-data-vaults/"+testVaultID+"/"+
			"docs/"+testDocID,
		bytes.NewBuffer([]byte("")))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID
	urlVars[docIDPathVariable] = testDocID

	req = mux.SetURLVars(req, urlVars)

	retrieveDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), "specified vault does not exist")
}

func TestRetrieveDocumentHandler_DocumentDoesNotExist(t *testing.T) {
	op := New(memstore.NewProvider())

	createDataVaultExpectSuccess(t, op)

	retrieveDocumentEndpointHandler := getHandler(t, op, retrieveDocumentEndpoint)

	req, err := http.NewRequest(http.MethodPost,
		"/encrypted-data-vaults/"+testVaultID+"/"+
			"docs/"+testDocID,
		bytes.NewBuffer([]byte("")))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID
	urlVars[docIDPathVariable] = testDocID

	req = mux.SetURLVars(req, urlVars)

	retrieveDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusNotFound, rr.Code)
	require.Contains(t, rr.Body.String(), "specified document does not exist")
}

func TestRetrieveDocumentHandler_DocumentExists(t *testing.T) {
	op := New(memstore.NewProvider())

	createDataVaultExpectSuccess(t, op)

	storeStructuredDocumentExpectSuccess(t, op)

	retrieveDocumentEndpointHandler := getHandler(t, op, retrieveDocumentEndpoint)

	req, err := http.NewRequest(http.MethodPost,
		"/encrypted-data-vaults/"+testVaultID+"/docs/"+testDocID,
		bytes.NewBuffer([]byte("")))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID
	urlVars[docIDPathVariable] = testDocID

	req = mux.SetURLVars(req, urlVars)

	retrieveDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)

	const expectedData = `{"id":"` + testDocID + `","meta":{"created":"2019-06-18"},"content":{"message":"Hello World!"}}`

	require.Equal(t, expectedData, rr.Body.String())
}

func TestCreateDocument_FailToMarshal(t *testing.T) {
	op := New(memstore.NewProvider())

	newStore, err := op.vaultCollection.provider.OpenStore("store1")
	require.NoError(t, err)

	op.vaultCollection.openStores["store1"] = newStore

	unmarshallableMap := make(map[string]interface{})
	unmarshallableMap["somewhere"] = make(chan int)

	err = op.vaultCollection.createDocument("store1", StructuredDocument{
		ID:      "",
		Meta:    unmarshallableMap,
		Content: nil,
	})

	require.Equal(t, "json: unsupported type: chan int", err.Error())
}

func createDataVaultExpectSuccess(t *testing.T, op *Operation) {
	req, err := http.NewRequest(http.MethodPost, createVaultEndpoint, bytes.NewBuffer([]byte(testDataVaultConfiguration)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	createVaultEndpointHandler := getHandler(t, op, createVaultEndpoint)
	createVaultEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code)
	require.Equal(t, "/encrypted-data-vaults/"+testVaultID, rr.Header().Get("Location"))
}

func storeStructuredDocumentExpectSuccess(t *testing.T, op *Operation) {
	req, err := http.NewRequest("POST", "/encrypted-data-vaults/"+testVaultID+"/docs",
		bytes.NewBuffer([]byte(testStructuredDocument)))
	require.NoError(t, err)

	rr := httptest.NewRecorder()

	urlVars := make(map[string]string)
	urlVars[vaultIDPathVariable] = testVaultID

	req = mux.SetURLVars(req, urlVars)

	createDocumentEndpointHandler := getHandler(t, op, createDocumentEndpoint)

	createDocumentEndpointHandler.Handle().ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code)
	require.Equal(t, "/encrypted-data-vaults/"+testVaultID+"/"+"docs/"+testDocID, rr.Header().Get("Location"))
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
