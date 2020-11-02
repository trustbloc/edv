/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/edvutils"
	"github.com/trustbloc/edv/pkg/internal/common/support"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	logModuleName                   = "restapi"
	dataVaultConfigurationStoreName = "data_vault_configurations"

	edvCommonEndpointPathRoot = "/encrypted-data-vaults"
	vaultIDPathVariable       = "vaultID"
	docIDPathVariable         = "docID"

	createVaultEndpoint = edvCommonEndpointPathRoot
	// TODO (#126): As of writing, the spec shows multiple, conflicting query endpoints.
	// See: https://github.com/decentralized-identity/secure-data-store/issues/110.
	// The endpoint listed below is the correct one (per the comment made by one of the spec contributors).
	// This also matches the one used by Transmute's EDV implementation.
	queryVaultEndpoint       = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/query"
	createDocumentEndpoint   = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/documents"
	readAllDocumentsEndpoint = createDocumentEndpoint
	readDocumentEndpoint     = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/documents/{" +
		docIDPathVariable + "}"
)

var logger = log.New(logModuleName)

// Operation defines handler logic for the EDV service.
type Operation struct {
	handlers        []Handler
	vaultCollection VaultCollection
}

// VaultCollection represents EDV storage.
type VaultCollection struct {
	provider edvprovider.EDVProvider
}

// Handler represents an HTTP handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// New returns a new EDV operations instance.
func New(provider edvprovider.EDVProvider) *Operation {
	svc := &Operation{
		vaultCollection: VaultCollection{
			provider: provider,
		}}
	svc.registerHandler()

	return svc
}

// registerHandler register handlers to be exposed from this service as REST API endpoints.
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(createVaultEndpoint, http.MethodPost, c.createDataVaultHandler),
		support.NewHTTPHandler(queryVaultEndpoint, http.MethodPost, c.queryVaultHandler),
		support.NewHTTPHandler(createDocumentEndpoint, http.MethodPost, c.createDocumentHandler),
		support.NewHTTPHandler(readAllDocumentsEndpoint, http.MethodGet, c.readAllDocumentsHandler),
		support.NewHTTPHandler(readDocumentEndpoint, http.MethodGet, c.readDocumentHandler),
	}
}

// GetRESTHandlers gets all controller API handler available for this service.
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}

// Create Data Vault swagger:route POST /encrypted-data-vaults createVaultReq
//
// Creates a new data vault.
//
// Responses:
//    default: genericError
//        201: createVaultRes
func (c *Operation) createDataVaultHandler(rw http.ResponseWriter, req *http.Request) {
	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writeCreateDataVaultRequestReadFailure(rw, err)
		return
	}

	logger.Infof(`Received request to create a new data vault.
Request body: %s`, string(requestBody))

	var config models.DataVaultConfiguration

	err = json.Unmarshal(requestBody, &config)
	if err != nil {
		writeCreateDataVaultUnmarshalFailure(rw, err, requestBody)
		return
	}

	var configBytesForLog []byte

	if debugLogLevelEnabled() {
		var err error
		configBytesForLog, err = json.Marshal(config)

		if err != nil {
			logger.Debugf(messages.DebugLogEventWithReceivedData,
				fmt.Sprintf(messages.MarshalVaultConfigForLogFailure, err),
				requestBody)
		}
	}

	c.createDataVault(rw, &config, req.Host, configBytesForLog)
}

func (c *Operation) createDataVault(rw http.ResponseWriter, config *models.DataVaultConfiguration, hostURL string,
	configBytesForLog []byte) {
	if config.ReferenceID == "" {
		writeBlankReferenceIDErrMsg(rw, configBytesForLog)
		return
	}

	vaultID, err := edvutils.GenerateEDVCompatibleID()
	if err != nil {
		writeCreateDataVaultFailure(rw, err, configBytesForLog)
		return
	}

	err = c.vaultCollection.storeDataVaultConfiguration(config, vaultID)
	if err != nil {
		writeCreateDataVaultFailure(rw, fmt.Errorf(messages.StoreVaultConfigFailure, err), configBytesForLog)
		return
	}

	err = c.vaultCollection.createDataVault(vaultID)
	if err != nil {
		writeCreateDataVaultFailure(rw, err, configBytesForLog)
		return
	}

	writeCreateDataVaultSuccess(rw, vaultID, hostURL, configBytesForLog)
}

// Query Vault swagger:route POST /encrypted-data-vaults/{vaultID}/queries queryVaultReq
//
// Queries a data vault using encrypted indices.
//
// Responses:
//    default: genericError
//        200: queryVaultRes
func (c *Operation) queryVaultHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusInternalServerError, messages.QueryFailReadRequestBody,
			err, vaultID, nil)
		return
	}

	logger.Debugf(messages.DebugLogEventWithReceivedData, fmt.Sprintf(messages.QueryReceiveRequest,
		vaultID), requestBody)

	var incomingQuery models.Query

	err = json.Unmarshal(requestBody, &incomingQuery)
	if err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusBadRequest, messages.InvalidQuery, err, vaultID, requestBody)
		return
	}

	var queryBytesForLog []byte

	if debugLogLevelEnabled() {
		var errMarshal error
		queryBytesForLog, errMarshal = json.Marshal(incomingQuery)

		if errMarshal != nil {
			logger.Errorf(messages.DebugLogEventWithReceivedData,
				fmt.Sprintf(messages.MarshalQueryForLogFailure, errMarshal),
				requestBody)
		}
	}

	matchingDocumentIDs, err := c.vaultCollection.queryVault(vaultID, &incomingQuery)
	if err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusBadRequest, messages.QueryFailure, err, vaultID, queryBytesForLog)
		return
	}

	fullDocumentURLs := convertToFullDocumentURLs(matchingDocumentIDs, vaultID, req)

	writeQueryResponse(rw, fullDocumentURLs, vaultID, queryBytesForLog)
}

// Create Document swagger:route POST /encrypted-data-vaults/{vaultID}/documents createDocumentReq
//
// Stores an encrypted document.
//
// Responses:
//    default: genericError
//        201: createDocumentRes
func (c *Operation) createDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusInternalServerError,
			messages.CreateDocumentFailReadRequestBody, err, vaultID, nil)
		return
	}

	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.CreateDocumentReceiveRequest, vaultID),
		requestBody)

	c.createDocument(rw, requestBody, req.Host, vaultID)
}

// Read All Documents swagger:route GET /encrypted-data-vaults/{vaultID}/documents readAllDocumentsReq
//
// Retrieves all encrypted documents from the specified vault.
//
// Responses:
//    default: genericError
//        201: readAllDocumentsRes
func (c *Operation) readAllDocumentsHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	logger.Debugf(messages.DebugLogEvent, fmt.Sprintf(messages.ReadAllDocumentsReceiveRequest, vaultID))

	allDocuments, err := c.vaultCollection.readAllDocuments(vaultID)
	if err != nil {
		writeReadAllDocumentsFailure(rw, err, vaultID)
		return
	}

	var allDocumentsJSONRawMessage []json.RawMessage

	for _, document := range allDocuments {
		allDocumentsJSONRawMessage = append(allDocumentsJSONRawMessage, document)
	}

	writeReadAllDocumentsSuccess(rw, allDocumentsJSONRawMessage, vaultID)
}

// Read Document swagger:route GET /encrypted-data-vaults/{vaultID}/documents/{docID} readDocumentReq
//
// Retrieves an encrypted document.
//
// Responses:
//    default: genericError
//        201: readDocumentRes
func (c *Operation) readDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	docID, success := unescapePathVar(docIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	logger.Debugf(messages.DebugLogEvent, fmt.Sprintf(messages.ReadDocumentReceiveRequest, docID, vaultID))

	documentBytes, err := c.vaultCollection.readDocument(vaultID, docID)
	if err != nil {
		writeReadDocumentFailure(rw, err, docID, vaultID)
		return
	}

	writeReadDocumentSuccess(rw, documentBytes, docID, vaultID)
}

func (vc *VaultCollection) createDataVault(vaultID string) error {
	err := vc.provider.CreateStore(vaultID)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateStore) {
			return messages.ErrDuplicateVault
		}

		return err
	}

	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		return err
	}

	err = store.CreateEDVIndex()
	if err != nil {
		if err == edvprovider.ErrIndexingNotSupported { // Allow the EDV to still operate without index support
			return nil
		}

		return err
	}

	return nil
}

// storeDataVaultConfiguration stores a given DataVaultConfiguration and vaultID
func (vc *VaultCollection) storeDataVaultConfiguration(config *models.DataVaultConfiguration, vaultID string) error {
	store, err := vc.provider.OpenStore(dataVaultConfigurationStoreName)
	if err != nil {
		if errors.Is(err, storage.ErrStoreNotFound) {
			return errors.New(messages.ConfigStoreNotFound)
		}

		return err
	}

	err = store.StoreDataVaultConfiguration(config, vaultID)
	if err != nil {
		return err
	}

	return nil
}

func (c *Operation) createDocument(rw http.ResponseWriter, requestBody []byte, hostURL, vaultID string) {
	var incomingDocument models.EncryptedDocument

	err := json.Unmarshal(requestBody, &incomingDocument)
	if err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusBadRequest, messages.InvalidDocument, err,
			vaultID, requestBody)
		return
	}

	var docBytesForLog []byte

	if debugLogLevelEnabled() {
		var errMarshal error
		docBytesForLog, errMarshal = json.Marshal(incomingDocument)

		if errMarshal != nil {
			logger.Errorf(messages.DebugLogEventWithReceivedData,
				fmt.Sprintf(messages.MarshalDocumentForLogFailure, errMarshal),
				requestBody)
		}
	}

	err = c.vaultCollection.createDocument(vaultID, incomingDocument)
	if err != nil {
		writeCreateDocumentFailure(rw, err, vaultID, docBytesForLog)
		return
	}

	writeCreateDocumentSuccess(rw, hostURL, vaultID, incomingDocument.ID, docBytesForLog)
}

func (vc *VaultCollection) createDocument(vaultID string, document models.EncryptedDocument) error {
	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		if errors.Is(err, storage.ErrStoreNotFound) {
			return messages.ErrVaultNotFound
		}

		return err
	}

	if encodingErr := edvutils.CheckIfBase58Encoded128BitValue(document.ID); encodingErr != nil {
		return encodingErr
	}

	// The Create Document API call should not overwrite an existing document.
	// So we first check to make sure there is not already a document associated with the id.
	// If there is, we send back an error.
	_, err = store.Get(document.ID)
	if err == nil {
		return messages.ErrDuplicateDocument
	}

	if !errors.Is(err, storage.ErrValueNotFound) {
		return err
	}

	return store.Put(document)
}

func (vc *VaultCollection) readAllDocuments(vaultName string) ([][]byte, error) {
	store, err := vc.provider.OpenStore(vaultName)
	if err != nil {
		if errors.Is(err, storage.ErrStoreNotFound) {
			return nil, messages.ErrVaultNotFound
		}

		return nil, err
	}

	documentBytes, err := store.GetAll()
	if err != nil {
		return nil, fmt.Errorf(messages.FailWhileGetAllDocsFromStoreErrMsg, err)
	}

	return documentBytes, err
}

func (vc *VaultCollection) readDocument(vaultID, docID string) ([]byte, error) {
	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		if errors.Is(err, storage.ErrStoreNotFound) {
			return nil, messages.ErrVaultNotFound
		}

		return nil, err
	}

	documentBytes, err := store.Get(docID)
	if err != nil {
		if errors.Is(err, storage.ErrValueNotFound) {
			return nil, messages.ErrDocumentNotFound
		}

		return nil, err
	}

	return documentBytes, err
}

func (vc *VaultCollection) queryVault(vaultID string, query *models.Query) ([]string, error) {
	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		if errors.Is(err, storage.ErrStoreNotFound) {
			return nil, messages.ErrVaultNotFound
		}

		return nil, err
	}

	return store.Query(query)
}
