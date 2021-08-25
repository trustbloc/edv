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
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/edvutils"
	"github.com/trustbloc/edv/pkg/internal/common/support"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	logModuleName = "restapi"

	edvCommonEndpointPathRoot = "/encrypted-data-vaults"
	vaultIDPathVariable       = "vaultID"
	docIDPathVariable         = "docID"

	createVaultEndpoint = edvCommonEndpointPathRoot
	// TODO (#126): As of writing, the spec shows multiple, conflicting query endpoints.
	// See: https://github.com/decentralized-identity/secure-data-store/issues/110.
	// The endpoint listed below is the correct one (per the comment made by one of the spec contributors).
	// This also matches the one used by Transmute's EDV implementation.
	queryVaultEndpoint     = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/query"
	createDocumentEndpoint = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/documents"
	batchEndpoint          = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/batch"
	readDocumentEndpoint   = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/documents/{" +
		docIDPathVariable + "}"
	updateDocumentEndpoint = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/documents/{" +
		docIDPathVariable + "}"
	deleteDocumentEndpoint = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/documents/{" +
		docIDPathVariable + "}"
)

var logger = log.New(logModuleName)

// Operation defines handler logic for the EDV service.
type Operation struct {
	handlers          []Handler
	vaultCollection   VaultCollection
	authEnable        bool
	authService       authService
	enabledExtensions *EnabledExtensions
}

type authService interface {
	Create(resourceID, verificationMethod string) ([]byte, error)
}

// VaultCollection represents EDV storage.
type VaultCollection struct {
	provider *edvprovider.Provider
}

// Handler represents an HTTP handler for each controller API endpoint.
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// EnabledExtensions indicates which EDV server extensions have been enabled.
type EnabledExtensions struct {
	ReturnFullDocumentsOnQuery bool
	ReadAllDocumentsEndpoint   bool
	Batch                      bool
}

// Config defines configuration for vcs operations
type Config struct {
	Provider          *edvprovider.Provider
	AuthService       authService
	AuthEnable        bool
	EnabledExtensions *EnabledExtensions
}

// New returns a new EDV operations instance.
func New(config *Config) *Operation {
	svc := &Operation{
		vaultCollection: VaultCollection{
			provider: config.Provider,
		}, authEnable: config.AuthEnable, authService: config.AuthService, enabledExtensions: config.EnabledExtensions,
	}

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
		support.NewHTTPHandler(readDocumentEndpoint, http.MethodGet, c.readDocumentHandler),
		support.NewHTTPHandler(updateDocumentEndpoint, http.MethodPost, c.updateDocumentHandler),
		support.NewHTTPHandler(deleteDocumentEndpoint, http.MethodDelete, c.deleteDocumentHandler),
	}
	if c.enabledExtensions != nil {
		if c.enabledExtensions.Batch {
			c.handlers = append(c.handlers,
				support.NewHTTPHandler(batchEndpoint, http.MethodPost, c.batchHandler))
		}
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

	logger.Infof(`Received request to create a new data vault. X-User header: %s,Request body: %s`,
		req.Header.Get("X-User"), string(requestBody))

	var config models.DataVaultConfiguration

	err = json.Unmarshal(requestBody, &config)
	if err != nil {
		writeCreateDataVaultInvalidRequest(rw, err, requestBody)
		return
	}

	err = validateDataVaultConfiguration(&config)
	if err != nil {
		writeCreateDataVaultInvalidRequest(rw, err, requestBody)
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

	// Add auth payload if enabled
	var payload []byte

	if c.authEnable {
		payload, err = c.authService.Create(vaultID, config.Controller)
		if err != nil {
			writeCreateDataVaultFailure(rw, err, configBytesForLog)
			return
		}
	}

	writeCreateDataVaultSuccess(rw, vaultID, hostURL, configBytesForLog, payload)
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

	incomingQuery, err := parseQuery(requestBody)
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

	matchingDocuments, err := c.vaultCollection.queryVault(vaultID, &incomingQuery)
	if err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusBadRequest, messages.QueryFailure, err, vaultID, queryBytesForLog)
		return
	}

	if c.enabledExtensions != nil && c.enabledExtensions.ReturnFullDocumentsOnQuery {
		writeQueryResponse(rw, matchingDocuments, vaultID, queryBytesForLog, incomingQuery.ReturnFullDocuments, req.Host)
	} else {
		writeQueryResponse(rw, matchingDocuments, vaultID, queryBytesForLog, false, req.Host)
	}
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

// Update Document swagger:route POST /encrypted-data-vaults/{vaultID}/documents/{docID} updateDocumentReq
//
// Update an encrypted document.
//
// Responses:
//		default: genericError
// 			200: emptyRes
func (c *Operation) updateDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	docID, success := unescapePathVar(docIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	logger.Debugf(messages.DebugLogEvent, fmt.Sprintf(messages.UpdateDocumentReceiveRequest, docID, vaultID))

	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writeErrorWithVaultIDAndDocID(rw, http.StatusInternalServerError,
			messages.UpdateDocumentFailReadRequestBody, err, docID, vaultID)
		return
	}

	c.updateDocument(rw, requestBody, docID, vaultID)
}

// Delete Document swagger:route DELETE /encrypted-data-vaults/{vaultID}/documents/{docID} deleteDocumentReq
//
// Delete an encrypted document.
//
// Responses:
//		default: genericError
// 			200: emptyRes
//			400: emptyRes
// 			404: emptyRes
func (c *Operation) deleteDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	docID, success := unescapePathVar(docIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	logger.Debugf(messages.DebugLogEvent, fmt.Sprintf(messages.DeleteDocumentReceiveRequest, docID, vaultID))

	err := c.vaultCollection.deleteDocument(docID, vaultID)
	if err != nil {
		writeDeleteDocumentFailure(rw, err, docID, vaultID)
	}
}

// Response body will be an array of responses, one for each vault operation. Response for a successful upsert
// will be the document location. No distinction is made between document creation and document updates.
// TODO (#171): Address the limitations of this endpoint. Specifically...
//  1. Updated documents must have the same encrypted indices (names+values) as the documents they're replacing,
//  2. For new documents, encrypted indices will be created, but no uniqueness validation will occur.
//     (No errors will be thrown if either of these limitations are not respected.
//     The underlying database will just get in a bad state if you ignore them.)
//  3. Delete operations are slow because they don't batch with other operations. They force any queued operations
//     to execute early. Delete operations don't batch with other operations (including other deletes).
func (c *Operation) batchHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusInternalServerError, messages.BatchFailReadRequestBody,
			err, vaultID, nil)
		return
	}

	logger.Debugf(messages.DebugLogEventWithReceivedData, fmt.Sprintf(messages.BatchReceiveRequest,
		vaultID), requestBody)

	var incomingBatch models.Batch

	err = json.Unmarshal(requestBody, &incomingBatch)
	if err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusBadRequest, messages.InvalidBatch, err, vaultID, requestBody)
		return
	}

	responses := createInitialResponses(len(incomingBatch))

	// Validate everything at the start, so we can fail fast if need be
	err = validateBatch(incomingBatch, responses)
	if err != nil {
		writeBatchResponse(rw, messages.BatchResponseFailure, vaultID, requestBody, responses)
		return
	}

	c.executeBatchedOperations(rw, req.Host, vaultID, incomingBatch, responses, requestBody)
}

func (c *Operation) executeBatchedOperations(rw http.ResponseWriter, host, vaultID string,
	vaultOperations models.Batch, responses []string, requestBody []byte) {
	// To improve performance, we gather as many document upsert operations as we can before we hit a
	// delete operation so that we can insert them into the underlying database in one big bulk operation.
	var currentUpsertDocumentsBatch []models.EncryptedDocument

	var numOperationsCompleted int

	for vaultOperationIndex, vaultOperation := range vaultOperations {
		switch {
		case strings.EqualFold(vaultOperation.Operation, models.UpsertDocumentVaultOperation):
			currentUpsertDocumentsBatch = append(currentUpsertDocumentsBatch, vaultOperation.EncryptedDocument)
		case strings.EqualFold(vaultOperation.Operation, models.DeleteDocumentVaultOperation):
			if len(currentUpsertDocumentsBatch) > 0 {
				err := c.vaultCollection.upsertDocuments(vaultID, currentUpsertDocumentsBatch)
				if err != nil {
					for i := 0; i < len(currentUpsertDocumentsBatch); i++ {
						responses[i+numOperationsCompleted] = err.Error()
					}

					writeBatchResponse(rw, messages.BatchResponseFailure, vaultID, requestBody, responses)

					return
				}

				for i := 0; i < len(currentUpsertDocumentsBatch); i++ {
					responses[i+numOperationsCompleted] =
						getFullDocumentURL(currentUpsertDocumentsBatch[i].ID, vaultID, host)
				}

				numOperationsCompleted += len(currentUpsertDocumentsBatch)

				currentUpsertDocumentsBatch = nil // Finished with these documents, start a new batch
			}

			err := c.vaultCollection.deleteDocument(vaultOperation.DocumentID, vaultID)
			if err == nil {
				responses[vaultOperationIndex] = ""
			} else {
				responses[vaultOperationIndex] = err.Error()
				if !errors.Is(err, messages.ErrDocumentNotFound) {
					writeBatchResponse(rw, messages.BatchResponseFailure, vaultID, requestBody, responses)

					return
				}
			}

			numOperationsCompleted++
		default: // Validation check should ensure that this can't happen.
			err := fmt.Errorf("%s is not a valid vault operation", vaultOperation.Operation)
			responses[vaultOperationIndex] = err.Error()
			writeBatchResponse(rw, messages.BatchResponseFailure, vaultID, requestBody, responses)

			return
		}
	}

	c.upsertRemainingDocuments(rw, host, vaultID, currentUpsertDocumentsBatch, responses, numOperationsCompleted,
		requestBody)
}

func (c *Operation) upsertRemainingDocuments(rw http.ResponseWriter, host, vaultID string,
	currentUpsertDocumentsBatch []models.EncryptedDocument, responses []string, numOperationsCompleted int,
	requestBody []byte) {
	if len(currentUpsertDocumentsBatch) > 0 {
		err := c.vaultCollection.upsertDocuments(vaultID, currentUpsertDocumentsBatch)
		if err != nil {
			for i := 0; i < len(currentUpsertDocumentsBatch); i++ {
				responses[i+numOperationsCompleted] = err.Error()
			}

			writeBatchResponse(rw, messages.BatchResponseFailure, vaultID, requestBody, responses)

			return
		}

		for i := 0; i < len(currentUpsertDocumentsBatch); i++ {
			responses[i+numOperationsCompleted] = getFullDocumentURL(currentUpsertDocumentsBatch[i].ID, vaultID, host)
		}
	}

	writeBatchResponse(rw, messages.BatchResponseSuccess, vaultID, requestBody, responses)
}

func createInitialResponses(numResponses int) []string {
	responses := make([]string, numResponses)
	for i := range responses {
		responses[i] = "not validated or executed"
	}

	return responses
}

func validateBatch(incomingBatch models.Batch, responses []string) error {
	for i, vaultOperation := range incomingBatch {
		switch {
		case strings.EqualFold(vaultOperation.Operation, models.UpsertDocumentVaultOperation):
			if err := validateEncryptedDocument(vaultOperation.EncryptedDocument); err != nil {
				responses[i] = err.Error()
				return err
			}

			responses[i] = "validated but not executed"
		case strings.EqualFold(vaultOperation.Operation, models.DeleteDocumentVaultOperation):
			if vaultOperation.DocumentID == "" {
				err := errors.New("document ID cannot be empty for a delete operation")
				responses[i] = err.Error()

				return err
			}

			responses[i] = "validated but not executed"
		default:
			err := fmt.Errorf("%s is not a valid vault operation", vaultOperation.Operation)
			responses[i] = err.Error()

			return err
		}
	}

	return nil
}

func (vc *VaultCollection) createDataVault(vaultID string) error {
	_, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		return fmt.Errorf("failed to open store for vault: %w", err)
	}

	err = vc.provider.SetStoreConfig(vaultID, storage.StoreConfiguration{TagNames: []string{
		edvprovider.MappingDocumentTagName,
		edvprovider.MappingDocumentMatchingEncryptedDocIDTagName,
	}})
	if err != nil {
		return fmt.Errorf("failed to set store config: %w", err)
	}

	return nil
}

// storeDataVaultConfiguration stores a given DataVaultConfiguration and vaultID
func (vc *VaultCollection) storeDataVaultConfiguration(config *models.DataVaultConfiguration, vaultID string) error {
	store, err := vc.provider.OpenStore(edvprovider.VaultConfigurationStoreName)
	if err != nil {
		if errors.Is(err, storage.ErrStoreNotFound) {
			return errors.New(messages.ConfigStoreNotFound)
		}

		return fmt.Errorf("failed to open store for vault configurations: %w", err)
	}

	err = store.StoreDataVaultConfiguration(config, vaultID)
	if err != nil {
		return fmt.Errorf("failed to store data vault configuration in store: %w", err)
	}

	return nil
}

func (c *Operation) createDocument(rw http.ResponseWriter, requestBody []byte, hostURL, vaultID string) {
	var incomingDocument models.EncryptedDocument

	err := json.Unmarshal(requestBody, &incomingDocument)
	if err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusBadRequest, messages.InvalidDocumentForDocCreation, err,
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

	if err = validateEncryptedDocument(incomingDocument); err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusBadRequest, messages.InvalidDocumentForDocCreation, err,
			vaultID, requestBody)
		return
	}

	err = c.vaultCollection.createDocument(vaultID, incomingDocument)
	if err != nil {
		writeCreateDocumentFailure(rw, err, vaultID, docBytesForLog)
		return
	}

	writeCreateDocumentSuccess(rw, hostURL, vaultID, incomingDocument.ID, docBytesForLog)
}

func (vc *VaultCollection) createDocument(vaultID string, document models.EncryptedDocument) error {
	exists, err := vc.provider.StoreExists(vaultID)
	if err != nil {
		return err
	}

	if !exists {
		return messages.ErrVaultNotFound
	}

	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		return err
	}

	// The Create Document API call should not overwrite an existing document.
	// So we first check to make sure there is not already a document associated with the id.
	// If there is, we send back an error.
	_, err = store.Get(document.ID)
	if err == nil {
		return messages.ErrDuplicateDocument
	}

	if !errors.Is(err, storage.ErrDataNotFound) {
		return err
	}

	return store.Put(document)
}

func (vc *VaultCollection) upsertDocuments(vaultID string, documents []models.EncryptedDocument) error {
	exists, err := vc.provider.StoreExists(vaultID)
	if err != nil {
		return err
	}

	if !exists {
		return messages.ErrVaultNotFound
	}

	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		return err
	}

	return store.UpsertBulk(documents)
}

func (vc *VaultCollection) readDocument(vaultID, docID string) ([]byte, error) {
	exists, err := vc.provider.StoreExists(vaultID)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, messages.ErrVaultNotFound
	}

	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		return nil, err
	}

	documentBytes, err := store.Get(docID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, messages.ErrDocumentNotFound
		}

		return nil, err
	}

	return documentBytes, err
}

func (vc *VaultCollection) queryVault(vaultID string, query *models.Query) ([]models.EncryptedDocument, error) {
	exists, err := vc.provider.StoreExists(vaultID)
	if err != nil {
		return nil, err
	}

	if !exists {
		return nil, messages.ErrVaultNotFound
	}

	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		return nil, err
	}

	return store.Query(query)
}

func (c *Operation) updateDocument(rw http.ResponseWriter, requestBody []byte, docID, vaultID string) {
	var incomingDocument models.EncryptedDocument

	err := json.Unmarshal(requestBody, &incomingDocument)
	if err != nil {
		writeErrorWithVaultIDAndDocID(rw, http.StatusBadRequest, messages.InvalidDocumentForDocUpdate, err, docID, vaultID)
		return
	}

	if incomingDocument.ID != docID {
		writeErrorWithVaultIDAndDocID(rw, http.StatusBadRequest, messages.InvalidDocumentForDocUpdate,
			errors.New(messages.MismatchedDocIDs), docID, vaultID)
		return
	}

	if err = validateEncryptedDocument(incomingDocument); err != nil {
		writeErrorWithVaultIDAndDocID(rw, http.StatusBadRequest, messages.InvalidDocumentForDocUpdate, err, docID, vaultID)
		return
	}

	err = c.vaultCollection.updateDocument(docID, vaultID, incomingDocument)
	if err != nil {
		writeUpdateDocumentFailure(rw, err, docID, vaultID)
		return
	}

	logger.Debugf(messages.DebugLogEvent, fmt.Sprintf(messages.UpdateDocumentSuccess, docID, vaultID))
}

func (vc *VaultCollection) updateDocument(docID, vaultID string, document models.EncryptedDocument) error {
	exists, err := vc.provider.StoreExists(vaultID)
	if err != nil {
		return err
	}

	if !exists {
		return messages.ErrVaultNotFound
	}

	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		return err
	}

	_, err = store.Get(docID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return messages.ErrDocumentNotFound
		}

		return err
	}

	return store.Update(document)
}

func (vc *VaultCollection) deleteDocument(docID, vaultID string) error {
	exists, err := vc.provider.StoreExists(vaultID)
	if err != nil {
		return err
	}

	if !exists {
		return messages.ErrVaultNotFound
	}

	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		return err
	}

	_, err = store.Get(docID)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return messages.ErrDocumentNotFound
		}

		return err
	}

	return store.Delete(docID)
}

func validateDataVaultConfiguration(dataVaultConfig *models.DataVaultConfiguration) error {
	if err := checkConfigRequiredFields(dataVaultConfig); err != nil {
		return err
	}

	if err := edvutils.CheckIfURI(dataVaultConfig.Controller); err != nil {
		return fmt.Errorf(messages.InvalidControllerString, err)
	}

	if err := checkFieldsWithURIArray(dataVaultConfig.Invoker); err != nil {
		return fmt.Errorf(messages.InvalidInvokerStringArray, err)
	}

	if err := checkFieldsWithURIArray(dataVaultConfig.Delegator); err != nil {
		return fmt.Errorf(messages.InvalidDelegatorStringArray, err)
	}

	if err := edvutils.CheckIfURI(dataVaultConfig.KEK.ID); err != nil {
		return fmt.Errorf(messages.InvalidKEKIDString, err)
	}

	return nil
}

func checkConfigRequiredFields(config *models.DataVaultConfiguration) error {
	if config.Controller == "" {
		return errors.New(messages.BlankController)
	}

	if config.KEK.ID == "" {
		return errors.New(messages.BlankKEKID)
	}

	if config.KEK.Type == "" {
		return errors.New(messages.BlankKEKType)
	}

	if config.HMAC.ID == "" {
		return errors.New(messages.BlankHMACID)
	}

	if config.HMAC.Type == "" {
		return errors.New(messages.BlankHMACType)
	}

	return nil
}

// Check if every string in the array is a valid URI.
func checkFieldsWithURIArray(arr []string) error {
	if len(arr) == 0 {
		return nil
	}

	return edvutils.CheckIfArrayIsURI(arr)
}

func validateEncryptedDocument(doc models.EncryptedDocument) error {
	if encodingErr := edvutils.CheckIfBase58Encoded128BitValue(doc.ID); encodingErr != nil {
		return encodingErr
	}

	if err := edvutils.ValidateJWE(doc.JWE); err != nil {
		return fmt.Errorf(messages.InvalidRawJWE, err.Error())
	}

	return nil
}

func parseQuery(requestBody []byte) (models.Query, error) {
	var incomingQuery models.Query

	err := json.Unmarshal(requestBody, &incomingQuery)
	if err != nil {
		return models.Query{}, fmt.Errorf("failed to unmarshal request body: %w", err)
	}

	if incomingQuery.Has == "" {
		// See if it's an "index + equals" query instead of a "has" query.
		if incomingQuery.Name == "" || incomingQuery.Value == "" {
			return models.Query{}, errors.New("invalid query format")
		}

		// This is a valid "index + equals" query.
		return incomingQuery, nil
	}

	if incomingQuery.Name != "" || incomingQuery.Value != "" {
		return models.Query{}, errors.New(`query cannot be a mix of "index + equals" and "has" formats`)
	}

	// This is a valid "has" query.
	return incomingQuery, nil
}
