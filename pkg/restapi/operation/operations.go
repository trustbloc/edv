/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	log "github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/internal/common/support"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	edvCommonEndpointPathRoot = "/encrypted-data-vaults"
	vaultIDPathVariable       = "vaultID"
	docIDPathVariable         = "docID"

	createVaultEndpoint    = edvCommonEndpointPathRoot
	queryVaultEndpoint     = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/queries"
	createDocumentEndpoint = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/documents"
	readDocumentEndpoint   = edvCommonEndpointPathRoot + "/{" + vaultIDPathVariable + "}/documents/{" +
		docIDPathVariable + "}"
	logSpecEndpoint = edvCommonEndpointPathRoot + "/logspec"
)

var logger = log.New("restapi")

// Operation defines handler logic for the EDV service.
type Operation struct {
	handlers        []Handler
	vaultCollection VaultCollection
	stringBuilder   func() stringBuilder
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

type stringBuilder interface {
	Write(p []byte) (int, error)
	String() string
	Reset()
}

type moduleLevelPair struct {
	module   string
	logLevel log.Level
}

// New returns a new EDV operations instance.
func New(provider edvprovider.EDVProvider) *Operation {
	svc := &Operation{
		vaultCollection: VaultCollection{
			provider: provider,
		},
		stringBuilder: func() stringBuilder { return &strings.Builder{} }}
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
		support.NewHTTPHandler(logSpecEndpoint, http.MethodPut, c.logSpecPutHandler),
		support.NewHTTPHandler(logSpecEndpoint, http.MethodGet, c.logSpecGetHandler),
	}
}

// GetRESTHandlers gets all controller API handler available for this service.
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}

func (c *Operation) createDataVaultHandler(rw http.ResponseWriter, req *http.Request) {
	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writeCreateDataVaultRequestReadFailure(rw, err)
		return
	}

	var config models.DataVaultConfiguration

	err = json.Unmarshal(requestBody, &config)
	if err != nil {
		writeCreateDataVaultUnmarshalFailure(rw, err)
		return
	}

	c.createDataVault(rw, &config, req.Host)
}

func (c *Operation) createDataVault(rw http.ResponseWriter, config *models.DataVaultConfiguration, hostURL string) {
	if config.ReferenceID == "" {
		writeBlankReferenceIDErrMsg(rw)
		return
	}

	err := c.vaultCollection.createDataVault(config.ReferenceID)
	if err != nil {
		writeCreateDataVaultFailure(rw, err)
		return
	}

	writeCreateDataVaultSuccess(rw, config.ReferenceID, hostURL)
}

func (c *Operation) queryVaultHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writeErrorWithVaultID(rw, http.StatusInternalServerError, messages.QueryFailReadRequestBody, err, vaultID)
		return
	}

	var incomingQuery models.Query

	err = json.Unmarshal(requestBody, &incomingQuery)
	if err != nil {
		writeErrorWithVaultID(rw, http.StatusBadRequest, messages.InvalidQuery, err, vaultID)
		return
	}

	matchingDocumentIDs, err := c.vaultCollection.queryVault(vaultID, &incomingQuery)
	if err != nil {
		writeErrorWithVaultID(rw, http.StatusBadRequest, messages.QueryFailure, err, vaultID)
		return
	}

	fullDocumentURLs := convertToFullDocumentURLs(matchingDocumentIDs, vaultID, req)

	writeQueryResponse(rw, fullDocumentURLs, vaultID)
}

func (c *Operation) createDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		writeErrorWithVaultID(rw, http.StatusInternalServerError, messages.CreateDocumentFailReadRequestBody,
			err, vaultID)
		return
	}

	var incomingDocument models.EncryptedDocument

	err = json.Unmarshal(requestBody, &incomingDocument)
	if err != nil {
		writeErrorWithVaultID(rw, http.StatusBadRequest, messages.InvalidDocument, err, vaultID)
		return
	}

	err = c.vaultCollection.createDocument(vaultID, incomingDocument)
	if err != nil {
		writeCreateDocumentFailure(rw, err, vaultID)
		return
	}

	writeCreateDocumentSuccess(rw, req.Host, vaultID, incomingDocument.ID)
}

func (c *Operation) readDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	docID, success := unescapePathVar(docIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	documentBytes, err := c.vaultCollection.readDocument(vaultID, docID)
	if err != nil {
		writeReadDocumentFailure(rw, err, docID, vaultID)
		return
	}

	writeReadDocumentSuccess(rw, documentBytes, docID, vaultID)
}

// Note that this will not work properly if a module name contains an '=' character.
func (c *Operation) logSpecPutHandler(rw http.ResponseWriter, req *http.Request) {
	incomingLogSpec := models.LogSpec{}

	err := json.NewDecoder(req.Body).Decode(&incomingLogSpec)
	if err != nil {
		writeInvalidLogSpec(rw)
		return
	}

	logLevelByModule := strings.Split(incomingLogSpec.Spec, ":")

	defaultLogLevel := log.Level(-1)

	var moduleLevelPairs []moduleLevelPair

	for _, logLevelByModulePart := range logLevelByModule {
		if strings.Contains(logLevelByModulePart, "=") {
			moduleAndLevelPair := strings.Split(logLevelByModulePart, "=")

			logLevel, parseErr := log.ParseLevel(moduleAndLevelPair[1])
			if parseErr != nil {
				writeInvalidLogSpec(rw)
				return
			}

			moduleLevelPairs = append(moduleLevelPairs,
				moduleLevelPair{moduleAndLevelPair[0], logLevel})
		} else {
			if defaultLogLevel != -1 {
				// The given log spec is formatted incorrectly; it contains multiple default values.
				writeInvalidLogSpec(rw)
				return
			}
			var parseErr error

			defaultLogLevel, parseErr = log.ParseLevel(logLevelByModulePart)
			if parseErr != nil {
				writeInvalidLogSpec(rw)
				return
			}
		}
	}

	if defaultLogLevel != -1 {
		log.SetLevel("", defaultLogLevel)
	}

	for _, moduleLevelPair := range moduleLevelPairs {
		log.SetLevel(moduleLevelPair.module, moduleLevelPair.logLevel)
	}

	_, err = rw.Write([]byte(messages.SetLogSpecSuccess))
	if err != nil {
		logger.Errorf(messages.SetLogSpecSuccess+messages.FailWriteResponse, err)
	}
}

func (c *Operation) logSpecGetHandler(rw http.ResponseWriter, _ *http.Request) {
	logLevels := log.GetAllLevels()

	var defaultDebugLevel string

	response := c.stringBuilder()

	for module, level := range logLevels {
		if module == "" {
			defaultDebugLevel = log.ParseString(level)
		} else {
			_, err := response.Write([]byte(module + "=" + log.ParseString(level) + ":"))
			if err != nil {
				rw.WriteHeader(http.StatusInternalServerError)
				logger.Errorf(messages.GetLogSpecPrepareErrMsg, err)

				return
			}
		}
	}

	_, err := response.Write([]byte(defaultDebugLevel))
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		logger.Errorf(messages.GetLogSpecPrepareErrMsg, err)

		return
	}

	_, err = rw.Write([]byte(response.String()))
	if err != nil {
		logger.Errorf(messages.GetLogSpecSuccess+messages.FailWriteResponse, err)
	}
}

func (vc *VaultCollection) createDataVault(vaultID string) error {
	err := vc.provider.CreateStore(vaultID)
	if err == storage.ErrDuplicateStore {
		return messages.ErrDuplicateVault
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

func (vc *VaultCollection) createDocument(vaultID string, document models.EncryptedDocument) error {
	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		if err == storage.ErrStoreNotFound {
			return messages.ErrVaultNotFound
		}

		return err
	}

	if encodingErr := checkIfBase58Encoded128BitValue(document.ID); encodingErr != nil {
		return encodingErr
	}

	// The Create Document API call should not overwrite an existing document.
	// So we first check to make sure there is not already a document associated with the id.
	// If there is, we send back an error.
	_, err = store.Get(document.ID)
	if err == nil {
		return messages.ErrDuplicateDocument
	}

	if err != storage.ErrValueNotFound {
		return err
	}

	return store.Put(document)
}

func (vc *VaultCollection) readDocument(vaultID, docID string) ([]byte, error) {
	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		if err == storage.ErrStoreNotFound {
			return nil, messages.ErrVaultNotFound
		}

		return nil, err
	}

	documentBytes, err := store.Get(docID)
	if err != nil {
		if err == storage.ErrValueNotFound {
			return nil, messages.ErrDocumentNotFound
		}

		return nil, err
	}

	return documentBytes, err
}

func (vc *VaultCollection) queryVault(vaultID string, query *models.Query) ([]string, error) {
	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		if err == storage.ErrStoreNotFound {
			return nil, messages.ErrVaultNotFound
		}

		return nil, err
	}

	return store.Query(query)
}
