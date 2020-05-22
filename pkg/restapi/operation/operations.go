/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/btcsuite/btcutil/base58"
	"github.com/gorilla/mux"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/internal/common/support"
	"github.com/trustbloc/edv/pkg/restapi/edverrors"
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
)

var logger = log.New("edv/pkg/restapi")

// Handler http handler for each controller API endpoint
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

// Operation defines handlers for EDV service
type Operation struct {
	handlers        []Handler
	vaultCollection VaultCollection
}

// VaultCollection represents EDV storage.
type VaultCollection struct {
	provider edvprovider.EDVProvider
}

func (c *Operation) createDataVaultHandler(rw http.ResponseWriter, req *http.Request) {
	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf(`Received request to create a new data vault, but failed to read request body: %s`, err)
	}

	logger.Infof(`Received request to create a new data vault.
Request body: ` + string(requestBody))

	var config models.DataVaultConfiguration

	err = json.Unmarshal(requestBody, &config)
	if err != nil {
		writeCreateDataVaultUnmarshalFailure(rw, requestBody, err)

		return
	}

	c.createDataVault(rw, &config, req.Host)
}

func writeCreateDataVaultUnmarshalFailure(rw http.ResponseWriter, requestBody []byte, unmarshalErr error) {
	logger.Errorf(`Received invalid data vault configuration. 
Received data: %s
Error: %s`, requestBody, unmarshalErr)

	rw.WriteHeader(http.StatusBadRequest)

	_, writeErr := rw.Write([]byte(fmt.Sprintf("Invalid data vault configuration received: %s", unmarshalErr)))
	if writeErr != nil {
		logger.Errorf(`Received invalid data vault configuration. `+
			`Failed to write response back to sender.
Received data: %s
Error: %s`, requestBody, writeErr)
	}
}

func (c *Operation) createDataVault(rw http.ResponseWriter, config *models.DataVaultConfiguration, hostURL string) {
	configBytesForLog, err := json.Marshal(config)
	if err != nil {
		writeCreateDataVaultMarshalForLogFailure(rw, err)

		return
	}

	if config.ReferenceID == "" {
		writeBlankReferenceIDErrMsg(rw, configBytesForLog)

		return
	}

	err = c.vaultCollection.createDataVault(config.ReferenceID)
	if err != nil {
		writeCreateDataVaultFailure(rw, configBytesForLog, err)

		return
	}

	logger.Infof("Created a new data vault with the following configuration: %s", configBytesForLog)

	urlEncodedReferenceID := url.PathEscape(config.ReferenceID)

	rw.Header().Set("Location", hostURL+"/encrypted-data-vaults/"+urlEncodedReferenceID)
	rw.WriteHeader(http.StatusCreated)
}

func writeCreateDataVaultMarshalForLogFailure(rw http.ResponseWriter, marshalErr error) {
	logger.Errorf("Newly unmarshalled data vault configuration could not be marshalled for logging: %s",
		marshalErr)

	rw.WriteHeader(http.StatusBadRequest)

	_, writeErr := rw.Write([]byte(fmt.Sprintf("Newly unmarshalled data vault configuration "+
		"could not be marshalled for logging: %s", marshalErr)))
	if writeErr != nil {
		logger.Errorf(`Failed to write the "Newly unmarshalled data vault configuration could not `+
			`be marshalled for logging: %s" message back to the sender: %s`, marshalErr, writeErr)
	}
}

func writeBlankReferenceIDErrMsg(rw http.ResponseWriter, configBytesForLog []byte) {
	logger.Errorf(`Received invalid data vault configuration. 
Received data: %s
Error: %s`, configBytesForLog, edverrors.BlankReferenceIDErrMsg)

	rw.WriteHeader(http.StatusBadRequest)

	_, err := rw.Write([]byte(fmt.Sprintf("Invalid data vault configuration: %s", edverrors.BlankReferenceIDErrMsg)))
	if err != nil {
		logger.Errorf(`Received invalid data vault configuration: %s. `+
			`Failed to write response back to sender.
Received data: %s
Error: %s`, edverrors.BlankReferenceIDErrMsg, configBytesForLog, err)
	}
}

func writeCreateDataVaultFailure(rw http.ResponseWriter, configBytesForLog []byte, err error) {
	logger.Errorf(fmt.Sprintf(`Failed to create a new data vault.
Data vault configuration: %s
Error: %s`, configBytesForLog, err))

	if err == edverrors.ErrDuplicateVault {
		rw.WriteHeader(http.StatusConflict)
	} else {
		rw.WriteHeader(http.StatusBadRequest)
	}

	_, err = rw.Write([]byte(fmt.Sprintf("Data vault creation failed: %s", err)))
	if err != nil {
		logger.Errorf(`Failed to create a new data vault. `+
			`Failed to write response to sender.
Data vault configuration: %s
Error: %s`, configBytesForLog, err)
	}
}

func (c *Operation) queryVaultHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf(`Received request to query data vault "%s", but failed to read request body: %s`, vaultID, err)
	}

	logger.Infof(`Received request to query data vault "%s".
Query: %s`, vaultID, string(requestBody))

	var incomingQuery models.Query

	err = json.Unmarshal(requestBody, &incomingQuery)
	if err != nil {
		writeQueryUnmarshalFailure(rw, vaultID, requestBody, err)

		return
	}

	queryBytesForLog, err := json.Marshal(incomingQuery)
	if err != nil {
		writeQueryVaultMarshalForLogFailure(rw, vaultID, err)

		return
	}

	matchingDocumentIDs, err := c.vaultCollection.queryVault(vaultID, &incomingQuery)
	if err != nil {
		writeQueryVaultFailure(rw, queryBytesForLog, err)

		return
	}

	fullDocumentURLs := convertToFullDocumentURLs(matchingDocumentIDs, vaultID, req)

	sendQueryResponse(rw, fullDocumentURLs, vaultID, queryBytesForLog)
}

func writeQueryVaultFailure(rw http.ResponseWriter, queryBytesForLog []byte, err error) {
	logger.Errorf(`Failure while querying vault.
Query: %s
Error: %s`, queryBytesForLog, err)

	rw.WriteHeader(http.StatusBadRequest)

	_, err = rw.Write([]byte(fmt.Sprintf("Failure while querying vault: %s", err)))
	if err != nil {
		logger.Errorf(`Failure while querying vault. Failed to write response to sender.
Query: %s
Error: %s`, queryBytesForLog, err)
	}
}

func writeQueryVaultMarshalForLogFailure(rw http.ResponseWriter, vaultID string, err error) {
	logger.Errorf(`Newly unmarshalled query for data vault "%s" could not be marshalled for logging: %s`,
		vaultID, err)

	rw.WriteHeader(http.StatusBadRequest)

	_, writeErr := rw.Write([]byte(fmt.Sprintf(`Newly unmarshalled query for data vault "%s" `+
		`could not be marshalled for logging: %s`, vaultID, err)))
	if writeErr != nil {
		logger.Errorf(`Failed to write the "Newly unmarshalled query for data vault "%s" `+
			`could not be marshalled for logging: %s" message back to the sender: %s`, vaultID, err, writeErr)
	}
}

func writeQueryUnmarshalFailure(rw http.ResponseWriter, vaultID string, requestBody []byte, err error) {
	logger.Errorf(`Received invalid query for data vault "%s". 
Query: %s
Error: %s`, vaultID, requestBody, err)

	rw.WriteHeader(http.StatusBadRequest)

	_, err = rw.Write([]byte(fmt.Sprintf("Invalid query received: %s", err)))
	if err != nil {
		logger.Errorf(`Received invalid query for data vault "%s". Failed to write response to sender.
Query: %s
Error: %s`, requestBody, err)
	}
}

func (c *Operation) createDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	vaultID, success := unescapePathVar(vaultIDPathVariable, mux.Vars(req), rw)
	if !success {
		return
	}

	requestBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		logger.Errorf(`Received request to create a new document in data vault "%s", `+
			`but failed to read request body: %s`, vaultID, err)
	}

	logger.Infof(`Received a request to create a document in vault "%s".
Received document: %s`, vaultID, string(requestBody))

	var incomingDocument models.EncryptedDocument

	err = json.Unmarshal(requestBody, &incomingDocument)
	if err != nil {
		writeDocumentUnmarshalFailure(rw, vaultID, requestBody, err)

		return
	}

	incomingDocumentBytesForLog, err := json.Marshal(incomingDocument)
	if err != nil {
		writeCreateDocumentMarshalForLogFailure(rw, vaultID, err)

		return
	}

	err = c.vaultCollection.createDocument(vaultID, incomingDocument)
	if err != nil {
		writeCreateDocumentFailure(rw, vaultID, incomingDocumentBytesForLog, err)

		return
	}

	logger.Infof(`The following document has been successfully stored in vault "%s": %s `,
		vaultID, incomingDocumentBytesForLog)

	rw.Header().Set("Location", req.Host+"/encrypted-data-vaults/"+
		url.PathEscape(vaultID)+"/documents/"+url.PathEscape(incomingDocument.ID))
	rw.WriteHeader(http.StatusCreated)
}

func writeDocumentUnmarshalFailure(rw http.ResponseWriter, vaultID string, requestBody []byte, err error) {
	logger.Errorf(`Received a request to create a document in vault "%s", but the document is invalid. 
Received document: %s
Error: %s`, vaultID, requestBody, err)

	rw.WriteHeader(http.StatusBadRequest)

	_, err = rw.Write([]byte(fmt.Sprintf("Invalid encrypted document received: %s", err)))
	if err != nil {
		logger.Errorf(`Received a request to create a document in vault "%s", `+
			`but the document is invalid. Failed to write response to sender. 
Received document: %s
Error: %s`, vaultID, requestBody, err)
	}
}

func writeCreateDocumentMarshalForLogFailure(rw http.ResponseWriter, vaultID string, err error) {
	logger.Errorf(`Newly unmarshalled encrypted document destined for vault "%s" `+
		`could not be marshalled for logging: %s`, vaultID, err)

	rw.WriteHeader(http.StatusBadRequest)

	_, writeErr := rw.Write([]byte(fmt.Sprintf(`Newly unmarshalled encrypted document destined for vault "%s" `+
		`could not be marshalled for logging: %s`, vaultID, err)))
	if writeErr != nil {
		logger.Errorf(`Failed to write the "Newly unmarshalled encrypted document destined for vault "%s" `+
			`could not be marshalled for logging: %s" message back to the sender: %s`, vaultID, err, writeErr)
	}
}

func writeCreateDocumentFailure(rw http.ResponseWriter, vaultID string, incomingDocumentBytesForLog []byte, err error) {
	logger.Errorf(`Failure while creating document in vault "%s".
Received document: %s
Error: %s`, vaultID, incomingDocumentBytesForLog, err)

	if err == edverrors.ErrDuplicateDocument {
		rw.WriteHeader(http.StatusConflict)
	} else {
		rw.WriteHeader(http.StatusBadRequest)
	}

	_, err = rw.Write([]byte(err.Error()))
	if err != nil {
		logger.Errorf(
			`Failure while creating document in vault "%s". Failed to write response to sender.
Received document: %s
Error: %s`, vaultID, incomingDocumentBytesForLog, err)
	}
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
		if err == edverrors.ErrDocumentNotFound || err == edverrors.ErrVaultNotFound {
			rw.WriteHeader(http.StatusNotFound)
		} else {
			rw.WriteHeader(http.StatusBadRequest)
		}

		_, err = rw.Write([]byte(fmt.Sprintf(`Failed to read document "%s" in vault "%s".
Error: %s`, docID, vaultID, err)))
		if err != nil {
			logger.Errorf(`Failed to read document "%s" in vault "%s". Failed to write response to sender.
Error: %s`, docID, vaultID, err)
		}

		return
	}

	logger.Infof(`Successfully retrieved document "%s" from vault "%s".
Retrieved document: %s`, docID, vaultID, documentBytes)

	_, err = rw.Write(documentBytes)
	if err != nil {
		logger.Errorf(`Successfully retrieved document "%s" in vault "%s", `+
			`but failed to write response to sender.
Error: %s`, docID, vaultID, err)
	}
}

func (vc *VaultCollection) createDataVault(vaultID string) error {
	err := vc.provider.CreateStore(vaultID)
	if err == storage.ErrDuplicateStore {
		return edverrors.ErrDuplicateVault
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
			return edverrors.ErrVaultNotFound
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
		return edverrors.ErrDuplicateDocument
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
			return nil, edverrors.ErrVaultNotFound
		}

		return nil, err
	}

	documentBytes, err := store.Get(docID)
	if err != nil {
		if err == storage.ErrValueNotFound {
			return nil, edverrors.ErrDocumentNotFound
		}

		return nil, err
	}

	return documentBytes, err
}

func (vc *VaultCollection) queryVault(vaultID string, query *models.Query) ([]string, error) {
	store, err := vc.provider.OpenStore(vaultID)
	if err != nil {
		if err == storage.ErrStoreNotFound {
			return nil, edverrors.ErrVaultNotFound
		}

		return nil, err
	}

	return store.Query(query)
}

// This function can't tell if the value before being encoded was precisely 128 bits long.
// This is because the byte58.decode function returns an array of bytes, not just a string of bits.
// So the closest I can do is see if the decoded byte array is 16 bytes long,
// however this means that if the original value was 121 bits to 127 bits long it'll still be accepted.
func checkIfBase58Encoded128BitValue(id string) error {
	decodedBytes := base58.Decode(id)
	if len(decodedBytes) == 0 {
		return edverrors.ErrNotBase58Encoded
	}

	if len(decodedBytes) != 16 {
		return edverrors.ErrNot128BitValue
	}

	return nil
}

func sendQueryResponse(rw http.ResponseWriter, matchingDocumentIDs []string, vaultID string, queryBytesForLog []byte) {
	if matchingDocumentIDs == nil {
		logger.Infof(`Successfully queried data vault %s, but no matching documents were found.
Query: %s`, vaultID, queryBytesForLog)

		_, err := rw.Write([]byte("no matching documents found"))
		if err != nil {
			logger.Errorf(`Successfully queried data vault %s, but no matching documents were found. `+
				`Failed to write response to sender.
Query: %s`, vaultID, queryBytesForLog)
		}

		return
	}

	matchingDocumentIDsBytes, err := json.Marshal(matchingDocumentIDs)
	if err != nil {
		logger.Errorf(`Successfully queried data vault %s, `+
			`but failed to marshal the matching document IDs into bytes. 
Query: %s
Error: %s`, vaultID, queryBytesForLog, err)
		rw.WriteHeader(http.StatusInternalServerError)

		_, err = rw.Write([]byte(fmt.Sprintf(
			"Failed to marshal the matching document IDs into bytes: %s", err)))
		if err != nil {
			logger.Errorf(`Successfully queried data vault %s, `+
				`but failed to marshal the matching document IDs into bytes. Failed to write response to sender.
Query: %s
Error: %s`, vaultID, queryBytesForLog, err)
		}

		return
	}

	logger.Infof(`Successfully queried data vault %s. 
Query: %s
Matching document IDs: %s`,
		vaultID, queryBytesForLog, matchingDocumentIDsBytes)

	_, err = rw.Write(matchingDocumentIDsBytes)
	if err != nil {
		logger.Errorf(`Successfully queried data vault %s. Failed to write response to sender. 
Query: %s
Matching document IDs: %s`, vaultID, queryBytesForLog, err)
	}
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (c *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	c.handlers = []Handler{
		support.NewHTTPHandler(createVaultEndpoint, http.MethodPost, c.createDataVaultHandler),
		support.NewHTTPHandler(queryVaultEndpoint, http.MethodPost, c.queryVaultHandler),
		support.NewHTTPHandler(createDocumentEndpoint, http.MethodPost, c.createDocumentHandler),
		support.NewHTTPHandler(readDocumentEndpoint, http.MethodGet, c.readDocumentHandler),
	}
}

// GetRESTHandlers get all controller API handler available for this service
func (c *Operation) GetRESTHandlers() []Handler {
	return c.handlers
}

// Unescapes the given path variable from the vars map and writes a response if any failure occurs.
// Returns the unescaped version of the path variable and a bool indicating whether the unescaping was successful.
func unescapePathVar(pathVar string, vars map[string]string, rw http.ResponseWriter) (string, bool) {
	unescapedPathVar, err := url.PathUnescape(vars[pathVar])
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)

		_, err = rw.Write([]byte(fmt.Sprintf("unable to escape %s path variable: %s", pathVar, err)))
		if err != nil {
			logger.Errorf("Failed to write response for %s unescaping failure: %s", pathVar, err)
		}

		return "", false
	}

	return unescapedPathVar, true
}

func convertToFullDocumentURLs(documentIDs []string, vaultID string, req *http.Request) []string {
	fullDocumentURLs := make([]string, len(documentIDs))

	for i, matchingDocumentID := range documentIDs {
		fullDocumentURLs[i] = req.Host + "/encrypted-data-vaults/" +
			url.PathEscape(vaultID) + "/documents/" + url.PathEscape(matchingDocumentID)
	}

	return fullDocumentURLs
}
