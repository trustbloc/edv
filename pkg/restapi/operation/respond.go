/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

func writeCreateDataVaultRequestReadFailure(rw http.ResponseWriter, errBodyRead error) {
	logger.Errorf(messages.CreateVaultFailReadRequestBody, errBodyRead)

	rw.WriteHeader(http.StatusInternalServerError)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.CreateVaultFailReadRequestBody, errBodyRead)))
	if errWrite != nil {
		logger.Errorf(messages.CreateVaultFailReadRequestBody+messages.FailWriteResponse, errBodyRead, errWrite)
	}
}

func writeCreateDataVaultInvalidRequest(rw http.ResponseWriter, errInvalid error, receivedConfig []byte) {
	logger.Errorf(messages.InvalidVaultConfig, errInvalid)
	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.InvalidVaultConfig, errInvalid),
		receivedConfig)

	rw.WriteHeader(http.StatusBadRequest)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.InvalidVaultConfig, errInvalid)))
	if errWrite != nil {
		logger.Errorf(messages.InvalidVaultConfig+messages.FailWriteResponse, errInvalid, errWrite)
		logger.Debugf(messages.DebugLogEventWithReceivedData,
			fmt.Sprintf(messages.InvalidVaultConfig+messages.FailWriteResponse, errInvalid, errWrite),
			receivedConfig)
	}
}

func writeCreateDataVaultFailure(rw http.ResponseWriter, errVaultCreation error, configBytesForLog []byte) {
	logger.Errorf(messages.VaultCreationFailure, errVaultCreation)
	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.VaultCreationFailure, errVaultCreation), configBytesForLog)

	switch {
	case strings.Contains(errVaultCreation.Error(), string(messages.ErrDuplicateVault)):
		rw.WriteHeader(http.StatusConflict)
	case strings.Contains(errVaultCreation.Error(), messages.ConfigStoreNotFound):
		rw.WriteHeader(http.StatusInternalServerError)
	default:
		rw.WriteHeader(http.StatusBadRequest)
	}

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.VaultCreationFailure, errVaultCreation)))
	if errWrite != nil {
		logger.Errorf(messages.VaultCreationFailure+messages.FailWriteResponse, errVaultCreation, errWrite)
		logger.Debugf(messages.DebugLogEventWithReceivedData,
			fmt.Sprintf(messages.VaultCreationFailure+messages.FailWriteResponse, errVaultCreation, errWrite),
			configBytesForLog)
	}
}

func writeCreateDataVaultSuccess(rw http.ResponseWriter, vaultID, hostURL string,
	configBytesForLog, body []byte) {
	urlEncodedVaultID := url.PathEscape(vaultID)

	newVaultLocation := hostURL + "/encrypted-data-vaults/" + urlEncodedVaultID

	logger.Debugf(messages.DebugLogEventWithReceivedData,
		"Successfully created new data vault at "+newVaultLocation, configBytesForLog)

	rw.Header().Set("Location", newVaultLocation)
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusCreated)

	if _, err := rw.Write(body); err != nil {
		logger.Errorf(err.Error())
	}
}

func writeQueryResponse(rw http.ResponseWriter, matchingDocuments []models.EncryptedDocument, vaultID string,
	queryBytesForLog []byte, returnFullDocument bool, host string) {
	if returnFullDocument {
		writeQueryResponseWithFullDocuments(rw, matchingDocuments, vaultID, queryBytesForLog)
	} else {
		writeQueryResponseWithDocumentIDs(rw, matchingDocuments, vaultID, queryBytesForLog, host)
	}
}

func writeQueryResponseWithDocumentIDs(rw http.ResponseWriter, matchingDocuments []models.EncryptedDocument,
	vaultID string, queryBytesForLog []byte, host string) {
	var matchingDocumentIDs []string

	for _, matchingDocument := range matchingDocuments {
		matchingDocumentIDs = append(matchingDocumentIDs, matchingDocument.ID)
	}

	fullDocumentURLs := convertToFullDocumentURLs(matchingDocumentIDs, vaultID, host)

	fullDocumentURLsBytes, err := json.Marshal(fullDocumentURLs)
	if err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusInternalServerError, messages.FailToMarshalDocIDs,
			err, vaultID, queryBytesForLog)
		return
	}

	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.QuerySuccess+" Matching document URLs: %s", vaultID, fullDocumentURLsBytes),
		queryBytesForLog)

	_, err = rw.Write(fullDocumentURLsBytes)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		logger.Errorf(messages.QuerySuccess+messages.FailWriteResponse, vaultID, err)
		logger.Debugf(messages.DebugLogEventWithReceivedData,
			fmt.Sprintf(messages.QuerySuccess+messages.FailWriteResponse, vaultID, err), queryBytesForLog)
	}
}

func writeQueryResponseWithFullDocuments(rw http.ResponseWriter, matchingDocuments []models.EncryptedDocument,
	vaultID string, queryBytesForLog []byte) {
	matchingDocumentsBytes, err := json.Marshal(matchingDocuments)
	if err != nil {
		writeErrorWithVaultIDAndReceivedData(rw, http.StatusInternalServerError, messages.FailToMarshalDocuments,
			err, vaultID, queryBytesForLog)
		return
	}

	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.QuerySuccess+" Matching documents: %s", vaultID, matchingDocumentsBytes),
		queryBytesForLog)

	_, err = rw.Write(matchingDocumentsBytes)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		logger.Errorf(messages.QuerySuccess+messages.FailWriteResponse, vaultID, err)
		logger.Debugf(messages.DebugLogEventWithReceivedData,
			fmt.Sprintf(messages.QuerySuccess+messages.FailWriteResponse, vaultID, err), queryBytesForLog)
	}
}

func writeCreateDocumentFailure(rw http.ResponseWriter, errCreateDoc error, vaultID string, docBytesForLog []byte) {
	logger.Errorf(messages.CreateDocumentFailure, vaultID, errCreateDoc)
	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.CreateDocumentFailure, vaultID, errCreateDoc),
		docBytesForLog)

	if errCreateDoc == messages.ErrDuplicateDocument {
		rw.WriteHeader(http.StatusConflict)
	} else {
		rw.WriteHeader(http.StatusBadRequest)
	}

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.CreateDocumentFailure, vaultID, errCreateDoc)))
	if errWrite != nil {
		logger.Errorf(messages.CreateDocumentFailure+messages.FailWriteResponse, vaultID, errCreateDoc, errWrite)
		logger.Debugf(messages.DebugLogEventWithReceivedData,
			fmt.Sprintf(messages.CreateDocumentFailure+messages.FailWriteResponse, vaultID, errCreateDoc, errWrite),
			docBytesForLog)
	}
}

func writeCreateDocumentSuccess(rw http.ResponseWriter, host, vaultID, docID string, docBytesForLog []byte) {
	newDocLocation := host + "/encrypted-data-vaults/" +
		url.PathEscape(vaultID) + "/documents/" + url.PathEscape(docID)

	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.CreateDocumentSuccess, vaultID, newDocLocation),
		docBytesForLog)

	rw.Header().Set("Location", newDocLocation)
	rw.WriteHeader(http.StatusCreated)
}

func writeErrorWithVaultID(rw http.ResponseWriter, statusCode int, message string, err error, vaultID string) {
	logger.Errorf(message, vaultID, err)
	logger.Debugf(messages.DebugLogEvent, fmt.Sprintf(message, vaultID, err))

	rw.WriteHeader(statusCode)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(message, vaultID, err)))
	if errWrite != nil {
		logger.Errorf(message+messages.FailWriteResponse, vaultID, err, errWrite)
		logger.Debugf(messages.DebugLogEvent,
			fmt.Sprintf(message+messages.FailWriteResponse, vaultID, err, errWrite))
	}
}

func writeErrorWithVaultIDAndReceivedData(rw http.ResponseWriter, statusCode int, message string,
	err error, vaultID string,
	receivedData []byte) {
	logger.Errorf(message, vaultID, err)
	logger.Debugf(messages.DebugLogEventWithReceivedData, fmt.Sprintf(message, vaultID, err), receivedData)

	rw.WriteHeader(statusCode)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(message, vaultID, err)))
	if errWrite != nil {
		logger.Errorf(message+messages.FailWriteResponse, vaultID, err, errWrite)
		logger.Debugf(messages.DebugLogEventWithReceivedData,
			fmt.Sprintf(message+messages.FailWriteResponse, vaultID, err, errWrite),
			receivedData)
	}
}

func writeErrorWithVaultIDAndDocID(rw http.ResponseWriter, statusCode int, message string, err error,
	docID, vaultID string) {
	logger.Errorf(message, docID, vaultID, err)

	rw.WriteHeader(statusCode)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(message, docID, vaultID, err)))
	if errWrite != nil {
		logger.Errorf(message+messages.FailWriteResponse, docID, vaultID, err, errWrite)
	}
}

func writeReadAllDocumentsFailure(rw http.ResponseWriter, errReadDoc error, vaultID string) {
	logger.Infof(messages.ReadAllDocumentsFailure, vaultID, errReadDoc)

	if errors.Is(errReadDoc, messages.ErrVaultNotFound) {
		rw.WriteHeader(http.StatusNotFound)
	} else {
		rw.WriteHeader(http.StatusInternalServerError)
	}

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.ReadAllDocumentsFailure, vaultID, errReadDoc)))
	if errWrite != nil {
		logger.Errorf(messages.ReadAllDocumentsFailure+messages.FailWriteResponse, vaultID, errReadDoc, errWrite)
	}
}

func writeReadAllDocumentsSuccess(rw http.ResponseWriter, allDocuments []json.RawMessage, vaultID string) {
	logger.Debugf(messages.DebugLogEvent,
		fmt.Sprintf(messages.ReadAllDocumentsSuccessWithRetrievedDocs, vaultID, allDocuments))

	allDocumentsMarshalled, err := json.Marshal(allDocuments)
	if err != nil {
		writeErrorWithVaultID(rw, http.StatusInternalServerError, messages.FailToMarshalAllDocuments, err, vaultID)
		return
	}

	_, errWrite := rw.Write(allDocumentsMarshalled)
	if errWrite != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		logger.Errorf(messages.ReadAllDocumentsSuccess+messages.FailWriteResponse, vaultID, errWrite)
		logger.Debugf(messages.DebugLogEvent,
			fmt.Sprintf(messages.ReadAllDocumentsSuccessWithRetrievedDocs+messages.FailWriteResponse,
				vaultID, errWrite, allDocuments))
	}
}

func writeReadDocumentFailure(rw http.ResponseWriter, errReadDoc error, docID, vaultID string) {
	logger.Infof(messages.ReadDocumentFailure, docID, vaultID, errReadDoc)

	if errReadDoc == messages.ErrDocumentNotFound || errReadDoc == messages.ErrVaultNotFound {
		rw.WriteHeader(http.StatusNotFound)
	} else {
		rw.WriteHeader(http.StatusBadRequest)
	}

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.ReadDocumentFailure, docID, vaultID, errReadDoc)))
	if errWrite != nil {
		logger.Errorf(messages.ReadDocumentFailure+messages.FailWriteResponse, docID, vaultID, errReadDoc, errWrite)
	}
}

func writeReadDocumentSuccess(rw http.ResponseWriter, documentBytes []byte, docID, vaultID string) {
	logger.Debugf(messages.DebugLogEvent,
		fmt.Sprintf(messages.ReadDocumentSuccessWithRetrievedDoc, docID, vaultID, documentBytes))

	_, errWrite := rw.Write(documentBytes)
	if errWrite != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		logger.Errorf(messages.ReadDocumentSuccess+messages.FailWriteResponse, docID, vaultID, errWrite)
		logger.Debugf(messages.DebugLogEvent,
			fmt.Sprintf(messages.ReadDocumentSuccessWithRetrievedDoc+messages.FailWriteResponse,
				docID, vaultID, errWrite, documentBytes))
	}
}

func writeUpdateDocumentFailure(rw http.ResponseWriter, errUpdateDoc error, docID, vaultID string) {
	logger.Infof(messages.UpdateDocumentFailure, docID, vaultID, errUpdateDoc)

	if errUpdateDoc == messages.ErrDocumentNotFound || errUpdateDoc == messages.ErrVaultNotFound {
		rw.WriteHeader(http.StatusNotFound)
	} else {
		rw.WriteHeader(http.StatusBadRequest)
	}

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.UpdateDocumentFailure, docID, vaultID, errUpdateDoc)))
	if errWrite != nil {
		logger.Errorf(messages.UpdateDocumentFailure+messages.FailWriteResponse, docID, vaultID, errUpdateDoc, errWrite)
	}
}

func writeDeleteDocumentFailure(rw http.ResponseWriter, errDeleteDoc error, docID, vaultID string) {
	logger.Infof(messages.DeleteDocumentFailure, docID, vaultID, errDeleteDoc)

	if errDeleteDoc == messages.ErrDocumentNotFound || errDeleteDoc == messages.ErrVaultNotFound {
		rw.WriteHeader(http.StatusNotFound)
	} else {
		rw.WriteHeader(http.StatusBadRequest)
	}

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.DeleteDocumentFailure, docID, vaultID, errDeleteDoc)))
	if errWrite != nil {
		logger.Errorf(messages.DeleteDocumentFailure+messages.FailWriteResponse, docID, vaultID, errDeleteDoc, errWrite)
	}
}
