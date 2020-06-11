/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/trustbloc/edv/pkg/restapi/messages"
)

func writeCreateDataVaultRequestReadFailure(rw http.ResponseWriter, errBodyRead error) {
	logger.Errorf(messages.CreateVaultFailReadRequestBody, errBodyRead)

	rw.WriteHeader(http.StatusInternalServerError)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.CreateVaultFailReadRequestBody, errBodyRead)))
	if errWrite != nil {
		logger.Errorf(messages.CreateVaultFailReadRequestBody+messages.FailWriteResponse, errBodyRead, errWrite)
	}
}

func writeCreateDataVaultUnmarshalFailure(rw http.ResponseWriter, errUnmarshal error, receivedConfig []byte) {
	logger.Errorf(messages.InvalidVaultConfig, errUnmarshal)
	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.InvalidVaultConfig, errUnmarshal),
		receivedConfig)

	rw.WriteHeader(http.StatusBadRequest)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.InvalidVaultConfig, errUnmarshal)))
	if errWrite != nil {
		logger.Errorf(messages.InvalidVaultConfig+messages.FailWriteResponse, errUnmarshal, errWrite)
		logger.Debugf(messages.DebugLogEventWithReceivedData,
			fmt.Sprintf(messages.InvalidVaultConfig+messages.FailWriteResponse, errUnmarshal, errWrite),
			receivedConfig)
	}
}

func writeBlankReferenceIDErrMsg(rw http.ResponseWriter, configBytesForLog []byte) {
	logger.Errorf(messages.InvalidVaultConfig, messages.BlankReferenceID)
	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.InvalidVaultConfig, messages.BlankReferenceID),
		configBytesForLog)

	rw.WriteHeader(http.StatusBadRequest)

	_, err := rw.Write([]byte(fmt.Sprintf(messages.InvalidVaultConfig, messages.BlankReferenceID)))
	if err != nil {
		logger.Errorf(messages.InvalidVaultConfig+messages.FailWriteResponse, messages.BlankReferenceID, err)
		logger.Debugf(messages.DebugLogEventWithReceivedData,
			fmt.Sprintf(messages.InvalidVaultConfig+messages.FailWriteResponse, messages.BlankReferenceID, err),
			configBytesForLog)
	}
}

func writeCreateDataVaultFailure(rw http.ResponseWriter, errVaultCreation error, configBytesForLog []byte) {
	logger.Errorf(messages.VaultCreationFailure, errVaultCreation)
	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.VaultCreationFailure, errVaultCreation), configBytesForLog)

	if errVaultCreation == messages.ErrDuplicateVault {
		rw.WriteHeader(http.StatusConflict)
	} else {
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

func writeCreateDataVaultSuccess(rw http.ResponseWriter, referenceID, hostURL string, configBytesForLog []byte) {
	urlEncodedReferenceID := url.PathEscape(referenceID)

	newVaultLocation := hostURL + "/encrypted-data-vaults/" + urlEncodedReferenceID

	logger.Debugf(messages.DebugLogEventWithReceivedData,
		"Successfully created new data vault at "+newVaultLocation, configBytesForLog)

	rw.Header().Set("Location", newVaultLocation)
	rw.WriteHeader(http.StatusCreated)
}

func writeQueryResponse(rw http.ResponseWriter, matchingDocumentIDs []string, vaultID string, queryBytesForLog []byte) {
	if matchingDocumentIDs == nil {
		writeNoDocsFound(rw, vaultID, queryBytesForLog)
		return
	}

	matchingDocumentIDsBytes, err := json.Marshal(matchingDocumentIDs)
	if err != nil {
		writeErrorWithVaultID(rw, http.StatusInternalServerError, messages.FailToMarshalDocIDs, err, vaultID,
			queryBytesForLog)
		return
	}

	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.QuerySuccess+" Matching document IDs: %s", vaultID, matchingDocumentIDsBytes),
		queryBytesForLog)

	_, err = rw.Write(matchingDocumentIDsBytes)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		logger.Errorf(messages.QuerySuccess+messages.FailWriteResponse, vaultID, err)
		logger.Debugf(messages.DebugLogEventWithReceivedData,
			fmt.Sprintf(messages.QuerySuccess+messages.FailWriteResponse, vaultID, err), queryBytesForLog)
	}
}

func writeNoDocsFound(rw io.Writer, vaultID string, queryBytesForLog []byte) {
	logger.Debugf(messages.DebugLogEventWithReceivedData,
		fmt.Sprintf(messages.QueryNoMatchingDocs, vaultID),
		queryBytesForLog)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.QueryNoMatchingDocs, vaultID)))
	if errWrite != nil {
		logger.Errorf(messages.QueryNoMatchingDocs+messages.FailWriteResponse, vaultID, errWrite)
		logger.Debugf(messages.DebugLogEventWithReceivedData,
			fmt.Sprintf(messages.QueryNoMatchingDocs+messages.FailWriteResponse, vaultID, errWrite),
			queryBytesForLog)
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

func writeErrorWithVaultID(rw http.ResponseWriter, statusCode int, message string, err error, vaultID string,
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

func writePutLogSpecRequestReadFailure(rw http.ResponseWriter, errBodyRead error) {
	logger.Errorf(messages.PutLogSpecFailReadRequestBody, errBodyRead)

	rw.WriteHeader(http.StatusInternalServerError)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.PutLogSpecFailReadRequestBody, errBodyRead)))
	if errWrite != nil {
		logger.Errorf(messages.PutLogSpecFailReadRequestBody+messages.FailWriteResponse, errBodyRead, errWrite)
	}
}

// Always prints out full debug data at the "error" level, since the method that calls this one is the one
// that allows log levels to be updated. The caller may need the extra information to diagnose the issue, and of course
// won't be able to change the log level to debug until they get this working.
func writeInvalidLogSpec(rw http.ResponseWriter, err error, receivedData []byte) {
	logger.Errorf(messages.DebugLogEvent, fmt.Sprintf(messages.InvalidLogSpec, err), receivedData)

	rw.WriteHeader(http.StatusBadRequest)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.InvalidLogSpec, err)))
	if errWrite != nil {
		logger.Errorf(messages.DebugLogEvent,
			fmt.Sprintf(messages.InvalidLogSpec+messages.FailWriteResponse, err, errWrite), receivedData)
	}
}

func writePutLogSpecSuccess(rw io.Writer, requestBody []byte) {
	_, errWrite := rw.Write([]byte(messages.SetLogSpecSuccess))
	if errWrite != nil {
		logger.Errorf(messages.SetLogSpecSuccess+messages.FailWriteResponse, errWrite)
		logger.Debugf(messages.DebugLogEvent,
			fmt.Sprintf(messages.SetLogSpecSuccess+messages.FailWriteResponse, errWrite), requestBody)
	}
}
