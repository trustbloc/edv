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
	rw.WriteHeader(http.StatusInternalServerError)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.CreateVaultFailReadResponseBody, errBodyRead)))
	if errWrite != nil {
		logger.Errorf(messages.CreateVaultFailReadResponseBody+messages.FailWriteResponse, errBodyRead, errWrite)
	}
}

func writeCreateDataVaultUnmarshalFailure(rw http.ResponseWriter, errUnmarshal error) {
	rw.WriteHeader(http.StatusBadRequest)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.InvalidVaultConfig, errUnmarshal)))
	if errWrite != nil {
		logger.Errorf(messages.InvalidVaultConfig+messages.FailWriteResponse, errUnmarshal, errWrite)
	}
}

func writeBlankReferenceIDErrMsg(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusBadRequest)

	_, err := rw.Write([]byte(messages.BlankReferenceID))
	if err != nil {
		logger.Errorf(messages.InvalidVaultConfig+messages.FailWriteResponse, messages.BlankReferenceID, err)
	}
}

func writeCreateDataVaultFailure(rw http.ResponseWriter, errVaultCreation error) {
	if errVaultCreation == messages.ErrDuplicateVault {
		rw.WriteHeader(http.StatusConflict)
	} else {
		rw.WriteHeader(http.StatusBadRequest)
	}

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.VaultCreationFailure, errVaultCreation)))
	if errWrite != nil {
		logger.Errorf(messages.VaultCreationFailure+messages.FailWriteResponse, errVaultCreation, errWrite)
	}
}

func writeCreateDataVaultSuccess(rw http.ResponseWriter, referenceID, hostURL string) {
	urlEncodedReferenceID := url.PathEscape(referenceID)

	rw.Header().Set("Location", hostURL+"/encrypted-data-vaults/"+urlEncodedReferenceID)
	rw.WriteHeader(http.StatusCreated)
}

func writeQueryResponse(rw http.ResponseWriter, matchingDocumentIDs []string, vaultID string) {
	if matchingDocumentIDs == nil {
		writeNoDocsFound(rw, vaultID)
		return
	}

	matchingDocumentIDsBytes, err := json.Marshal(matchingDocumentIDs)
	if err != nil {
		writeErrorWithVaultID(rw, http.StatusInternalServerError, messages.FailToMarshalDocIDs, err, vaultID)
		return
	}

	_, err = rw.Write(matchingDocumentIDsBytes)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		logger.Errorf(messages.QuerySuccess+messages.FailWriteResponse, vaultID, err)
	}
}

func writeNoDocsFound(rw io.Writer, vaultID string) {
	_, err := rw.Write([]byte(fmt.Sprintf(messages.QueryNoMatchingDocs, vaultID)))
	if err != nil {
		logger.Errorf(messages.QueryNoMatchingDocs+messages.FailWriteResponse, vaultID, err)
	}
}

func writeCreateDocumentFailure(rw http.ResponseWriter, errCreateDoc error, vaultID string) {
	if errCreateDoc == messages.ErrDuplicateDocument {
		rw.WriteHeader(http.StatusConflict)
	} else {
		rw.WriteHeader(http.StatusBadRequest)
	}

	_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.CreateDocumentFailure, vaultID, errCreateDoc)))
	if errWrite != nil {
		logger.Errorf(messages.CreateDocumentFailure+messages.FailWriteResponse, vaultID, errCreateDoc, errWrite)
	}
}

func writeCreateDocumentSuccess(rw http.ResponseWriter, host, vaultID, docID string) {
	rw.Header().Set("Location", host+"/encrypted-data-vaults/"+
		url.PathEscape(vaultID)+"/documents/"+url.PathEscape(docID))
	rw.WriteHeader(http.StatusCreated)
}

func writeErrorWithVaultID(rw http.ResponseWriter, statusCode int, message string, err error, vaultID string) {
	rw.WriteHeader(statusCode)

	_, errWrite := rw.Write([]byte(fmt.Sprintf(message, vaultID, err)))
	if errWrite != nil {
		logger.Errorf(message+messages.FailWriteResponse, vaultID, err, errWrite)
	}
}

func writeReadDocumentFailure(rw http.ResponseWriter, errReadDoc error, docID, vaultID string) {
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
	_, err := rw.Write(documentBytes)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		logger.Errorf(messages.ReadDocumentSuccess+messages.FailWriteResponse, docID, vaultID, err)
	}
}

func writeInvalidLogSpec(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusBadRequest)

	_, err := rw.Write([]byte(messages.InvalidLogSpec))
	if err != nil {
		logger.Errorf(messages.InvalidLogSpec+messages.FailWriteResponse, err)
	}
}
