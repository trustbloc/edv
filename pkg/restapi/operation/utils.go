/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edv/pkg/restapi/messages"
)

// Unescapes the given path variable from the vars map and writes a response if any failure occurs.
// Returns the unescaped version of the path variable and a bool indicating whether the unescaping was successful.
func unescapePathVar(pathVar string, vars map[string]string, rw http.ResponseWriter) (string, bool) {
	unescapedPathVar, errUnescape := url.PathUnescape(vars[pathVar])
	if errUnescape != nil {
		logger.Errorf(messages.UnescapeFailure, pathVar, errUnescape)

		rw.WriteHeader(http.StatusBadRequest)

		_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.UnescapeFailure, pathVar, errUnescape)))
		if errWrite != nil {
			logger.Errorf(messages.UnescapeFailure+messages.FailWriteResponse, pathVar, errWrite, errWrite)
		}

		return "", false
	}

	return unescapedPathVar, true
}

func convertToFullDocumentURLs(documentIDs []string, vaultID, host string) []string {
	fullDocumentURLs := make([]string, len(documentIDs))

	for i, matchingDocumentID := range documentIDs {
		fullDocumentURLs[i] = getFullDocumentURL(matchingDocumentID, vaultID, host)
	}

	return fullDocumentURLs
}

func getFullDocumentURL(documentID, vaultID, host string) string {
	return host + "/encrypted-data-vaults/" + url.PathEscape(vaultID) + "/documents/" + url.PathEscape(documentID)
}

func debugLogLevelEnabled() bool {
	return log.GetLevel(logModuleName) >= log.DEBUG
}
