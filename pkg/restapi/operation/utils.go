/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/trustbloc/edv/pkg/restapi/messages"

	"github.com/btcsuite/btcutil/base58"
)

// This function can't tell if the value before being encoded was precisely 128 bits long.
// This is because the byte58.decode function returns an array of bytes, not just a string of bits.
// So the closest I can do is see if the decoded byte array is 16 bytes long,
// however this means that if the original value was 121 bits to 127 bits long it'll still be accepted.
func checkIfBase58Encoded128BitValue(id string) error {
	decodedBytes := base58.Decode(id)
	if len(decodedBytes) == 0 {
		return messages.ErrNotBase58Encoded
	}

	if len(decodedBytes) != 16 {
		return messages.ErrNot128BitValue
	}

	return nil
}

// Unescapes the given path variable from the vars map and writes a response if any failure occurs.
// Returns the unescaped version of the path variable and a bool indicating whether the unescaping was successful.
func unescapePathVar(pathVar string, vars map[string]string, rw http.ResponseWriter) (string, bool) {
	unescapedPathVar, errUnescape := url.PathUnescape(vars[pathVar])
	if errUnescape != nil {
		rw.WriteHeader(http.StatusInternalServerError)

		_, errWrite := rw.Write([]byte(fmt.Sprintf(messages.UnescapeFailure, pathVar, errUnescape)))
		if errWrite != nil {
			logger.Errorf(messages.UnescapeFailure+messages.FailWriteResponse, pathVar, errWrite, errWrite)
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
