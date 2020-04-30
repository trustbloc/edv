/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"

	"github.com/trustbloc/edv/pkg/restapi/edv/models"
)

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
	EDVHostURL                 string
	JWEDecrypter               *jose.JWEDecrypt
	StructuredDocToBeEncrypted *models.StructuredDocument
	EncryptedDocToStore        *models.EncryptedDocument
	ReceivedEncryptedDoc       *models.EncryptedDocument
}

// NewBDDContext create new BDDContext
func NewBDDContext(edvHostURL string) (*BDDContext, error) {
	instance := BDDContext{
		EDVHostURL: edvHostURL,
	}

	return &instance, nil
}
