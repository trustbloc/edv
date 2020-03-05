/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	// TODO: Don't reference Didcomm here: https://github.com/trustbloc/edv/issues/41
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"

	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
)

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
	EDVHostURL string
	// TODO: Replace with JWE document instead of legacy/authcrypt: https://github.com/trustbloc/edv/issues/41
	Packer                     *authcrypt.Packer
	StructuredDocToBeEncrypted *operation.StructuredDocument
	EncryptedDocToStore        *operation.EncryptedDocument
	ReceivedEncryptedDoc       *operation.EncryptedDocument
}

// NewBDDContext create new BDDContext
func NewBDDContext(edvHostURL string) (*BDDContext, error) {
	instance := BDDContext{
		EDVHostURL: edvHostURL,
	}

	return &instance, nil
}
