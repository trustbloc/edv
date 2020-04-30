/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"

	"github.com/trustbloc/edv/pkg/client/edv"
	"github.com/trustbloc/edv/pkg/restapi/edv/models"
)

const sampleEncryptedDoc = `{
    "id": "VJYHHJx4C8J9Fsgz7rZqSp",
    "indexed": [
        {
            "attributes": [
                {
                    "name": "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
                    "unique": true,
                    "value": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
                },
                {
                    "name": "CUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
                    "unique": true,
                    "value": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
                },
                {
                    "name": "DUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
                    "value": "QV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
                }
            ],
            "hmac": {
                "id": "https://example.com/kms/z7BgF536GaR",
                "type": "Sha256HmacKey2019"
            },
            "sequence": 0
        }
    ],
    "jwe": {
        "ciphertext": "Cb-963UCXblINT8F6MDHzMJN9EAhK3I",
        "iv": "i8Nins2vTI3PlrYW",
        "protected": "eyJlbmMiOiJDMjBQIn0",
        "recipients": [
            {
                "encrypted_key": "OR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug",
                "header": {
                    "alg": "A256KW",
                    "kid": "https://example.com/kms/z7BgF536GaR"
                }
            }
        ],
        "tag": "pfZO0JulJcrc3trOZy8rjA"
    },
    "sequence": 0
}`

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

// BDDInteropContext is a global context shared between different interop test suites in bddtests
type BDDInteropContext struct {
	TrustBlocEDVHostURL        string
	TrustBlocEDVClient         *edv.Client
	TransmuteEDVHostURL        string
	TransmuteEDVClient         *edv.Client
	DataVaultConfig            *models.DataVaultConfiguration
	TransmuteDataVaultLocation string
	TransmuteDataVaultID       string
	SampleDocToStore           *models.EncryptedDocument
}

// NewBDDInteropContext creates a new BDDInteropContext.
func NewBDDInteropContext(edvHostURL, transmuteEDVHostURL string) (*BDDInteropContext, error) {
	var sampleDocToStore models.EncryptedDocument

	err := json.Unmarshal([]byte(sampleEncryptedDoc), &sampleDocToStore)
	if err != nil {
		return nil, err
	}

	return &BDDInteropContext{
		TrustBlocEDVHostURL: edvHostURL,
		TrustBlocEDVClient:  edv.New("http://" + edvHostURL),
		TransmuteEDVHostURL: transmuteEDVHostURL,
		TransmuteEDVClient:  edv.New(transmuteEDVHostURL),
		SampleDocToStore:    &sampleDocToStore,
	}, nil
}
