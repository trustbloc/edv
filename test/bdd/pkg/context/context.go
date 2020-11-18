/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"crypto/tls"
	"encoding/json"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	edvclient "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"
)

const (
	sampleDocID        = "VJYHHJx4C8J9Fsgz7rZqSp"
	sampleEncryptedDoc = `{
    "id": "` + sampleDocID + `",
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

	sampleUpdateEncryptedDoc = `{
    "id": "` + sampleDocID + `",
    "indexed": [
        {
            "attributes": [
                {
                    "name": "DUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
                    "value": "QV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
                },
                {
                    "name": "EUQaxPtSLtd8L3WBAIkJ4DiVJeqoF6bdnhR7lSaPloZ",
                    "unique": true,
                    "value": "RV58Va4904K-18_L5g_vfARXRWEB00knFSGPpukUBro"
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
                "encrypted_key": "BR1vdCNvf_B68mfUxFQVT-vyXVrBembuiM40mAAjDC1-Qu5iArDbug",
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

	proxyHostURL        = "localhost:4455/encrypted-data-vaults"
	trustBlocEDVHostURL = "localhost:8080/encrypted-data-vaults"
)

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
	EDVClient                  *edvclient.Client
	ProxyEDVClient             *edvclient.Client
	VaultID                    string
	JWEDecrypter               *jose.JWEDecrypt
	StructuredDocToBeEncrypted *models.StructuredDocument
	EncryptedDocToStore        *models.EncryptedDocument
	ReceivedEncryptedDoc       *models.EncryptedDocument
	TLSConfig                  *tls.Config
}

// NewBDDContext creates a new BDDContext
func NewBDDContext(caCertPaths ...string) (*BDDContext, error) {
	rootCAs, err := tlsutils.GetCertPool(false, caCertPaths)
	if err != nil {
		return nil, err
	}

	trustBlocEDVClient, err := createTrustBlocEDVClient()
	if err != nil {
		return nil, err
	}

	proxyEDVClient, err := createProxyEDVClient()
	if err != nil {
		return nil, err
	}

	instance := BDDContext{
		TLSConfig:      &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12},
		EDVClient:      trustBlocEDVClient,
		ProxyEDVClient: proxyEDVClient,
	}

	return &instance, nil
}

// BDDInteropContext is a global context shared between different interop test suites in bddtests
type BDDInteropContext struct {
	TrustBlocEDVHostURL        string
	TrustBlocEDVClient         *edvclient.Client
	TrustBlocEDVDataVaultID    string
	TrustBlocDataVaultLocation string
	TransmuteEDVHostURL        string
	TransmuteEDVClient         *edvclient.Client
	TransmuteDataVaultID       string
	TransmuteDataVaultLocation string
	DataVaultConfig            *models.DataVaultConfiguration
	SampleDocToStore           *models.EncryptedDocument
	SampleDocForUpdate         *models.EncryptedDocument
}

// NewBDDInteropContext creates a new BDDInteropContext.
func NewBDDInteropContext() (*BDDInteropContext, error) {
	trustBlocEDVClient, err := createTrustBlocEDVClient()
	if err != nil {
		return nil, err
	}

	transmuteEDVURL := "https://did-edv.web.app/edvs"

	transmuteEDVClient := edvclient.New(transmuteEDVURL)

	var sampleDocToStore models.EncryptedDocument

	err = json.Unmarshal([]byte(sampleEncryptedDoc), &sampleDocToStore)
	if err != nil {
		return nil, err
	}

	var sampleDocForUpdate models.EncryptedDocument

	err = json.Unmarshal([]byte(sampleUpdateEncryptedDoc), &sampleDocForUpdate)
	if err != nil {
		return nil, err
	}

	return &BDDInteropContext{
		TrustBlocEDVHostURL: trustBlocEDVHostURL,
		TrustBlocEDVClient:  trustBlocEDVClient,
		TransmuteEDVHostURL: transmuteEDVURL,
		TransmuteEDVClient:  transmuteEDVClient,
		SampleDocToStore:    &sampleDocToStore,
		SampleDocForUpdate:  &sampleDocForUpdate,
	}, nil
}

func createTrustBlocEDVClient() (*edvclient.Client, error) {
	rootCAs, err := tlsutils.GetCertPool(false, []string{"fixtures/keys/tls/ec-cacert.pem"})
	if err != nil {
		return nil, err
	}

	return edvclient.New("https://"+trustBlocEDVHostURL, edvclient.WithTLSConfig(&tls.Config{RootCAs: rootCAs,
		MinVersion: tls.VersionTLS12})), nil
}

func createProxyEDVClient() (*edvclient.Client, error) {
	rootCAs, err := tlsutils.GetCertPool(false, []string{"fixtures/keys/tls/ec-cacert.pem"})
	if err != nil {
		return nil, err
	}

	return edvclient.New("http://"+proxyHostURL, edvclient.WithTLSConfig(&tls.Config{RootCAs: rootCAs,
		MinVersion: tls.VersionTLS12})), nil
}
