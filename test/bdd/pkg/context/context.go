/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package context

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/igor-pavlenko/httpsignatures-go"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"github.com/trustbloc/edge-core/pkg/zcapld"

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

	trustBlocEDVHostURL = "localhost:8076/encrypted-data-vaults"
)

type kmsProvider struct {
	storageProvider   ariesstorage.Provider
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() ariesstorage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
	EDVClient                  *edvclient.Client
	VaultID                    string
	JWEDecrypter               *jose.JWEDecrypt
	StructuredDocToBeEncrypted *models.StructuredDocument
	EncryptedDocToStore        *models.EncryptedDocument
	ReceivedEncryptedDoc       *models.EncryptedDocument
	TLSConfig                  *tls.Config
	Capability                 *zcapld.Capability
	KeyManager                 kms.KeyManager
	Crypto                     cryptoapi.Crypto
}

// NewBDDContext creates a new BDDContext
func NewBDDContext(caCertPaths string) (*BDDContext, error) {
	rootCAs, err := tlsutils.GetCertPool(false, []string{caCertPaths})
	if err != nil {
		return nil, err
	}

	keyManager, err := localkms.New(
		"local-lock://custom/master/key/",
		kmsProvider{storageProvider: ariesmemstorage.NewProvider(), secretLockService: &noop.NoLock{}},
	)
	if err != nil {
		return nil, err
	}

	crypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	instance := BDDContext{
		TLSConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}, KeyManager: keyManager, Crypto: crypto,
	}

	trustBlocEDVClient, err := createProxyEDVClient(&instance)
	if err != nil {
		return nil, err
	}

	instance.EDVClient = trustBlocEDVClient

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
	Capability                 *zcapld.Capability
	KeyManager                 kms.KeyManager
	Crypto                     cryptoapi.Crypto
	VerificationMethod         string
}

// NewBDDInteropContext creates a new BDDInteropContext.
func NewBDDInteropContext() (*BDDInteropContext, error) {
	transmuteEDVURL := "https://did-edv.web.app/edvs"

	transmuteEDVClient := edvclient.New(transmuteEDVURL)

	var sampleDocToStore models.EncryptedDocument

	err := json.Unmarshal([]byte(sampleEncryptedDoc), &sampleDocToStore)
	if err != nil {
		return nil, err
	}

	var sampleDocForUpdate models.EncryptedDocument

	err = json.Unmarshal([]byte(sampleUpdateEncryptedDoc), &sampleDocForUpdate)
	if err != nil {
		return nil, err
	}

	keyManager, err := localkms.New(
		"local-lock://custom/master/key/",
		kmsProvider{storageProvider: ariesmemstorage.NewProvider(), secretLockService: &noop.NoLock{}},
	)
	if err != nil {
		return nil, err
	}

	crypto, err := tinkcrypto.New()
	if err != nil {
		return nil, err
	}

	signer, err := signature.NewCryptoSigner(crypto, keyManager, kms.ED25519)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto signer: %w", err)
	}

	_, didKeyURL := fingerprint.CreateDIDKey(signer.PublicKeyBytes())

	ctx := &BDDInteropContext{
		TrustBlocEDVHostURL: trustBlocEDVHostURL,
		TransmuteEDVHostURL: transmuteEDVURL,
		TransmuteEDVClient:  transmuteEDVClient,
		SampleDocToStore:    &sampleDocToStore,
		SampleDocForUpdate:  &sampleDocForUpdate,
		KeyManager:          keyManager,
		Crypto:              crypto,
		VerificationMethod:  didKeyURL,
	}

	trustBlocEDVClient, err := createTrustBlocEDVClient(ctx)
	if err != nil {
		return nil, err
	}

	ctx.TrustBlocEDVClient = trustBlocEDVClient

	return ctx, nil
}

func createProxyEDVClient(ctx *BDDContext) (*edvclient.Client, error) {
	rootCAs, err := tlsutils.GetCertPool(false, []string{"fixtures/keys/tls/ec-cacert.pem"})
	if err != nil {
		return nil, err
	}

	return edvclient.New("https://"+trustBlocEDVHostURL, edvclient.WithTLSConfig(&tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}), edvclient.WithHeaders(func(req *http.Request) (*http.Header, error) {
		compressedZcap, err := compressZCAP(ctx.Capability)
		if err != nil {
			return nil, err
		}

		action := "write"
		if req.Method == http.MethodGet {
			action = "read"
		}

		req.Header.Set(zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressedZcap, action))

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: ctx.Crypto,
			KMS:    ctx.KeyManager,
		})

		err = hs.Sign(ctx.Capability.Invoker, req)
		if err != nil {
			return nil, err
		}

		return &req.Header, nil
	})), nil
}

func createTrustBlocEDVClient(ctx *BDDInteropContext) (*edvclient.Client, error) {
	rootCAs, err := tlsutils.GetCertPool(false, []string{"fixtures/keys/tls/ec-cacert.pem"})
	if err != nil {
		return nil, err
	}

	return edvclient.New("https://"+trustBlocEDVHostURL, edvclient.WithTLSConfig(&tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}), edvclient.WithHeaders(func(req *http.Request) (*http.Header, error) {
		compressedZcap, err := compressZCAP(ctx.Capability)
		if err != nil {
			return nil, err
		}

		action := "write"
		if req.Method == http.MethodGet {
			action = "read"
		}

		req.Header.Set(zcapld.CapabilityInvocationHTTPHeader,
			fmt.Sprintf(`zcap capability="%s",action="%s"`, compressedZcap, action))

		hs := httpsignatures.NewHTTPSignatures(&zcapld.AriesDIDKeySecrets{})
		hs.SetSignatureHashAlgorithm(&zcapld.AriesDIDKeySignatureHashAlgorithm{
			Crypto: ctx.Crypto,
			KMS:    ctx.KeyManager,
		})

		err = hs.Sign(ctx.VerificationMethod, req)
		if err != nil {
			return nil, err
		}

		return &req.Header, nil
	})), nil
}

func compressZCAP(zcap *zcapld.Capability) (string, error) {
	raw, err := json.Marshal(zcap)
	if err != nil {
		return "", err
	}

	compressed := bytes.NewBuffer(nil)

	w := gzip.NewWriter(compressed)

	_, err = w.Write(raw)
	if err != nil {
		return "", err
	}

	err = w.Close()
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(compressed.Bytes()), nil
}
