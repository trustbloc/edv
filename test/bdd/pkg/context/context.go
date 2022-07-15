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
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"

	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/igor-pavlenko/httpsignatures-go"
	"github.com/trustbloc/auth/component/gnap/as"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/auth/spi/gnap/proof/httpsig"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	"github.com/trustbloc/edge-core/pkg/zcapld"

	edvclient "github.com/trustbloc/edv/pkg/client"
	"github.com/trustbloc/edv/pkg/restapi/models"
	"github.com/trustbloc/edv/test/bdd/pkg/internal/vdrutil"
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

	trustBlocEDVHostURL     = "localhost:8076/encrypted-data-vaults"
	authServerURL           = "https://auth.trustbloc.local:8070"
	proofType               = "httpsig"
	mockClientFinishURI     = "https://mock.client.example.com/"
	oidcProviderSelectorURL = authServerURL + "/oidc/login"
	mockOIDCProviderName    = "mockbank1" // oidc-config/providers.yaml
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

	tlsConfig := tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}

	withTLSConfigOpt := edvclient.WithTLSConfig(&tlsConfig)

	options := []edvclient.Option{withTLSConfigOpt}

	authType := os.Getenv("EDV_AUTH_TYPE")

	if strings.EqualFold(authType, "zcap") { //nolint: nestif // test file
		println("Adding header function to EDV client for ZCAP...")

		withHeadersOpt := edvclient.WithHeaders(func(req *http.Request) (*http.Header, error) {
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
		})

		options = append(options, withHeadersOpt)
	} else if strings.EqualFold(authType, "gnap") || strings.EqualFold(authType, "GNAP,ZCAP") {
		println("Adding header function to EDV client for GNAP...")

		option, err := addGNAPHeaderOption(&tlsConfig)
		if err != nil {
			return nil, err
		}

		options = append(options, option)
	}

	return edvclient.New("https://"+trustBlocEDVHostURL, options...), nil
}

func addGNAPHeaderOption(tlsConfig *tls.Config) (edvclient.Option, error) { //nolint: funlen,gocyclo,gocognit
	println("Getting GNAP access token...")

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	vdr, err := vdrutil.CreateVDR(httpClient)
	if err != nil {
		return nil, err
	}

	didOwner, err := createDIDOwner(vdr)
	if err != nil {
		return nil, fmt.Errorf("create DID owner: %w", err)
	}

	gnapClient, err := as.NewClient(&httpsig.Signer{SigningKey: didOwner.PrivateKey}, httpClient, authServerURL)
	if err != nil {
		return nil, fmt.Errorf("create gnap client: %w", err)
	}

	publicJWK := &jwk.JWK{
		JSONWebKey: didOwner.PrivateKey.Public(),
		Kty:        "EC",
		Crv:        "P-256",
	}

	req := &gnap.AuthRequest{
		Client: &gnap.RequestClient{
			Key: &gnap.ClientKey{
				Proof: proofType,
				JWK:   *publicJWK,
			},
		},
		AccessToken: []*gnap.TokenRequest{
			{
				Access: []gnap.TokenAccess{
					{
						IsReference: true,
						Ref:         "example-token-type",
					},
				},
			},
		},
		Interact: &gnap.RequestInteract{
			Start: []string{"redirect"},
			Finish: gnap.RequestFinish{
				Method: "redirect",
				URI:    mockClientFinishURI,
			},
		},
	}

	authResp, err := gnapClient.RequestAccess(req)
	if err != nil {
		return nil, fmt.Errorf("request gnap access: %w", err)
	}

	interactURL, err := url.Parse(authResp.Interact.Redirect)
	if err != nil {
		return nil, fmt.Errorf("parse interact url: %w", err)
	}

	txnID := interactURL.Query().Get("txnID")

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("init cookie jar: %w", err)
	}

	browser := &http.Client{
		Jar:       jar,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	// redirect to interact url
	resp0, err := browser.Get(authResp.Interact.Redirect)
	if err != nil {
		return nil, fmt.Errorf("redirect to interact url: %w", err)
	}

	defer func() {
		errClose := resp0.Body.Close()
		if errClose != nil {
			println(fmt.Sprintf("failed to close response: %s", err.Error()))
		}
	}()

	requestURL := fmt.Sprintf("%s?provider=%s&txnID=%s", oidcProviderSelectorURL, mockOIDCProviderName, txnID)

	browser.CheckRedirect = func(req *http.Request, via []*http.Request) error { // do not follow redirects
		return http.ErrUseLastResponse
	}

	resp1, err := browser.Get(requestURL)
	if err != nil {
		return nil, fmt.Errorf("redirect to OIDC provider (%s): %w", requestURL, err)
	}

	defer func() {
		errClose := resp1.Body.Close()
		if errClose != nil {
			println(fmt.Sprintf("failed to close response: %s", err.Error()))
		}
	}()

	requestURL = resp1.Header.Get("Location")

	resp2, err := browser.Get(requestURL)
	if err != nil {
		return nil, fmt.Errorf("redirect to OIDC provider (%s): %w", requestURL, err)
	}

	defer func() {
		errClose := resp2.Body.Close()
		if errClose != nil {
			println(fmt.Sprintf("failed to close response: %s", err.Error()))
		}
	}()

	requestURL = resp2.Header.Get("Location")

	resp3, err := browser.Get(requestURL)
	if err != nil {
		return nil, fmt.Errorf("redirect to login (%s): %w", requestURL, err)
	}

	defer func() {
		errClose := resp3.Body.Close()
		if errClose != nil {
			println(fmt.Sprintf("failed to close response: %s", err.Error()))
		}
	}()

	// login to third-party oidc
	resp4, err := browser.Post(resp3.Request.URL.String(), "", nil)
	if err != nil {
		return nil, fmt.Errorf("login to third-party oidc: %w", err)
	}

	defer func() {
		errClose := resp4.Body.Close()
		if errClose != nil {
			println(fmt.Sprintf("failed to close response: %s", err.Error()))
		}
	}()

	requestURL = resp4.Header.Get("Location")

	resp5, err := browser.Get(requestURL)
	if err != nil {
		return nil, fmt.Errorf("redirect to post-login oauth (%s): %w", requestURL, err)
	}

	defer func() {
		errClose := resp5.Body.Close()
		if errClose != nil {
			println(fmt.Sprintf("failed to close response: %s", err.Error()))
		}
	}()

	requestURL = resp5.Header.Get("Location")

	resp6, err := browser.Get(requestURL)
	if err != nil {
		return nil, fmt.Errorf("redirect to consent (%s): %w", requestURL, err)
	}

	defer func() {
		errClose := resp6.Body.Close()
		if errClose != nil {
			println(fmt.Sprintf("failed to close response: %s", err.Error()))
		}
	}()

	requestURL = resp6.Header.Get("Location")

	resp7, err := browser.Get(requestURL)
	if err != nil {
		return nil, fmt.Errorf("redirect to post-consent oauth (%s): %w", requestURL, err)
	}

	defer func() {
		errClose := resp7.Body.Close()
		if errClose != nil {
			println(fmt.Sprintf("failed to close response: %s", err.Error()))
		}
	}()

	requestURL = resp7.Header.Get("Location")

	resp8, err := browser.Get(requestURL)
	if err != nil {
		return nil, fmt.Errorf("redirect to auth callback (%s): %w", requestURL, err)
	}

	defer func() {
		errClose := resp8.Body.Close()
		if errClose != nil {
			println(fmt.Sprintf("failed to close response: %s", err.Error()))
		}
	}()

	clientRedirect := resp8.Header.Get("Location")

	crURL, err := url.Parse(clientRedirect)
	if err != nil {
		return nil, fmt.Errorf("parse client redirect url: %w", err)
	}

	interactRef := crURL.Query().Get("interact_ref")

	continueReq := &gnap.ContinueRequest{
		InteractRef: interactRef,
	}

	continueResp, err := gnapClient.Continue(continueReq, authResp.Continue.AccessToken.Value)
	if err != nil {
		return nil, fmt.Errorf("call continue request: %w", err)
	}

	println(fmt.Sprintf("Successfully got GNAP access token (%s)", continueResp.AccessToken[0].Value))

	return edvclient.WithHeaders(func(req *http.Request) (*http.Header, error) {
		header := http.Header{}

		header.Add("Authorization", "GNAP "+continueResp.AccessToken[0].Value)
		return &header, nil
	}), nil
}

func createDIDOwner(vdr vdrapi.Registry) (*DIDOwner, error) {
	doc, pk, err := vdrutil.CreateDIDDoc(vdr)
	if err != nil {
		return nil, fmt.Errorf("create did doc: %w", err)
	}

	_, err = vdrutil.ResolveDID(vdr, doc.ID, 10)
	if err != nil {
		return nil, fmt.Errorf("resolve did: %w", err)
	}

	return &DIDOwner{
		DID:        doc.ID,
		KeyID:      doc.Authentication[0].VerificationMethod.ID,
		PrivateKey: pk,
	}, nil
}

// DIDOwner defines parameters of a DID owner.
type DIDOwner struct {
	DID        string
	KeyID      string
	PrivateKey *jwk.JWK
}

func createTrustBlocEDVClient(ctx *BDDInteropContext) (*edvclient.Client, error) {
	rootCAs, err := tlsutils.GetCertPool(false, []string{"fixtures/keys/tls/ec-cacert.pem"})
	if err != nil {
		return nil, err
	}

	tlsConfig := tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}

	withTLSConfigOpt := edvclient.WithTLSConfig(&tlsConfig)

	options := []edvclient.Option{withTLSConfigOpt}

	authType := os.Getenv("EDV_AUTH_TYPE")

	if strings.EqualFold(authType, "zcap") { //nolint: nestif // test file
		println("Adding header function to EDV client for ZCAP...")

		withHeadersOpt := edvclient.WithHeaders(func(req *http.Request) (*http.Header, error) {
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
		})

		options = append(options, withHeadersOpt)
	} else if strings.EqualFold(authType, "gnap") || strings.EqualFold(authType, "GNAP,ZCAP") {
		println("Adding header function to EDV client for GNAP...")

		option, err := addGNAPHeaderOption(&tlsConfig)
		if err != nil {
			return nil, err
		}

		options = append(options, option)
	}

	return edvclient.New("https://"+trustBlocEDVHostURL, options...), nil
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
