/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/tink/go/subtle/random"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	ariesvdr "github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	zcapldcore "github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/edv/pkg/auth/zcapld"
	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/edvprovider/couchdbedvprovider"
	"github.com/trustbloc/edv/pkg/edvprovider/memedvprovider"
	"github.com/trustbloc/edv/pkg/restapi"
	"github.com/trustbloc/edv/pkg/restapi/healthcheck"
	"github.com/trustbloc/edv/pkg/restapi/operation"
)

const (
	commonEnvVarUsageText = "Alternatively, this can be set with the following environment variable: "

	hostURLFlagName      = "host-url"
	hostURLEnvKey        = "EDV_HOST_URL"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the edv instance on. Format: HostName:Port." +
		" Alternatively, this can be set with the following environment variable: " + hostURLEnvKey

	databaseTypeFlagName      = "database-type"
	databaseTypeEnvKey        = "EDV_DATABASE_TYPE"
	databaseTypeFlagShorthand = "t"
	databaseTypeFlagUsage     = "The type of database to use internally in the EDV. Supported options: mem, couchdb. " +
		"Note that mem doesn't support encrypted index querying. Alternatively, this can be set with the following " +
		"environment variable: " + databaseTypeEnvKey

	databaseTypeMemOption     = "mem"
	databaseTypeCouchDBOption = "couchdb"

	databaseURLFlagName      = "database-url"
	databaseURLEnvKey        = "EDV_DATABASE_URL"
	databaseURLFlagShorthand = "r"
	databaseURLFlagUsage     = "The URL of the database. Not needed if using memstore." +
		" For CouchDB, include the username:password@ text." +
		" Alternatively, this can be set with the following environment variable: " + databaseURLEnvKey

	databasePrefixFlagName      = "database-prefix"
	databasePrefixEnvKey        = "EDV_DATABASE_PREFIX"
	databasePrefixFlagShorthand = "p"
	databasePrefixFlagUsage     = "An optional prefix to be used when creating and retrieving underlying databases." +
		" This followed by an underscore will be prepended to any incoming vault IDs received in REST calls before" +
		" creating or accessing underlying databases." +
		" Alternatively, this can be set with the following environment variable: " + databasePrefixEnvKey

	databaseTimeoutFlagName      = "database-timeout"
	databaseTimeoutEnvKey        = "EDV_DATABASE_TIMEOUT"
	databaseTimeoutFlagShorthand = "o"
	databaseTimeoutFlagUsage     = "Total time in seconds to wait until the database is available before giving up." +
		" Default: 30 seconds." +
		" Alternatively, this can be set with the following environment variable: " + databaseTimeoutEnvKey
	databaseTimeoutDefault = 30

	databaseRetrievalPageSizeFlagName      = "database-retrieval-page-size"
	databaseRetrievalPageSizeEnvKey        = "EDV_DATABASE_PAGE_SIZE"
	databaseRetrievalPageSizeFlagShorthand = "s"
	databaseRetrievalPageSizeFlagUsage     = "Number of entries within each page when doing bulk operations " +
		"within underlying databases. Larger values provide better performance at the expense of memory usage." +
		" This option is ignored if the database type is mem." +
		" Default: 100." +
		" Alternatively, this can be set with the following environment variable: " + databaseRetrievalPageSizeEnvKey
	databaseRetrievalPageSizeDefault = 100

	logLevelFlagName        = "log-level"
	logLevelEnvKey          = "EDV_LOG_LEVEL"
	logLevelFlagShorthand   = "l"
	logLevelPrefixFlagUsage = "Logging level to set. Supported options: critical, error, warning, info, debug." +
		`Defaults to "info" if not set. Setting to "debug" may adversely impact performance. Alternatively, this can be ` +
		"set with the following environment variable: " + logLevelEnvKey

	logLevelCritical = "critical"
	logLevelError    = "error"
	logLevelWarn     = "warning"
	logLevelInfo     = "info"
	logLevelDebug    = "debug"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool. Possible values [true] [false]. " +
		"Defaults to false if not set. " + commonEnvVarUsageText + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "EDV_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-separated list of CA certs path. " + commonEnvVarUsageText + tlsCACertsEnvKey
	tlsCACertsEnvKey    = "EDV_TLS_CACERTS"

	tlsCertFileFlagName      = "tls-cert-file"
	tlsCertFileFlagShorthand = ""
	tlsCertFileFlagUsage     = "TLS certificate file." +
		" Alternatively, this can be set with the following environment variable: " + tlsCertFileEnvKey
	tlsCertFileEnvKey = "EDV_TLS_CERT_FILE"

	tlsKeyFileFlagName      = "tls-key-file"
	tlsKeyFileFlagShorthand = ""
	tlsKeyFileFlagUsage     = "TLS key file." +
		" Alternatively, this can be set with the following environment variable: " + tlsKeyFileEnvKey
	tlsKeyFileEnvKey = "EDV_TLS_KEY_FILE"

	localKMSSecretsDatabaseTypeFlagName  = "localkms-secrets-database-type"
	localKMSSecretsDatabaseTypeEnvKey    = "EDV_LOCALKMS_SECRETS_DATABASE_TYPE" //nolint: gosec
	localKMSSecretsDatabaseTypeFlagUsage = "The type of database to use for storing KMS secrets for Keystore. " +
		"Supported options: mem, couchdb. " + commonEnvVarUsageText + localKMSSecretsDatabaseTypeEnvKey

	localKMSSecretsDatabaseURLFlagName  = "localkms-secrets-database-url"
	localKMSSecretsDatabaseURLEnvKey    = "EDV_LOCALKMS_SECRETS_DATABASE_URL" //nolint: gosec
	localKMSSecretsDatabaseURLFlagUsage = "The URL of the database for KMS secrets. " +
		"Not needed if using in-memory storage. " +
		"For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText +
		localKMSSecretsDatabaseURLEnvKey

	localKMSSecretsDatabasePrefixFlagName  = "localkms-secrets-database-prefix"
	localKMSSecretsDatabasePrefixEnvKey    = "EDV_LOCALKMS_SECRETS_DATABASE_PREFIX" //nolint: gosec
	localKMSSecretsDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the underlying " +
		"KMS secrets database. " + commonEnvVarUsageText + localKMSSecretsDatabasePrefixEnvKey

	authEnableFlagName  = "auth-enable"
	authEnableFlagUsage = "Enable authorization. Possible values [true] [false]. " +
		"Defaults to false if not set. " + commonEnvVarUsageText + authEnableEnvKey
	authEnableEnvKey = "EDV_AUTH_ENABLE"

	corsEnableFlagName  = "cors-enable"
	corsEnableFlagUsage = "Enable cors. Possible values [true] [false]. " +
		"Defaults to false if not set. " + commonEnvVarUsageText + corsEnableEnvKey
	corsEnableEnvKey = "EDV_CORS_ENABLE"

	// Enables queries to return full documents in queries instead of only the document locations.
	// Requires "returnFullDocuments" to be set to true in incoming query JSON,
	// otherwise only document locations will be returned.
	returnFullDocumentOnQueryExtensionName = "ReturnFullDocumentsOnQuery"
	// Enables a /{VaultID}/batch endpoint for doing batching operations within a vault.
	batchExtensionName            = "Batch"
	readAllDocumentsExtensionName = "ReadAllDocuments"

	extensionsFlagName  = "with-extensions"
	extensionsFlagUsage = "Enables features that are extensions of the spec. " +
		"If set, must be a comma-separated list of some or all of the following possible values: " +
		"[" + returnFullDocumentOnQueryExtensionName + "," + batchExtensionName + "]. " +
		"If not set, then no extensions will be used and the EDV server will be " +
		"strictly conformant with the spec. These can all be safely enabled without breaking any core " +
		"EDV functionality or non-extension-aware clients." + commonEnvVarUsageText + extensionsEnvKey
	extensionsEnvKey = "EDV_EXTENSIONS"

	didDomainFlagName  = "did-domain"
	didDomainFlagUsage = "URL to the did consortium's domain." +
		" Alternatively, this can be set with the following environment variable: " + didDomainEnvKey
	didDomainEnvKey = "EDV_DID_DOMAIN"

	sleep = time.Second

	masterKeyURI       = "local-lock://custom/master/key/"
	masterKeyStoreName = "masterkey"
	masterKeyDBKeyName = masterKeyStoreName

	masterKeyNumBytes = 32

	createVaultPath = "/encrypted-data-vaults"
	healthCheckPath = "/healthcheck"
)

var logger = log.New("edv-rest")

var errInvalidDatabaseType = fmt.Errorf("database type not set to a valid type." +
	" run start --help to see the available options")

var errCreateConfigStore = "failed to create data vault configuration store: %w"

// nolint:gochecknoglobals
var supportedEDVStorageProviders = map[string]func(string, string, uint) (edvprovider.EDVProvider, error){
	databaseTypeCouchDBOption: func(databaseURL, prefix string, retrievalPageSize uint) (edvprovider.EDVProvider, error) {
		return couchdbedvprovider.NewProvider(databaseURL, prefix, retrievalPageSize)
	},
	databaseTypeMemOption: func(_, _ string, _ uint) (edvprovider.EDVProvider, error) { // nolint:unparam
		return memedvprovider.NewProvider(), nil
	},
}

// nolint:gochecknoglobals
var supportedAriesStorageProviders = map[string]func(string, string) (storage.Provider, error){
	databaseTypeCouchDBOption: func(databaseURL, prefix string) (storage.Provider, error) {
		return couchdb.NewProvider(databaseURL, couchdb.WithDBPrefix(prefix))
	},
	databaseTypeMemOption: func(_, _ string) (storage.Provider, error) { // nolint:unparam
		return mem.NewProvider(), nil
	},
}

type edvParameters struct {
	srv                       server
	hostURL                   string
	databaseType              string
	databaseURL               string
	databasePrefix            string
	databaseTimeout           uint64
	databaseRetrievalPageSize uint
	logLevel                  string
	didDomain                 string
	tlsConfig                 *tlsConfig
	authEnable                bool
	corsEnable                bool
	localKMSSecretsStorage    *storageParameters
	extensionsToEnable        *operation.EnabledExtensions
}

type storageParameters struct {
	storageType   string
	storageURL    string
	storagePrefix string
}

type tlsConfig struct {
	certFile             string
	keyFile              string
	tlsUseSystemCertPool bool
	tlsCACerts           []string
}

type kmsProvider struct {
	storageProvider   storage.Provider
	secretLockService secretlock.Service
}

func (k kmsProvider) StorageProvider() storage.Provider {
	return k.storageProvider
}

func (k kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

type authService interface {
	Create(resourceID, verificationMethod string) ([]byte, error)
	Handler(resourceID string, req *http.Request, w http.ResponseWriter, next http.HandlerFunc) (http.HandlerFunc, error)
}

type server interface {
	ListenAndServe(host, certFile, keyFile string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host, certFile, keyFile string, router http.Handler) error {
	if certFile != "" && keyFile != "" {
		return http.ListenAndServeTLS(host, certFile, keyFile, router)
	}

	return http.ListenAndServe(host, router)
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command { //nolint: funlen,gocyclo
	return &cobra.Command{
		Use:   "start",
		Short: "Start EDV",
		Long:  "Start EDV",
		RunE: func(cmd *cobra.Command, args []string) error {
			hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
			if err != nil {
				return err
			}

			didDomain, err := cmdutils.GetUserSetVarFromString(cmd, didDomainFlagName, didDomainEnvKey, true)
			if err != nil {
				return err
			}

			databaseType, err := cmdutils.GetUserSetVarFromString(cmd, databaseTypeFlagName, databaseTypeEnvKey, false)
			if err != nil {
				return err
			}

			var databaseURL string
			if databaseType == databaseTypeMemOption {
				databaseURL = "N/A"
			} else {
				var errGetUserSetVar error
				databaseURL, errGetUserSetVar = cmdutils.GetUserSetVarFromString(cmd, databaseURLFlagName, databaseURLEnvKey, true)
				if errGetUserSetVar != nil {
					return errGetUserSetVar
				}
			}

			databasePrefix, err := cmdutils.GetUserSetVarFromString(cmd, databasePrefixFlagName, databasePrefixEnvKey, true)
			if err != nil {
				return err
			}

			databaseTimeout, err := getTimeout(cmd)
			if err != nil {
				return err
			}

			databaseRetrievalPageSize, err := getDatabaseRetrievalPageSize(cmd)
			if err != nil {
				return err
			}

			loggingLevel, err := cmdutils.GetUserSetVarFromString(cmd, logLevelFlagName, logLevelEnvKey, true)
			if err != nil {
				return err
			}

			tlsConfig, err := getTLS(cmd)
			if err != nil {
				return err
			}

			authEnable, err := getAuthEnable(cmd)
			if err != nil {
				return err
			}

			corsEnable, err := getCORSEnable(cmd)
			if err != nil {
				return err
			}

			localKMSSecretsStorage, err := getLocalKMSSecretsStorageParameters(cmd, !authEnable)
			if err != nil {
				return err
			}

			enabledExtensions, err := getEnabledExtensions(cmd)
			if err != nil {
				return err
			}

			parameters := &edvParameters{
				srv:                       srv,
				hostURL:                   hostURL,
				databaseType:              databaseType,
				databaseURL:               databaseURL,
				databasePrefix:            databasePrefix,
				databaseTimeout:           databaseTimeout,
				databaseRetrievalPageSize: databaseRetrievalPageSize,
				logLevel:                  loggingLevel,
				tlsConfig:                 tlsConfig,
				authEnable:                authEnable,
				corsEnable:                corsEnable,
				localKMSSecretsStorage:    localKMSSecretsStorage,
				extensionsToEnable:        enabledExtensions,
				didDomain:                 didDomain,
			}
			return startEDV(parameters)
		},
	}
}

func getAuthEnable(cmd *cobra.Command) (bool, error) {
	authEnableString := cmdutils.GetUserSetOptionalVarFromString(cmd, authEnableFlagName, authEnableEnvKey)

	authEnable := false

	if authEnableString != "" {
		var err error
		authEnable, err = strconv.ParseBool(authEnableString)

		if err != nil {
			return false, err
		}
	}

	return authEnable, nil
}

func getCORSEnable(cmd *cobra.Command) (bool, error) {
	corsEnableString := cmdutils.GetUserSetOptionalVarFromString(cmd, corsEnableFlagName, corsEnableEnvKey)

	corsEnable := false

	if corsEnableString != "" {
		var err error
		corsEnable, err = strconv.ParseBool(corsEnableString)

		if err != nil {
			return false, err
		}
	}

	return corsEnable, nil
}

func getLocalKMSSecretsStorageParameters(cmd *cobra.Command, isOptional bool) (*storageParameters, error) {
	dbType, err := cmdutils.GetUserSetVarFromString(cmd, localKMSSecretsDatabaseTypeFlagName,
		localKMSSecretsDatabaseTypeEnvKey, isOptional)
	if err != nil {
		return nil, err
	}

	storageParam := &storageParameters{storageType: dbType}

	if dbType != databaseTypeMemOption {
		dbURL, err := cmdutils.GetUserSetVarFromString(cmd, localKMSSecretsDatabaseURLFlagName,
			localKMSSecretsDatabaseURLEnvKey, isOptional)
		if err != nil {
			return nil, err
		}

		dbPrefix := cmdutils.GetUserSetOptionalVarFromString(cmd, localKMSSecretsDatabasePrefixFlagName,
			localKMSSecretsDatabasePrefixEnvKey)

		storageParam.storageURL = dbURL
		storageParam.storagePrefix = dbPrefix
	}

	return storageParam, nil
}

func getEnabledExtensions(cmd *cobra.Command) (*operation.EnabledExtensions, error) {
	extensionsCSV, err := cmdutils.GetUserSetVarFromString(cmd, extensionsFlagName, extensionsEnvKey, true)
	if err != nil {
		return nil, err
	}

	extensionsToEnable := strings.Split(extensionsCSV, ",")

	var enabledExtensions operation.EnabledExtensions

	for _, extensionToEnable := range extensionsToEnable {
		switch {
		case strings.EqualFold(extensionToEnable, returnFullDocumentOnQueryExtensionName):
			enabledExtensions.ReturnFullDocumentsOnQuery = true
		case strings.EqualFold(extensionToEnable, batchExtensionName):
			enabledExtensions.Batch = true
		}
	}

	return &enabledExtensions, nil
}

func getTimeout(cmd *cobra.Command) (timeout uint64, err error) {
	databaseTimeout, err := cmdutils.GetUserSetVarFromString(cmd, databaseTimeoutFlagName, databaseTimeoutEnvKey, true)
	if err != nil {
		return 0, err
	}

	if databaseTimeout == "" {
		databaseTimeout = strconv.Itoa(databaseTimeoutDefault)
	}

	databaseTimeoutInt, err := strconv.Atoi(databaseTimeout)
	if err != nil {
		return 0, fmt.Errorf("failed to parse timeout %s: %w", databaseTimeout, err)
	}

	return uint64(databaseTimeoutInt), nil
}

func getDatabaseRetrievalPageSize(cmd *cobra.Command) (uint, error) {
	databaseRetrievalPageSize, err := cmdutils.GetUserSetVarFromString(cmd,
		databaseRetrievalPageSizeFlagName, databaseRetrievalPageSizeEnvKey, true)
	if err != nil {
		return 0, err
	}

	if databaseRetrievalPageSize == "" {
		databaseRetrievalPageSize = strconv.Itoa(databaseRetrievalPageSizeDefault)
	}

	databaseRetrievalPageSizeInt, err := strconv.ParseUint(databaseRetrievalPageSize, 10, 0)
	if err != nil {
		return 0,
			fmt.Errorf("failed to parse database retrieval page size %s into a string: %w",
				databaseRetrievalPageSize, err)
	}

	return uint(databaseRetrievalPageSizeInt), nil
}

func getTLS(cmd *cobra.Command) (*tlsConfig, error) {
	tlsCertFile, err := cmdutils.GetUserSetVarFromString(cmd, tlsCertFileFlagName,
		tlsCertFileEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsKeyFile, err := cmdutils.GetUserSetVarFromString(cmd, tlsKeyFileFlagName,
		tlsKeyFileEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsUseSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsUseSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName, tlsCACertsEnvKey)

	return &tlsConfig{
		certFile:             tlsCertFile,
		keyFile:              tlsKeyFile,
		tlsUseSystemCertPool: tlsUseSystemCertPool,
		tlsCACerts:           tlsCACerts,
	}, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, databaseURLFlagShorthand, "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, databasePrefixFlagShorthand, "", databasePrefixFlagUsage)
	startCmd.Flags().StringP(databaseTimeoutFlagName, databaseTimeoutFlagShorthand, "", databaseTimeoutFlagUsage)
	startCmd.Flags().StringP(databaseRetrievalPageSizeFlagName,
		databaseRetrievalPageSizeFlagShorthand, "", databaseRetrievalPageSizeFlagUsage)
	startCmd.Flags().StringP(logLevelFlagName, logLevelFlagShorthand, "", logLevelPrefixFlagUsage)
	startCmd.Flags().StringP(tlsCertFileFlagName, tlsCertFileFlagShorthand, "", tlsCertFileFlagUsage)
	startCmd.Flags().StringP(tlsKeyFileFlagName, tlsKeyFileFlagShorthand, "", tlsKeyFileFlagUsage)
	startCmd.Flags().StringP(localKMSSecretsDatabaseTypeFlagName, "", "",
		localKMSSecretsDatabaseTypeFlagUsage)
	startCmd.Flags().StringP(localKMSSecretsDatabaseURLFlagName, "", "",
		localKMSSecretsDatabaseURLFlagUsage)
	startCmd.Flags().StringP(localKMSSecretsDatabasePrefixFlagName, "", "",
		localKMSSecretsDatabasePrefixFlagUsage)
	startCmd.Flags().StringP(authEnableFlagName, "", "", authEnableFlagUsage)
	startCmd.Flags().StringP(extensionsFlagName, "", "", extensionsFlagUsage)
	startCmd.Flags().StringP(corsEnableFlagName, "", "", corsEnableFlagUsage)
	startCmd.Flags().StringP(didDomainFlagName, "", "", didDomainFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
}

func startEDV(parameters *edvParameters) error { //nolint: funlen,gocyclo
	if parameters.logLevel != "" {
		setLogLevel(parameters.logLevel)
	}

	provider, err := createEDVProvider(parameters)
	if err != nil {
		return err
	}

	err = createConfigStore(provider)
	if err != nil {
		return err
	}

	// create auth service
	var authSvc authService

	if parameters.authEnable { // nolint: nestif
		keyManager, errCreate := createKeyManager(parameters)
		if errCreate != nil {
			return errCreate
		}

		// create crypto
		crypto, errCreate := tinkcrypto.New()
		if errCreate != nil {
			return errCreate
		}

		storageProvider, errCreate := createStorageProvider(&storageParameters{
			storageType: parameters.databaseType,
			storageURL:  parameters.databaseURL, storagePrefix: parameters.databasePrefix,
		}, parameters.databaseTimeout)
		if errCreate != nil {
			return errCreate
		}

		vdrResolver, errVDR := prepareVDR(parameters)
		if errVDR != nil {
			return errVDR
		}

		authSvc, err = zcapld.New(keyManager, crypto, storageProvider, verifiable.CachingJSONLDLoader(), vdrResolver)
		if err != nil {
			return err
		}
	}

	edvService, err := restapi.New(&operation.Config{
		Provider: provider, AuthService: authSvc,
		AuthEnable: parameters.authEnable, EnabledExtensions: parameters.extensionsToEnable,
	})
	if err != nil {
		return err
	}

	router := mux.NewRouter()
	router.UseEncodedPath()

	// add health check endpoint
	healthCheckService := healthcheck.New()

	healthCheckHandlers := healthCheckService.GetOperations()
	for _, handler := range healthCheckHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	handlers := edvService.GetOperations()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	for _, handler := range logspec.New().GetOperations() {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logStartupMessage(parameters)

	return parameters.srv.ListenAndServe(parameters.hostURL,
		parameters.tlsConfig.certFile, parameters.tlsConfig.keyFile, constructHandlers(parameters.corsEnable,
			authSvc, router))
}

func prepareVDR(params *edvParameters) (zcapldcore.VDRResolver, error) {
	rootCAs, err := tlsutils.GetCertPool(params.tlsConfig.tlsUseSystemCertPool, params.tlsConfig.tlsCACerts)
	if err != nil {
		return nil, err
	}

	orbVDR, err := orb.New(nil, orb.WithDomain(params.didDomain),
		orb.WithTLSConfig(&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}),
	)
	if err != nil {
		return nil, err
	}

	return ariesvdr.New(
		ariesvdr.WithVDR(vdrkey.New()),
		ariesvdr.WithVDR(orbVDR),
	), nil
}

func setLogLevel(userLogLevel string) {
	logLevel, err := log.ParseLevel(userLogLevel)
	if err != nil {
		logger.Warnf(`%s is not a valid logging level.`+
			`It must be one of the following: critical,error,warning,info,debug. Defaulting to info.`, userLogLevel)

		logLevel = log.INFO
	} else if logLevel == log.DEBUG {
		logger.Infof(`Log level set to "debug". Performance may be adversely impacted.`)
	}

	log.SetLevel("", logLevel)
}

func createEDVProvider(parameters *edvParameters) (edvprovider.EDVProvider, error) {
	var edvProv edvprovider.EDVProvider

	if parameters.databaseType == databaseTypeMemOption {
		logger.Warnf("encrypted indexing and querying is disabled since they are not supported by memstore")
	}

	providerFunc, supported := supportedEDVStorageProviders[parameters.databaseType]
	if !supported {
		return nil, errInvalidDatabaseType
	}

	err := retry(func() error {
		var openErr error
		edvProv, openErr =
			providerFunc(parameters.databaseURL, parameters.databasePrefix, parameters.databaseRetrievalPageSize)
		return openErr
	}, parameters.databaseTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", parameters.databaseType, err)
	}

	return edvProv, nil
}

// createConfigStore creates the config store and creates indices if supported.
func createConfigStore(provider edvprovider.EDVProvider) error {
	_, err := provider.OpenStore(edvprovider.VaultConfigurationStoreName)
	if err != nil {
		return fmt.Errorf(errCreateConfigStore, err)
	}

	err = provider.SetStoreConfig(edvprovider.VaultConfigurationStoreName,
		storage.StoreConfiguration{TagNames: []string{edvprovider.VaultConfigReferenceIDTagName}})
	if err != nil {
		return fmt.Errorf("failed to set store config: %w", err)
	}

	return nil
}

func constructHandlers(enableCORS bool, authSvc authService, routerHandler http.Handler) http.Handler {
	if enableCORS {
		return cors.New(
			cors.Options{
				AllowedMethods: []string{
					http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions,
				},
				AllowedHeaders: []string{"*"},
			},
		).Handler(&httpHandler{authSvc: authSvc, routerHandler: routerHandler})
	}

	return &httpHandler{authSvc: authSvc, routerHandler: routerHandler}
}

func retry(fn func() error, numRetries uint64) error {
	return backoff.RetryNotify(fn,
		backoff.WithMaxRetries(backoff.NewConstantBackOff(sleep), numRetries),
		func(retryErr error, t time.Duration) {
			logger.Warnf("failed to connect to database, will sleep for %s before trying again: %s",
				t, retryErr)
		})
}

func createKeyManager(parameters *edvParameters) (kms.KeyManager, error) {
	localKMSSecretsStorageProvider, err := createStorageProvider(parameters.localKMSSecretsStorage,
		parameters.databaseTimeout)
	if err != nil {
		return nil, err
	}

	localKMS, err := createLocalKMS(localKMSSecretsStorageProvider)
	if err != nil {
		return nil, err
	}

	return localKMS, nil
}

func createLocalKMS(kmsSecretsStoreProvider storage.Provider) (*localkms.LocalKMS, error) {
	masterKeyReader, err := prepareMasterKeyReader(kmsSecretsStoreProvider)
	if err != nil {
		return nil, err
	}

	secretLockService, err := local.NewService(masterKeyReader, nil)
	if err != nil {
		return nil, err
	}

	kmsProv := kmsProvider{
		storageProvider:   kmsSecretsStoreProvider,
		secretLockService: secretLockService,
	}

	return localkms.New(masterKeyURI, kmsProv)
}

// prepareMasterKeyReader prepares a master key reader for secret lock usage
func prepareMasterKeyReader(kmsSecretsStoreProvider storage.Provider) (*bytes.Reader, error) {
	masterKeyStore, err := kmsSecretsStoreProvider.OpenStore(masterKeyStoreName)
	if err != nil {
		return nil, err
	}

	masterKey, err := masterKeyStore.Get(masterKeyDBKeyName)
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			masterKeyRaw := random.GetRandomBytes(uint32(masterKeyNumBytes))
			masterKey = []byte(base64.URLEncoding.EncodeToString(masterKeyRaw))

			putErr := masterKeyStore.Put(masterKeyDBKeyName, masterKey)
			if putErr != nil {
				return nil, putErr
			}
		} else {
			return nil, err
		}
	}

	masterKeyReader := bytes.NewReader(masterKey)

	return masterKeyReader, nil
}

func createStorageProvider(parameters *storageParameters, databaseTimeout uint64) (storage.Provider, error) {
	var prov storage.Provider

	if parameters.storageType == databaseTypeMemOption {
		logger.Warnf("encrypted indexing and querying is disabled since they are not supported by memstore")
	}

	providerFunc, supported := supportedAriesStorageProviders[parameters.storageType]
	if !supported {
		return nil, errInvalidDatabaseType
	}

	err := retry(func() error {
		var openErr error
		prov, openErr = providerFunc(parameters.storageURL, parameters.storagePrefix)
		return openErr
	}, databaseTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", parameters.storageType, err)
	}

	return prov, nil
}

func logStartupMessage(parameters *edvParameters) {
	logger.Infof("Starting EDV REST server with the following parameters:   Host URL: %s, Database type: %s, "+
		"Database URL: %s, Database prefix: %s, TLS certificate file: %s, TLS key file: %s, Extensions: %+v, "+
		"Auth enabled?: %t, CORS enabled?: %t, Database timeout: %d, Local KMS secrets storage: %+v, Log level: %s",
		parameters.hostURL, parameters.databaseType, parameters.databaseURL, parameters.databasePrefix,
		parameters.tlsConfig.certFile, parameters.tlsConfig.keyFile, parameters.extensionsToEnable,
		parameters.authEnable, parameters.corsEnable, parameters.databaseTimeout, parameters.localKMSSecretsStorage,
		parameters.logLevel)
}

type httpHandler struct {
	authSvc       authService
	routerHandler http.Handler
}

func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// check if authSvc is nil
	if h.authSvc == nil {
		h.routerHandler.ServeHTTP(w, r)

		return
	}

	s := strings.SplitAfter(r.RequestURI, "/")

	if r.RequestURI == createVaultPath || r.RequestURI == healthCheckPath || len(s) < 3 {
		h.routerHandler.ServeHTTP(w, r)

		return
	}

	authHandler, err := h.authSvc.Handler(strings.TrimSuffix(s[2], "/"), r, w,
		func(writer http.ResponseWriter, request *http.Request) {
			h.routerHandler.ServeHTTP(w, r)
		})
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)

		_, errWrite := w.Write([]byte(err.Error()))
		if errWrite != nil {
			logger.Errorf(errWrite.Error())
		}

		return
	}

	authHandler.ServeHTTP(w, r)
}
