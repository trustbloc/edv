/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/google/tink/go/subtle/random"
	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/couchdb"
	"github.com/hyperledger/aries-framework-go-ext/component/storage/mongodb"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/orb"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/local"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	ariesvdr "github.com/hyperledger/aries-framework-go/pkg/vdr"
	vdrkey "github.com/hyperledger/aries-framework-go/pkg/vdr/key"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/square/go-jose/v3"
	"github.com/trustbloc/auth/component/gnap/rs"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/auth/spi/gnap/proof/httpsig"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"
	zcapldcore "github.com/trustbloc/edge-core/pkg/zcapld"

	"github.com/trustbloc/edv/pkg/auth/zcapld"
	"github.com/trustbloc/edv/pkg/edvprovider"
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
	databaseTypeFlagUsage     = "The type of database to use internally in the EDV. " +
		"Supported options: mem, couchdb, mongodb. " +
		"Alternatively, this can be set with the following environment variable: " + databaseTypeEnvKey

	databaseTypeMemOption     = "mem"
	databaseTypeCouchDBOption = "couchdb"
	databaseTypeMongoDBOption = "mongodb"

	databaseURLFlagName      = "database-url"
	databaseURLEnvKey        = "EDV_DATABASE_URL"
	databaseURLFlagShorthand = "r"
	databaseURLFlagUsage     = "The URL (or connection string) of the database. Not needed if using memstore." +
		" For CouchDB, include the username:password@ text if required." +
		" Alternatively, this can be set with the following environment variable: " + databaseURLEnvKey

	configDatabaseNameFlagName      = "config-database-name"
	configDatabaseNameEnvKey        = "EDV_CONFIG_DATABASE_NAME"
	configDatabaseNameFlagShorthand = "c"
	configDatabaseNameFlagUsage     = "The name of the main database where data vault configurations will be stored." +
		` Defaults to "configurations" if not set` +
		" Alternatively, this can be set with the following environment variable: " + documentDatabaseNameEnvKey
	defaultConfigDatabaseName = "configurations"

	documentDatabaseNameFlagName      = "document-database-name"
	documentDatabaseNameEnvKey        = "EDV_DOCUMENT_DATABASE_NAME"
	documentDatabaseNameFlagShorthand = "d"
	documentDatabaseNameFlagUsage     = "The name of the database where encrypted documents will be stored." +
		` Defaults to "documents" if not set` +
		" Alternatively, this can be set with the following environment variable: " + documentDatabaseNameEnvKey
	defaultDocumentDatabaseName = "documents"

	databasePrefixFlagName      = "database-prefix"
	databasePrefixEnvKey        = "EDV_DATABASE_PREFIX"
	databasePrefixFlagShorthand = "p"
	databasePrefixFlagUsage     = "An optional prefix to be used for the names for all databases." +
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
		"Supported options: mem, couchdb, mongodb " + commonEnvVarUsageText + localKMSSecretsDatabaseTypeEnvKey

	localKMSSecretsDatabaseURLFlagName  = "localkms-secrets-database-url"
	localKMSSecretsDatabaseURLEnvKey    = "EDV_LOCALKMS_SECRETS_DATABASE_URL" //nolint: gosec
	localKMSSecretsDatabaseURLFlagUsage = "The URL (or connection string) of the database for KMS secrets. " +
		"Not needed if using in-memory storage. " +
		"For CouchDB, include the username:password@ text if required. " + commonEnvVarUsageText +
		localKMSSecretsDatabaseURLEnvKey

	localKMSSecretsDatabasePrefixFlagName  = "localkms-secrets-database-prefix"
	localKMSSecretsDatabasePrefixEnvKey    = "EDV_LOCALKMS_SECRETS_DATABASE_PREFIX" //nolint: gosec
	localKMSSecretsDatabasePrefixFlagUsage = "An optional prefix to be used when creating and retrieving the underlying " +
		"KMS secrets database. " + commonEnvVarUsageText + localKMSSecretsDatabasePrefixEnvKey

	authTypeFlagName  = "auth-type"
	authTypeFlagUsage = "Comma-separated list of the types of authorization to enable. Authorization is " +
		"server-wide, not per-vault. Possible values [GNAP] [ZCAP]. If GNAP and ZCAP are both enabled, then a client " +
		"may authorize themselves with either one (rather than the two stacking on top of each other). " +
		"If no options are specified, then no authorization will be required. " + commonEnvVarUsageText + authTypeEnvKey
	authTypeEnvKey = "EDV_AUTH_TYPE"

	gnapAuthType = "gnap"
	zcapAuthType = "zcap"

	gnapSigningKeyPathFlagName  = "gnap-signing-key"
	gnapSigningKeyPathEnvKey    = "EDV_GNAP_SIGNING_KEY"
	gnapSigningKeyPathFlagUsage = "The path to the private key to use when signing GNAP introspection requests. " +
		"Required if using GNAP authorization. Ignored otherwise. " +
		commonEnvVarUsageText + gnapSigningKeyPathEnvKey

	authServerURLFlagName  = "auth-server-url"
	authServerURLEnvKey    = "EDV_AUTH_SERVER_URL"
	authServerURLFlagUsage = "The URL of the authorization server. " +
		"Required if using GNAP authorization. Ignored otherwise. " +
		commonEnvVarUsageText + authServerURLEnvKey

	corsEnableFlagName  = "cors-enable"
	corsEnableFlagUsage = "Enable cors. Possible values [true] [false]. " +
		"Defaults to false if not set. " + commonEnvVarUsageText + corsEnableEnvKey
	corsEnableEnvKey = "EDV_CORS_ENABLE"

	// Enables a /{VaultID}/batch endpoint for doing batching operations within a vault.
	batchExtensionName = "Batch"

	extensionsFlagName  = "with-extensions"
	extensionsFlagUsage = "Enables features that are extensions of the spec. " +
		"If set, must be a comma-separated list of some or all of the following possible values: " +
		"[" + batchExtensionName + "]. " +
		"If not set, then no extensions will be used and the EDV server will be " +
		"strictly conformant with the spec. These can all be safely enabled without breaking any core " +
		"EDV functionality or non-extension-aware clients. " + commonEnvVarUsageText + extensionsEnvKey
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
	logSpecEndpoint = "/logspec"

	proofType = "httpsig"
	gnapToken = "GNAP"
)

var logger = log.New("edv-rest")

var errInvalidDatabaseType = fmt.Errorf("database type not set to a valid type." +
	" run start --help to see the available options")

// nolint:gochecknoglobals
var supportedEDVStorageProviders = map[string]func(string, string, string, string, uint) (*edvprovider.Provider, error){
	databaseTypeCouchDBOption: func(databaseURL, configDatabaseName, documentDatabaseName, prefix string,
		retrievalPageSize uint) (*edvprovider.Provider, error) {
		couchDBProvider, err := couchdb.NewProvider(databaseURL, couchdb.WithDBPrefix(prefix))
		if err != nil {
			return nil, fmt.Errorf("failed to create new CouchDB storage provider: %w", err)
		}

		return edvprovider.NewProvider(couchDBProvider, configDatabaseName, documentDatabaseName, retrievalPageSize)
	},
	databaseTypeMemOption: func(_, documentDatabaseName, configDatabaseName, _ string,
		retrievalPageSize uint) (*edvprovider.Provider, error) {
		return edvprovider.NewProvider(mem.NewProvider(), configDatabaseName, documentDatabaseName, retrievalPageSize)
	},
	databaseTypeMongoDBOption: func(databaseURL, documentDatabaseName, configDatabaseName, prefix string,
		retrievalPageSize uint) (*edvprovider.Provider, error) {
		mongoDBProvider, err := mongodb.NewProvider(databaseURL, mongodb.WithDBPrefix(prefix))
		if err != nil {
			return nil, fmt.Errorf("failed to create new MongoDB storage provider: %w", err)
		}

		return edvprovider.NewProvider(mongoDBProvider, configDatabaseName, documentDatabaseName, retrievalPageSize)
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
	databaseTypeMongoDBOption: func(databaseURL, prefix string) (storage.Provider, error) {
		return mongodb.NewProvider(databaseURL, mongodb.WithDBPrefix(prefix))
	},
}

type edvParameters struct {
	srv                       server
	hostURL                   string
	databaseType              string
	databaseURL               string
	documentDatabaseName      string
	configDatabaseName        string
	databasePrefix            string
	databaseTimeout           uint64
	databaseRetrievalPageSize uint
	logLevel                  string
	didDomain                 string
	tlsConfig                 *tlsConfig
	gnapAuthEnabled           bool
	zcapAuthEnabled           bool
	gnapSigningKeyPath        string
	authServerURL             string
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

type authZCAPService interface {
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

func createStartCmd(srv server) *cobra.Command { //nolint: funlen,gocyclo,gocognit
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

			databaseType = strings.ToLower(databaseType)

			var databaseURL string
			if databaseType == databaseTypeMemOption {
				databaseURL = "N/A"
			} else {
				var errGetUserSetVar error
				databaseURL, errGetUserSetVar = cmdutils.GetUserSetVarFromString(cmd, databaseURLFlagName,
					databaseURLEnvKey, true)
				if errGetUserSetVar != nil {
					return errGetUserSetVar
				}
			}

			documentDatabaseName, err := cmdutils.GetUserSetVarFromString(cmd, documentDatabaseNameFlagName,
				documentDatabaseNameEnvKey, true)
			if err != nil {
				return err
			}

			if documentDatabaseName == "" {
				documentDatabaseName = defaultDocumentDatabaseName
			}

			configDatabaseName, err := cmdutils.GetUserSetVarFromString(cmd, configDatabaseNameFlagName,
				configDatabaseNameEnvKey, true)
			if err != nil {
				return err
			}

			if configDatabaseName == "" {
				configDatabaseName = defaultConfigDatabaseName
			}

			databasePrefix, err := cmdutils.GetUserSetVarFromString(cmd, databasePrefixFlagName,
				databasePrefixEnvKey, true)
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

			authTypesCSV, err := cmdutils.GetUserSetVarFromString(cmd, authTypeFlagName, authTypeEnvKey, true)
			if err != nil {
				return err
			}

			authTypes := strings.Split(authTypesCSV, ",")

			var gnapAuthEnabled, zcapAuthEnabled bool

			noAuthorizationModeSpecified := len(authTypes) == 1 && authTypes[0] == ""

			atLeastOneAuthorizationModeSpecified := !noAuthorizationModeSpecified

			if atLeastOneAuthorizationModeSpecified {
				for _, authType := range authTypes {
					authType = strings.ToLower(authType)

					switch authType {
					case gnapAuthType:
						gnapAuthEnabled = true
					case zcapAuthType:
						zcapAuthEnabled = true
					default:
						return fmt.Errorf("%s is not a valid auth type", authType)
					}
				}
			}

			var gnapSigningKeyPath, authServerURL string

			if gnapAuthEnabled {
				gnapSigningKeyPath, err = cmdutils.GetUserSetVarFromString(cmd, gnapSigningKeyPathFlagName,
					gnapSigningKeyPathEnvKey, true)
				if err != nil {
					return err
				}

				authServerURL, err = cmdutils.GetUserSetVarFromString(cmd, authServerURLFlagName,
					authServerURLEnvKey, true)
				if err != nil {
					return err
				}
			}

			corsEnable, err := getCORSEnable(cmd)
			if err != nil {
				return err
			}

			localKMSSecretsStorage, err := getLocalKMSSecretsStorageParameters(cmd, noAuthorizationModeSpecified)
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
				documentDatabaseName:      documentDatabaseName,
				configDatabaseName:        configDatabaseName,
				databasePrefix:            databasePrefix,
				databaseTimeout:           databaseTimeout,
				databaseRetrievalPageSize: databaseRetrievalPageSize,
				logLevel:                  loggingLevel,
				tlsConfig:                 tlsConfig,
				gnapAuthEnabled:           gnapAuthEnabled,
				zcapAuthEnabled:           zcapAuthEnabled,
				gnapSigningKeyPath:        gnapSigningKeyPath,
				authServerURL:             authServerURL,
				corsEnable:                corsEnable,
				localKMSSecretsStorage:    localKMSSecretsStorage,
				extensionsToEnable:        enabledExtensions,
				didDomain:                 didDomain,
			}
			return startEDV(parameters)
		},
	}
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
		if strings.EqualFold(extensionToEnable, batchExtensionName) {
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
	startCmd.Flags().StringP(configDatabaseNameFlagName, configDatabaseNameFlagShorthand, "",
		configDatabaseNameFlagUsage)
	startCmd.Flags().StringP(documentDatabaseNameFlagName, documentDatabaseNameFlagShorthand, "",
		documentDatabaseNameFlagUsage)
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
	startCmd.Flags().StringP(authTypeFlagName, "", "", authTypeFlagUsage)
	startCmd.Flags().StringP(gnapSigningKeyPathFlagName, "", "", gnapSigningKeyPathFlagUsage)
	startCmd.Flags().StringP(authServerURLFlagName, "", "", authServerURLFlagUsage)
	startCmd.Flags().StringP(extensionsFlagName, "", "", extensionsFlagUsage)
	startCmd.Flags().StringP(corsEnableFlagName, "", "", corsEnableFlagUsage)
	startCmd.Flags().StringP(didDomainFlagName, "", "", didDomainFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "", tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
}

type gnapRSClient interface {
	Introspect(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error)
}

type gnapService struct {
	Client    gnapRSClient
	RSPubKey  *jwk.JWK
	ClientKey *gnap.ClientKey
}

func startEDV(parameters *edvParameters) error { //nolint: funlen,gocyclo
	if parameters.logLevel != "" {
		setLogLevel(parameters.logLevel)
	}

	provider, err := createEDVProvider(parameters)
	if err != nil {
		return err
	}

	// create ZCAP auth service
	var authZCAPSvc authZCAPService

	if parameters.zcapAuthEnabled { // nolint: nestif
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

		loader, errLoader := createJSONLDDocumentLoader(storageProvider)
		if errLoader != nil {
			return errLoader
		}

		authZCAPSvc, err = zcapld.New(keyManager, crypto, storageProvider, loader, vdrResolver)
		if err != nil {
			return err
		}
	}

	var authGNAPSvc *gnapService

	if parameters.gnapAuthEnabled {
		privateJWK, publicJWK, errCreateGNAPSigningJWK := createGNAPSigningJWK(parameters.gnapSigningKeyPath)
		if errCreateGNAPSigningJWK != nil {
			return fmt.Errorf("failed to create gnap signing jwk: %w", errCreateGNAPSigningJWK)
		}

		rootCAs, errGetCertPool :=
			tlsutils.GetCertPool(parameters.tlsConfig.tlsUseSystemCertPool, parameters.tlsConfig.tlsCACerts)
		if errGetCertPool != nil {
			return errGetCertPool
		}

		tlsConfig := &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		}

		httpClient := &http.Client{
			Timeout: time.Minute,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}

		gnapRSClient, errNewClient := rs.NewClient(
			&httpsig.Signer{SigningKey: privateJWK},
			httpClient,
			parameters.authServerURL,
		)
		if errNewClient != nil {
			return errNewClient
		}

		authGNAPSvc = &gnapService{
			Client: gnapRSClient,
			ClientKey: &gnap.ClientKey{
				Proof: proofType,
				JWK:   *publicJWK,
			},
		}
	}

	edvService, err := restapi.New(&operation.Config{
		Provider:             provider,
		AuthZCAPService:      authZCAPSvc,
		AuthZCAPEnabled:      parameters.zcapAuthEnabled,
		EnabledExtensions:    parameters.extensionsToEnable,
		DocumentDatabaseName: parameters.documentDatabaseName,
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
			authZCAPSvc, authGNAPSvc, router))
}

func createGNAPSigningJWK(keyFilePath string) (*jwk.JWK, *jwk.JWK, error) {
	b, err := ioutil.ReadFile(keyFilePath) //nolint:gosec // false positive
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}

	block, _ := pem.Decode(b)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, nil, fmt.Errorf("invalid pem")
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse private key: %w", err)
	}

	// TODO: make key type configurable
	privateJWK := &jwk.JWK{
		JSONWebKey: jose.JSONWebKey{
			Key:       key,
			Algorithm: "ES256",
		},
		Kty: "EC",
		Crv: "P-256",
	}

	publicJWK := &jwk.JWK{
		JSONWebKey: privateJWK.Public(),
		Kty:        "EC",
		Crv:        "P-256",
	}

	return privateJWK, publicJWK, nil
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

func createEDVProvider(parameters *edvParameters) (*edvprovider.Provider, error) {
	var edvProv *edvprovider.Provider

	providerFunc, supported := supportedEDVStorageProviders[parameters.databaseType]
	if !supported {
		return nil, errInvalidDatabaseType
	}

	err := retry(func() error {
		var openErr error
		edvProv, openErr =
			providerFunc(parameters.databaseURL, parameters.documentDatabaseName, parameters.configDatabaseName,
				parameters.databasePrefix, parameters.databaseRetrievalPageSize)
		return openErr
	}, parameters.databaseTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", parameters.databaseType, err)
	}

	return edvProv, nil
}

func constructHandlers(enableCORS bool, authZCAPSvc authZCAPService, authGNAPSvc *gnapService,
	routerHandler http.Handler) http.Handler {
	var gnapAuthHandlerInstance *gnapAuthHandler

	var zcapAuthHandlerInstance *zcapAuthHandler

	if authGNAPSvc != nil {
		gnapAuthHandlerInstance = &gnapAuthHandler{
			authGNAPSvc:   authGNAPSvc,
			routerHandler: routerHandler,
		}
	}

	if authZCAPSvc != nil {
		zcapAuthHandlerInstance = &zcapAuthHandler{
			authZCAPSvc:   authZCAPSvc,
			routerHandler: routerHandler,
		}
	}

	if authGNAPSvc != nil || authZCAPSvc != nil {
		routerHandler = &authHandler{
			gnapAuthHandler: gnapAuthHandlerInstance,
			zcapAuthHandler: zcapAuthHandlerInstance,
			routerHandler:   routerHandler,
		}
	}

	if enableCORS {
		return cors.New(
			cors.Options{
				AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete},
				AllowedHeaders: []string{"*"},
				ExposedHeaders: []string{"Location"},
			},
		).Handler(routerHandler)
	}

	return routerHandler
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
		"GNAP auth enabled?: %t, ZCAP auth enabled?: %t, CORS enabled?: %t, Database timeout: %d, "+
		"Local KMS secrets storage: %+v, Log level: %s",
		parameters.hostURL, parameters.databaseType, parameters.databaseURL, parameters.databasePrefix,
		parameters.tlsConfig.certFile, parameters.tlsConfig.keyFile, parameters.extensionsToEnable,
		parameters.gnapAuthEnabled, parameters.zcapAuthEnabled, parameters.corsEnable, parameters.databaseTimeout,
		parameters.localKMSSecretsStorage, parameters.logLevel)
}

// authHandler does an authorization check and then passes the request to routerHandler for handling of the standard
// EDV operations.
type authHandler struct {
	gnapAuthHandler *gnapAuthHandler
	zcapAuthHandler *zcapAuthHandler
	routerHandler   http.Handler
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.RequestURI == healthCheckPath || r.RequestURI == logSpecEndpoint {
		a.routerHandler.ServeHTTP(w, r)

		return
	}

	if a.gnapAuthHandler != nil && headerContainsGNAPToken(r.Header) {
		a.gnapAuthHandler.ServeHTTP(w, r)

		return
	}

	if a.zcapAuthHandler != nil {
		if r.RequestURI == createVaultPath {
			a.routerHandler.ServeHTTP(w, r)

			return
		}

		if headerContainsCapabilityInvocation(r.Header) {
			a.zcapAuthHandler.ServeHTTP(w, r)

			return
		}
	}

	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func headerContainsGNAPToken(header http.Header) bool {
	authorizationString := header.Get("Authorization")

	return strings.Contains(authorizationString, gnapToken)
}

func headerContainsCapabilityInvocation(header http.Header) bool {
	capabilityInvocation := header.Get("Capability-Invocation")

	return capabilityInvocation != ""
}

type gnapAuthHandler struct {
	authGNAPSvc   *gnapService
	routerHandler http.Handler
}

func (h *gnapAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tokenHeader := strings.Split(strings.Trim(r.Header.Get("Authorization"), " "), " ")

	if len(tokenHeader) < 2 || tokenHeader[0] != gnapToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	introspectReq := &gnap.IntrospectRequest{
		ResourceServer: &gnap.RequestClient{
			Key: h.authGNAPSvc.ClientKey,
		},
		// Proof: proofType, // TODO: Enable httpsig verification
		AccessToken: tokenHeader[1],
	}

	resp, err := h.authGNAPSvc.Client.Introspect(introspectReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("introspect token: %s", err.Error()), http.StatusInternalServerError)

		return
	}

	if !resp.Active {
		http.Error(w, "unauthorized", http.StatusUnauthorized)

		return
	}

	h.routerHandler.ServeHTTP(w, r)
}

type zcapAuthHandler struct {
	authZCAPSvc   authZCAPService
	routerHandler http.Handler
}

func (h *zcapAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := strings.SplitAfter(r.RequestURI, "/")

	authHandler, err := h.authZCAPSvc.Handler(strings.TrimSuffix(s[2], "/"), r, w,
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

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

func createJSONLDDocumentLoader(provider storage.Provider) (*ld.DocumentLoader, error) {
	contextStore, err := ldstore.NewContextStore(provider)
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(provider)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	ldStore := &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	documentLoader, err := ld.NewDocumentLoader(ldStore)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return documentLoader, nil
}
