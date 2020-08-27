/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/restapi/logspec"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/edvprovider/couchdbedvprovider"
	"github.com/trustbloc/edv/pkg/edvprovider/memedvprovider"
	"github.com/trustbloc/edv/pkg/restapi"
	"github.com/trustbloc/edv/pkg/restapi/healthcheck"
)

const (
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
		" For CouchDB, include the username:password@ text if required." +
		" Alternatively, this can be set with the following environment variable: " + databaseURLEnvKey

	databasePrefixFlagName      = "database-prefix"
	databasePrefixEnvKey        = "EDV_DATABASE_PREFIX"
	databasePrefixFlagShorthand = "p"
	databasePrefixFlagUsage     = "An optional prefix to be used when creating and retrieving underlying databases." +
		" This followed by an underscore will be prepended to any incoming vault IDs received in REST calls before" +
		" creating or accessing underlying databases." +
		" Alternatively, this can be set with the following environment variable: " + databasePrefixEnvKey

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
)

var logger = log.New("edv-rest")

var errInvalidDatabaseType = fmt.Errorf("database type not set to a valid type." +
	" run start --help to see the available options")

type edvParameters struct {
	srv            server
	hostURL        string
	databaseType   string
	databaseURL    string
	databasePrefix string
	logLevel       string
	tlsConfig      *tlsConfig
}

type tlsConfig struct {
	certFile string
	keyFile  string
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

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start EDV",
		Long:  "Start EDV",
		RunE: func(cmd *cobra.Command, args []string) error {
			hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
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

			loggingLevel, err := cmdutils.GetUserSetVarFromString(cmd, logLevelFlagName, logLevelEnvKey, true)
			if err != nil {
				return err
			}

			tlsConfig, err := getTLS(cmd)
			if err != nil {
				return err
			}

			parameters := &edvParameters{
				srv:            srv,
				hostURL:        hostURL,
				databaseType:   databaseType,
				databaseURL:    databaseURL,
				databasePrefix: databasePrefix,
				logLevel:       loggingLevel,
				tlsConfig:      tlsConfig,
			}
			return startEDV(parameters)
		},
	}
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

	return &tlsConfig{certFile: tlsCertFile, keyFile: tlsKeyFile}, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, databaseURLFlagShorthand, "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, databasePrefixFlagShorthand, "", databasePrefixFlagUsage)
	startCmd.Flags().StringP(logLevelFlagName, logLevelFlagShorthand, "", logLevelPrefixFlagUsage)
	startCmd.Flags().StringP(tlsCertFileFlagName, tlsCertFileFlagShorthand, "", tlsCertFileFlagUsage)
	startCmd.Flags().StringP(tlsKeyFileFlagName, tlsKeyFileFlagShorthand, "", tlsKeyFileFlagUsage)
}

func startEDV(parameters *edvParameters) error {
	if parameters.logLevel != "" {
		setLogLevel(parameters.logLevel)
	}

	provider, err := createEDVProvider(parameters)
	if err != nil {
		return err
	}

	edvService, err := restapi.New(provider)
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

	logger.Infof(`Starting EDV REST server with the following parameters: 
Host URL: %s
Database type: %s
Database URL: %s
Database prefix: %s
TLS certificate file: %s
TLS key file: %s`, parameters.hostURL, parameters.databaseType, parameters.databaseURL, parameters.databasePrefix,
		parameters.tlsConfig.certFile, parameters.tlsConfig.keyFile)

	return parameters.srv.ListenAndServe(parameters.hostURL,
		parameters.tlsConfig.certFile, parameters.tlsConfig.keyFile, constructCORSHandler(router))
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

	switch {
	case strings.EqualFold(parameters.databaseType, databaseTypeMemOption):
		edvProv = memedvprovider.NewProvider()

		logger.Warnf("encrypted indexing and querying is disabled since they are not supported by memstore")
	case strings.EqualFold(parameters.databaseType, databaseTypeCouchDBOption):
		couchDBEDVProv, err := couchdbedvprovider.NewProvider(parameters.databaseURL, parameters.databasePrefix)
		if err != nil {
			return nil, err
		}

		edvProv = couchDBEDVProv
	default:
		return edvProv, errInvalidDatabaseType
	}

	return edvProv, nil
}

func constructCORSHandler(handler http.Handler) http.Handler {
	return cors.New(
		cors.Options{
			AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodPut},
			AllowedHeaders: []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "Authorization"},
		},
	).Handler(handler)
}
