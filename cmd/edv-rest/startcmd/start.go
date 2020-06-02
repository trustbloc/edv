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
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/edvprovider/couchdbedvprovider"
	"github.com/trustbloc/edv/pkg/edvprovider/memedvprovider"
	"github.com/trustbloc/edv/pkg/restapi/edv"
	cmdutils "github.com/trustbloc/edv/pkg/utils/cmd"
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
	logLevelEnvKey          = "LOG_LEVEL"
	logLevelFlagShorthand   = "l"
	logLevelPrefixFlagUsage = "Logging level to set. Supported options: critical, error, warning, info, debug." +
		`Defaults to "info" if not set. Setting to "debug" may adversely impact performance. Alternatively, this can be ` +
		"set with the following environment variable: " + logLevelEnvKey

	logLevelCritical = "critical"
	logLevelError    = "error"
	logLevelWarn     = "warning"
	logLevelInfo     = "info"
	logLevelDebug    = "debug"
)

var logger = log.New("edv-rest")

var errMissingHostURL = fmt.Errorf("host URL not provided")
var errInvalidDatabaseType = fmt.Errorf("database type not set to a valid type." +
	" run start --help to see the available options")

type edvParameters struct {
	srv            server
	hostURL        string
	databaseType   string
	databaseURL    string
	databasePrefix string
	logLevel       string
}

type server interface {
	ListenAndServe(host string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler) error {
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
			hostURL, err := cmdutils.GetUserSetVar(cmd, hostURLFlagName, hostURLEnvKey, false)
			if err != nil {
				return err
			}

			databaseType, err := cmdutils.GetUserSetVar(cmd, databaseTypeFlagName, databaseTypeEnvKey, false)
			if err != nil {
				return err
			}

			databaseURL, err := cmdutils.GetUserSetVar(cmd, databaseURLFlagName, databaseURLEnvKey, true)
			if err != nil {
				return err
			}

			databasePrefix, err := cmdutils.GetUserSetVar(cmd, databasePrefixFlagName, databasePrefixEnvKey, true)
			if err != nil {
				return err
			}

			loggingLevel, err := cmdutils.GetUserSetVar(cmd, logLevelFlagName, logLevelEnvKey, true)
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
			}
			return startEDV(parameters)
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(databaseTypeFlagName, databaseTypeFlagShorthand, "", databaseTypeFlagUsage)
	startCmd.Flags().StringP(databaseURLFlagName, databaseURLFlagShorthand, "", databaseURLFlagUsage)
	startCmd.Flags().StringP(databasePrefixFlagName, databasePrefixFlagShorthand, "", databasePrefixFlagUsage)
	startCmd.Flags().StringP(logLevelFlagName, logLevelFlagShorthand, "", logLevelPrefixFlagUsage)
}

func startEDV(parameters *edvParameters) error {
	setLogLevel(parameters.logLevel)

	if parameters.hostURL == "" {
		return errMissingHostURL
	}

	provider, err := createEDVProvider(parameters)
	if err != nil {
		return err
	}

	edvService, err := edv.New(provider)
	if err != nil {
		return err
	}

	handlers := edvService.GetOperations()
	router := mux.NewRouter()
	router.UseEncodedPath()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	logger.Infof("Starting edv rest server on host %s", parameters.hostURL)
	err = parameters.srv.ListenAndServe(parameters.hostURL, router)

	return err
}

func setLogLevel(userLogLevel string) {
	logLevel, err := log.ParseLevel(userLogLevel)
	if err != nil {
		logger.Warnf(`"%s" is not a valid logging level.` +
			`It must be one of the following: critical,error,warning,info,debug. Defaulting to "info".`)

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
