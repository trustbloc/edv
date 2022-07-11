/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/auth/spi/gnap"
	"github.com/trustbloc/edge-core/pkg/log"
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host, certFile, keyFile string, handler http.Handler) error {
	return nil
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start EDV", startCmd.Short)
	require.Equal(t, "Start EDV", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithMissingArg(t *testing.T) {
	t.Run("test missing host url arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		err := startCmd.Execute()

		require.Equal(t,
			"Neither host-url (command line flag) nor EDV_HOST_URL (environment variable) have been set.",
			err.Error())
	})
	t.Run("test missing database url arg - couchdb", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "couchdb", "--" +
			databaseTimeoutFlagName, "1"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.EqualError(t, err, "failed to connect to couchdb: "+
			"failed to create new CouchDB storage provider: failed to ping couchDB: url can't be blank")
	})
	t.Run("test missing kms database url arg - couchdb", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem", "--" +
				localKMSSecretsDatabaseTypeFlagName, "couchdb", "--" + authTypeFlagName, "ZCAP",
			"--" + databaseTimeoutFlagName, "1",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "Neither localkms-secrets-database-url (command line flag) nor "+
			"EDV_LOCALKMS_SECRETS_DATABASE_URL (environment variable) have been set")
	})

	t.Run("test auth invalid type", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + authTypeFlagName, "wrong",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.EqualError(t, err, "wrong is not a valid auth type")
	})
}

func TestStartEDV_FailToCreateEDVProvider(t *testing.T) {
	parameters := &edvParameters{hostURL: "NotBlank", databaseType: "NotAValidType"}

	err := startEDV(parameters)
	require.Equal(t, errInvalidDatabaseType, err)
}

func TestStartCmdValidArgs(t *testing.T) {
	t.Run("auth type: none", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + localKMSSecretsDatabaseTypeFlagName, "mem",
			"--" + extensionsFlagName, batchExtensionName, "--" + corsEnableFlagName, "true",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NoError(t, err)
	})
	t.Run("auth type: ZCAP", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + localKMSSecretsDatabaseTypeFlagName, "mem",
			"--" + extensionsFlagName, batchExtensionName, "--" + corsEnableFlagName, "true",
			"--" + authTypeFlagName, "ZCAP",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NoError(t, err)
	})
	t.Run("auth type: GNAP", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		testSigningKeyFileName := "testSigningKeyFile-" + uuid.New().String()

		const testGnapKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINZmobflCTvl6BBzGpbbhA+KFx6+Sariitjz6wIsU1jEoAoGCCqGSM49
AwEHoUQDQgAEnCacKwI7j9SuvH150dAZ5sEbpHMCMkmjVjJbS5gD/XXE3HgNlHc+
oohTo0aQ9u6MA4AlUFjcSkTTQtObtD7RdQ==
-----END EC PRIVATE KEY-----`

		err := os.WriteFile(testSigningKeyFileName, []byte(testGnapKey), 0o600)
		require.NoError(t, err)

		defer func() {
			require.NoError(t, os.Remove(testSigningKeyFileName))
		}()

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + localKMSSecretsDatabaseTypeFlagName, "mem",
			"--" + extensionsFlagName, batchExtensionName, "--" + corsEnableFlagName, "true",
			"--" + authTypeFlagName, "GNAP", "--" + gnapSigningKeyPathFlagName, testSigningKeyFileName,
			"--" + authServerURLFlagName, "someURL",
		}
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})
}

func TestStartCmdLogLevels(t *testing.T) {
	t.Run(`Log level not specified - default to "info"`, func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Log level: critical", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelCritical,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.CRITICAL, log.GetLevel(""))
	})
	t.Run("Log level: error", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelError,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.ERROR, log.GetLevel(""))
	})
	t.Run("Log level: warn", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelWarn,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.WARNING, log.GetLevel(""))
	})
	t.Run("Log level: info", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelInfo,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Log level: debug", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelDebug,
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})
	t.Run("Invalid log level - default to info", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, "mango",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func TestStartCmdBlankTLSArgs(t *testing.T) {
	t.Run("Blank cert file arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + tlsCertFileFlagName, "",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.EqualError(t, err, fmt.Sprintf("%s value is empty", tlsCertFileFlagName))
	})
	t.Run("Blank key file arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + tlsKeyFileFlagName, "",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.EqualError(t, err, fmt.Sprintf("%s value is empty", tlsKeyFileFlagName))
	})
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.Nil(t, err)
	err = os.Setenv(databaseTypeEnvKey, "mem")
	require.Nil(t, err)

	err = startCmd.Execute()

	require.Nil(t, err)
}

func TestStartCmdFailToCreateGNAPSigningJWK(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	testSigningKeyFileName := "testSigningKeyFile-" + uuid.New().String()

	err := os.WriteFile(testSigningKeyFileName, []byte("Not a valid GNAP signing key"), 0o600)
	require.NoError(t, err)

	defer func() {
		require.NoError(t, os.Remove(testSigningKeyFileName))
	}()

	args := []string{
		"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
		"--" + localKMSSecretsDatabaseTypeFlagName, "mem",
		"--" + extensionsFlagName, batchExtensionName, "--" + corsEnableFlagName, "true",
		"--" + authTypeFlagName, "GNAP", "--" + gnapSigningKeyPathFlagName, testSigningKeyFileName,
		"--" + authServerURLFlagName, "someURL",
	}
	startCmd.SetArgs(args)

	err = startCmd.Execute()
	require.EqualError(t, err, "failed to create gnap signing jwk: invalid pem")
}

func TestKeyManager(t *testing.T) {
	t.Run("Error - invalid database type", func(t *testing.T) {
		parameters := edvParameters{localKMSSecretsStorage: &storageParameters{storageType: "NotARealDatabaseType"}}

		provider, err := createKeyManager(&parameters)
		require.Nil(t, provider)
		require.Equal(t, errInvalidDatabaseType, err)
	})

	t.Run("Error - CouchDB url is invalid", func(t *testing.T) {
		parameters := edvParameters{localKMSSecretsStorage: &storageParameters{
			storageType: databaseTypeCouchDBOption,
			storageURL:  "%",
		}, databaseTimeout: 1}

		provider, err := createKeyManager(&parameters)
		require.Error(t, err)
		require.Nil(t, provider)
		require.Contains(t, err.Error(), "failed to connect to couchdb: failed to ping couchDB")
	})
}

func TestCreateProvider(t *testing.T) {
	t.Run("Successfully create memory storage provider", func(t *testing.T) {
		parameters := edvParameters{
			databaseType:         databaseTypeMemOption,
			configDatabaseName:   defaultConfigDatabaseName,
			documentDatabaseName: defaultDocumentDatabaseName,
		}

		provider, err := createEDVProvider(&parameters)
		require.NoError(t, err)
		require.NotNil(t, provider)
	})
	t.Run("Error - invalid database type", func(t *testing.T) {
		parameters := edvParameters{databaseType: "NotARealDatabaseType"}

		provider, err := createEDVProvider(&parameters)
		require.Nil(t, provider)
		require.Equal(t, errInvalidDatabaseType, err)
	})
	t.Run("Error - CouchDB url is blank", func(t *testing.T) {
		parameters := edvParameters{databaseType: databaseTypeCouchDBOption, databaseURL: "", databaseTimeout: 1}

		provider, err := createEDVProvider(&parameters)
		require.Nil(t, provider)
		require.EqualError(t, err, "failed to connect to couchdb: "+
			"failed to create new CouchDB storage provider: failed to ping couchDB: url can't be blank")
	})
	t.Run("Error - CouchDB url is invalid", func(t *testing.T) {
		parameters := edvParameters{databaseType: databaseTypeCouchDBOption, databaseURL: "%", databaseTimeout: 1}

		provider, err := createEDVProvider(&parameters)
		require.Nil(t, provider)
		require.EqualError(t, err, "failed to connect to couchdb: "+
			"failed to create new CouchDB storage provider: "+
			`failed to ping couchDB: parse "http://%": invalid URL escape "%"`)
	})
}

func TestHttpHandler_ServeHTTP(t *testing.T) {
	t.Run("test create vault request", func(t *testing.T) {
		m := &mockHTTPHandler{serveHTTPFun: func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.RequestURI, createVaultPath)
		}}
		h := zcapAuthHandler{routerHandler: m, authZCAPSvc: &mockAuthService{}}
		h.ServeHTTP(&httptest.ResponseRecorder{}, &http.Request{RequestURI: createVaultPath})
	})

	t.Run("test health check request", func(t *testing.T) {
		m := &mockHTTPHandler{serveHTTPFun: func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, r.RequestURI, healthCheckPath)
		}}
		h := zcapAuthHandler{routerHandler: m, authZCAPSvc: &mockAuthService{}}
		h.ServeHTTP(&httptest.ResponseRecorder{}, &http.Request{RequestURI: healthCheckPath})
	})

	t.Run("test error from auth handler", func(t *testing.T) {
		h := zcapAuthHandler{authZCAPSvc: &mockAuthService{
			handlerFunc: func(resourceID string, req *http.Request, w http.ResponseWriter,
				next http.HandlerFunc) (http.HandlerFunc, error) {
				return nil, fmt.Errorf("failed to create auth handler")
			},
		}}

		responseRecorder := httptest.NewRecorder()
		h.ServeHTTP(responseRecorder, &http.Request{RequestURI: createVaultPath + "/vaultID"})

		require.Contains(t, responseRecorder.Body.String(), "failed to create auth handler")
	})

	t.Run("test ZCAP auth handler success", func(t *testing.T) {
		h := zcapAuthHandler{authZCAPSvc: &mockAuthService{
			handlerFunc: func(resourceID string, req *http.Request, w http.ResponseWriter,
				next http.HandlerFunc) (http.HandlerFunc, error) {
				return func(w http.ResponseWriter, r *http.Request) {
					require.Equal(t, r.RequestURI, createVaultPath+"/vaultID")
				}, nil
			},
		}}

		responseRecorder := httptest.NewRecorder()
		h.ServeHTTP(responseRecorder, &http.Request{RequestURI: createVaultPath + "/vaultID"})

		require.Equal(t, http.StatusOK, responseRecorder.Code)
	})

	t.Run("test GNAP auth handler", func(t *testing.T) {
		t.Run("Request URI is health check path, so auth check is skipped", func(t *testing.T) {
			h := gnapAuthHandler{routerHandler: &mockHTTPHandler{}}

			responseRecorder := httptest.NewRecorder()
			h.ServeHTTP(responseRecorder, &http.Request{RequestURI: healthCheckPath})

			require.Equal(t, http.StatusOK, responseRecorder.Code)
		})
		t.Run("Missing token header", func(t *testing.T) {
			h := gnapAuthHandler{}

			responseRecorder := httptest.NewRecorder()
			h.ServeHTTP(responseRecorder, &http.Request{})

			require.Equal(t, http.StatusUnauthorized, responseRecorder.Code)
			require.Contains(t, responseRecorder.Body.String(), "unauthorized")
		})
		t.Run("Failure while introspecting token", func(t *testing.T) {
			h := gnapAuthHandler{
				authGNAPSvc: &gnapService{
					Client:    &mockGNAPRSClient{errIntrospect: errors.New("introspection error")},
					RSPubKey:  nil,
					ClientKey: nil,
				},
			}

			responseRecorder := httptest.NewRecorder()
			h.ServeHTTP(responseRecorder,
				&http.Request{
					Header: map[string][]string{"Authorization": {"GNAP aeeac7c8-0cf7-401b-af5b-5b1806204346"}},
				})

			require.Equal(t, http.StatusInternalServerError, responseRecorder.Code)
			require.Contains(t, responseRecorder.Body.String(), "introspect token: introspection error")
		})
		t.Run("Token is not active", func(t *testing.T) {
			h := gnapAuthHandler{
				authGNAPSvc: &gnapService{
					Client:    &mockGNAPRSClient{},
					RSPubKey:  nil,
					ClientKey: nil,
				},
			}

			responseRecorder := httptest.NewRecorder()
			h.ServeHTTP(responseRecorder,
				&http.Request{
					Header: map[string][]string{"Authorization": {"GNAP aeeac7c8-0cf7-401b-af5b-5b1806204346"}},
				})

			require.Equal(t, http.StatusUnauthorized, responseRecorder.Code)
			require.Contains(t, responseRecorder.Body.String(), "unauthorized")
		})
		t.Run("Token is active", func(t *testing.T) {
			h := gnapAuthHandler{
				authGNAPSvc: &gnapService{
					Client:    &mockGNAPRSClient{active: true},
					RSPubKey:  nil,
					ClientKey: nil,
				},
				routerHandler: &mockHTTPHandler{},
			}

			responseRecorder := httptest.NewRecorder()
			h.ServeHTTP(responseRecorder,
				&http.Request{
					Header: map[string][]string{"Authorization": {"GNAP aeeac7c8-0cf7-401b-af5b-5b1806204346"}},
				})

			require.Equal(t, http.StatusOK, responseRecorder.Code)
		})
	})
}

type mockGNAPRSClient struct {
	errIntrospect error
	active        bool
}

func (m *mockGNAPRSClient) Introspect(req *gnap.IntrospectRequest) (*gnap.IntrospectResponse, error) {
	if m.errIntrospect != nil {
		return nil, m.errIntrospect
	}

	return &gnap.IntrospectResponse{Active: m.active}, nil
}

type mockHTTPHandler struct {
	serveHTTPFun func(w http.ResponseWriter, r *http.Request)
}

func (m *mockHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m.serveHTTPFun != nil {
		m.serveHTTPFun(w, r)
	}
}

type mockAuthService struct {
	handlerFunc func(resourceID string, req *http.Request, w http.ResponseWriter,
		next http.HandlerFunc) (http.HandlerFunc, error)
}

func (m *mockAuthService) Create(resourceID, verificationMethod string) ([]byte, error) {
	return nil, nil
}

func (m *mockAuthService) Handler(resourceID string, req *http.Request, w http.ResponseWriter,
	next http.HandlerFunc) (http.HandlerFunc, error) {
	if m.handlerFunc != nil {
		return m.handlerFunc(resourceID, req, w, next)
	}

	return nil, nil
}

func TestListenAndServe(t *testing.T) {
	h := HTTPServer{}
	err := h.ListenAndServe("localhost:8080", "test.key", "test.cert", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "open test.key: no such file or directory")
}

func TestGetTimeout(t *testing.T) {
	t.Run("failure - invalid timeout flag", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{
			"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + databaseTimeoutFlagName, "NotAnInt",
		}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.EqualError(t, err,
			"failed to parse timeout NotAnInt: strconv.Atoi: parsing \"NotAnInt\": invalid syntax")
	})
}

func TestStartCmdEmptyDomain(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{
		"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
		"--" + databaseTimeoutFlagName, "NotAnInt",
		"--" + didDomainFlagName, "",
	}

	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.EqualError(t, err, "did-domain value is empty")
}

func TestStartCmdInvalidSystemCertPool(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{
		"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
		"--" + tlsSystemCertPoolFlagName, "test",
	}

	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.EqualError(t, err, "strconv.ParseBool: parsing \"test\": invalid syntax")
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	t.Helper()

	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}
