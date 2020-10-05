/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"
	"github.com/trustbloc/edge-core/pkg/storage"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/edvprovider/couchdbedvprovider"
	"github.com/trustbloc/edv/pkg/edvprovider/memedvprovider"
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host, certFile, keyFile string, handler http.Handler) error {
	return nil
}

type mockDBInitializer struct{}

func (i *mockDBInitializer) CreateConfigStore(provider edvprovider.EDVProvider) error {
	return nil
}

type mockEDVProvider struct {
	errCreateStore error
	errOpenStore   error
}

func (m *mockEDVProvider) CreateStore(string) error {
	return m.errCreateStore
}

func (m *mockEDVProvider) OpenStore(string) (edvprovider.EDVStore, error) {
	return nil, m.errOpenStore
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start EDV", startCmd.Short)
	require.Equal(t, "Start EDV", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

	err := startCmd.Execute()

	require.Equal(t,
		"Neither host-url (command line flag) nor EDV_HOST_URL (environment variable) have been set.",
		err.Error())
}

func TestStartEDV_FailToCreateEDVProvider(t *testing.T) {
	parameters := &edvParameters{hostURL: "NotBlank", databaseType: "NotAValidType"}

	err := startEDV(parameters, &mockDBInitializer{})
	require.Equal(t, errInvalidDatabaseType, err)
}

func TestStartCmdValidArgs(t *testing.T) {
	t.Run("database type: mem", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.NoError(t, err)
	})
	t.Run("database type: couchdb", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080",
			"--" + databaseTypeFlagName, "couchdb", "--" + databaseURLFlagName, "localhost:8080"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.NoError(t, err)
	})
}

func TestStartCmdLogLevels(t *testing.T) {
	t.Run(`Log level not specified - default to "info"`, func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Log level: critical", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelCritical}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.CRITICAL, log.GetLevel(""))
	})
	t.Run("Log level: error", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelError}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.ERROR, log.GetLevel(""))
	})
	t.Run("Log level: warn", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelWarn}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.WARNING, log.GetLevel(""))
	})
	t.Run("Log level: info", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelInfo}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Log level: debug", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelDebug}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})
	t.Run("Invalid log level - default to info", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, "mango"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
}

func TestStartCmdBlankTLSArgs(t *testing.T) {
	t.Run("Blank cert file arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + tlsCertFileFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.EqualError(t, err, fmt.Sprintf("%s value is empty", tlsCertFileFlagName))
	})
	t.Run("Blank key file arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + tlsKeyFileFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.EqualError(t, err, fmt.Sprintf("%s value is empty", tlsKeyFileFlagName))
	})
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{}, &mockDBInitializer{})

	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.Nil(t, err)
	err = os.Setenv(databaseTypeEnvKey, "mem")
	require.Nil(t, err)

	err = startCmd.Execute()

	require.Nil(t, err)
}

func TestCreateProvider(t *testing.T) {
	t.Run("Successfully create memory storage provider", func(t *testing.T) {
		parameters := edvParameters{databaseType: databaseTypeMemOption}

		provider, err := createEDVProvider(&parameters)
		require.NoError(t, err)
		require.IsType(t, &memedvprovider.MemEDVProvider{}, provider)
	})
	t.Run("Successfully create CouchDB storage provider", func(t *testing.T) {
		parameters := edvParameters{databaseType: databaseTypeCouchDBOption, databaseURL: "something"}

		provider, err := createEDVProvider(&parameters)
		require.NoError(t, err)
		require.IsType(t, &couchdbedvprovider.CouchDBEDVProvider{}, provider)
	})
	t.Run("Error - invalid database type", func(t *testing.T) {
		parameters := edvParameters{databaseType: "NotARealDatabaseType"}

		provider, err := createEDVProvider(&parameters)
		require.Nil(t, provider)
		require.Equal(t, errInvalidDatabaseType, err)
	})
	t.Run("Error - CouchDB url is blank", func(t *testing.T) {
		parameters := edvParameters{databaseType: databaseTypeCouchDBOption, databaseURL: ""}

		provider, err := createEDVProvider(&parameters)
		require.Nil(t, provider)
		require.Equal(t, couchdbedvprovider.ErrMissingDatabaseURL, err)
	})
	t.Run("Error - CouchDB url is invalid", func(t *testing.T) {
		parameters := edvParameters{databaseType: databaseTypeCouchDBOption, databaseURL: "%"}

		provider, err := createEDVProvider(&parameters)
		require.Nil(t, provider)
		require.EqualError(t, err, `failure while instantiate Kivik CouchDB client: parse "http://%": invalid URL escape "%"`)
	})
}

func TestListenAndServe(t *testing.T) {
	h := HTTPServer{}
	err := h.ListenAndServe("localhost:8080", "test.key", "test.cert", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "open test.key: no such file or directory")
}

func TestActualDbInitializer_CreateConfigStore(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		provider := memedvprovider.NewProvider()

		dbInitializer := ActualDBInitializer{}

		err := dbInitializer.CreateConfigStore(provider)
		require.NoError(t, err)
	})
	t.Run("Success - create duplicate store", func(t *testing.T) {
		dbInitializer := ActualDBInitializer{}

		err := dbInitializer.CreateConfigStore(&mockEDVProvider{errCreateStore: storage.ErrDuplicateStore})
		require.Nil(t, err)
	})
	t.Run("failure - other error in create store", func(t *testing.T) {
		dbInitializer := ActualDBInitializer{}
		errTest := errors.New("error in create store")

		err := dbInitializer.CreateConfigStore(&mockEDVProvider{errCreateStore: errTest})
		require.Equal(t, fmt.Errorf(errCreateConfigStore, errTest), err)
	})
	t.Run("failure - open store error", func(t *testing.T) {
		dbInitializer := ActualDBInitializer{}
		errTest := errors.New("error in open store")

		err := dbInitializer.CreateConfigStore(&mockEDVProvider{errOpenStore: errTest})
		require.Equal(t, fmt.Errorf(errCreateConfigStore, errTest), err)
	})
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}
