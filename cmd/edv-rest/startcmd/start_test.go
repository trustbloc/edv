/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/http"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edv/pkg/edvprovider/couchdbedvprovider"
	"github.com/trustbloc/edv/pkg/edvprovider/memedvprovider"
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host string, handler http.Handler) error {
	return nil
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start EDV", startCmd.Short)
	require.Equal(t, "Start EDV", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithBlankHostArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{"--" + hostURLFlagName, "", "--" + databaseTypeFlagName, "mem"}
	startCmd.SetArgs(args)

	err := startCmd.Execute()

	require.Equal(t, errMissingHostURL.Error(), err.Error())
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := startCmd.Execute()

	require.Equal(t,
		"neither host-url (command line flag) nor EDV_HOST_URL (environment variable) have been set",
		err.Error())
}

func TestStartEDVWithBlankHost(t *testing.T) {
	parameters := &edvParameters{hostURL: ""}

	err := startEDV(parameters)
	require.NotNil(t, err)
	require.Equal(t, errMissingHostURL, err)
}

func TestStartEDV_FailToCreateEDVProvider(t *testing.T) {
	parameters := &edvParameters{hostURL: "NotBlank", databaseType: "NotAValidType"}

	err := startEDV(parameters)
	require.Equal(t, errInvalidDatabaseType, err)
}

func TestStartCmdValidArgs(t *testing.T) {
	t.Run("database type: mem", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

		require.NoError(t, err)
	})
	t.Run("database type: couchdb", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080",
			"--" + databaseTypeFlagName, "couchdb", "--" + databaseURLFlagName, "localhost:8080"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()

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

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelCritical}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.CRITICAL, log.GetLevel(""))
	})
	t.Run("Log level: error", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelError}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.ERROR, log.GetLevel(""))
	})
	t.Run("Log level: warn", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelWarn}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.WARNING, log.GetLevel(""))
	})
	t.Run("Log level: info", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelInfo}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
	})
	t.Run("Log level: debug", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, logLevelDebug}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.DEBUG, log.GetLevel(""))
	})
	t.Run("Invalid log level - default to info", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + logLevelFlagName, "mango"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Nil(t, err)
		require.Equal(t, log.INFO, log.GetLevel(""))
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
		require.Equal(t, `parse http://%: invalid URL escape "%"`, err.Error())
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
