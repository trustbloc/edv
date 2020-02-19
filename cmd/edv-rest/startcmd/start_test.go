/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/http"
	"os"
	"testing"

	couchdbstore "github.com/trustbloc/edge-core/pkg/storage/couchdb"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
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

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem"}
	startCmd.SetArgs(args)

	err := startCmd.Execute()

	require.Nil(t, err)
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

		provider, err := createProvider(&parameters)
		require.NoError(t, err)
		require.IsType(t, &memstore.Provider{}, provider)
	})
	t.Run("Successfully create CouchDB storage provider", func(t *testing.T) {
		parameters := edvParameters{databaseType: databaseTypeCouchDBOption, databaseURL: "something"}

		provider, err := createProvider(&parameters)
		require.NoError(t, err)
		require.IsType(t, &couchdbstore.Provider{}, provider)
	})
	t.Run("Error - invalid database type", func(t *testing.T) {
		parameters := edvParameters{databaseType: "NotARealDatabaseType"}

		provider, err := createProvider(&parameters)
		require.Nil(t, provider)
		require.Equal(t, errInvalidDatabaseType, err)
	})
	t.Run("Error - CouchDB url is blank", func(t *testing.T) {
		parameters := edvParameters{databaseType: databaseTypeCouchDBOption, databaseURL: ""}

		provider, err := createProvider(&parameters)
		require.Nil(t, provider)
		require.Equal(t, errMissingDatabaseURL, err)
	})
	t.Run("Error - CouchDB url is invalid", func(t *testing.T) {
		parameters := edvParameters{databaseType: databaseTypeCouchDBOption, databaseURL: "%"}

		provider, err := createProvider(&parameters)
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
