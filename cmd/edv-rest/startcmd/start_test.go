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
	"github.com/trustbloc/edv/pkg/restapi/models"
)

type mockServer struct{}

func (s *mockServer) ListenAndServe(host, certFile, keyFile string, handler http.Handler) error {
	return nil
}

type mockEDVProvider struct {
	errCreateStore                 error
	errOpenStore                   error
	errStoreCreateReferenceIDIndex error
}

func (m *mockEDVProvider) CreateStore(string) error {
	return m.errCreateStore
}

func (m *mockEDVProvider) OpenStore(string) (edvprovider.EDVStore, error) {
	return &mockEDVStore{errCreateReferenceIDIndex: m.errStoreCreateReferenceIDIndex}, m.errOpenStore
}

type mockEDVStore struct {
	errCreateReferenceIDIndex error
}

func (m *mockEDVStore) Put(models.EncryptedDocument) error {
	return nil
}

func (m *mockEDVStore) GetAll() ([][]byte, error) {
	return nil, nil
}

func (m *mockEDVStore) Get(string) ([]byte, error) {
	return nil, nil
}

func (m *mockEDVStore) CreateEDVIndex() error {
	return nil
}

func (m *mockEDVStore) Query(*models.Query) ([]string, error) {
	return nil, nil
}

func (m *mockEDVStore) CreateReferenceIDIndex() error {
	return m.errCreateReferenceIDIndex
}

func (m *mockEDVStore) StoreDataVaultConfiguration(*models.DataVaultConfiguration, string) error {
	return nil
}

func (m *mockEDVStore) CreateEncryptedDocIDIndex() error {
	return nil
}

func (m *mockEDVStore) Update(document models.EncryptedDocument) error {
	return nil
}

func (m *mockEDVStore) Delete(docID string) error {
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

		require.Equal(t, fmt.Errorf("failed to connect to couchdb: %w", couchdbedvprovider.ErrMissingDatabaseURL), err)
	})
	t.Run("test missing kms database url arg - couchdb", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem", "--" +
			localKMSSecretsDatabaseTypeFlagName, "couchdb", "--" + authEnableFlagName, "true", "--" +
			databaseTimeoutFlagName, "1"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "Neither localkms-secrets-database-url (command line flag) nor "+
			"EDV_LOCALKMS_SECRETS_DATABASE_URL (environment variable) have been set")
	})

	t.Run("test auth enable wrong value", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + authEnableFlagName, "wrong"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "strconv.ParseBool: parsing ")
	})
}

func TestStartEDV_FailToCreateEDVProvider(t *testing.T) {
	parameters := &edvParameters{hostURL: "NotBlank", databaseType: "NotAValidType"}

	err := startEDV(parameters)
	require.Equal(t, errInvalidDatabaseType, err)
}

func TestStartCmdValidArgs(t *testing.T) {
	t.Run("database type: mem", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + authEnableFlagName, "true", "--" + localKMSSecretsDatabaseTypeFlagName, "mem"}
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

func TestStartCmdBlankTLSArgs(t *testing.T) {
	t.Run("Blank cert file arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + tlsCertFileFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.EqualError(t, err, fmt.Sprintf("%s value is empty", tlsCertFileFlagName))
	})
	t.Run("Blank key file arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + tlsKeyFileFlagName, ""}
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

func TestKeyManager(t *testing.T) {
	t.Run("Error - invalid database type", func(t *testing.T) {
		parameters := edvParameters{localKMSSecretsStorage: &storageParameters{storageType: "NotARealDatabaseType"}}

		provider, err := createKeyManager(&parameters)
		require.Nil(t, provider)
		require.Equal(t, errInvalidDatabaseType, err)
	})

	t.Run("Error - CouchDB url is invalid", func(t *testing.T) {
		parameters := edvParameters{localKMSSecretsStorage: &storageParameters{storageType: databaseTypeCouchDBOption,
			storageURL: "%"}, databaseTimeout: 1}

		provider, err := createKeyManager(&parameters)
		require.Error(t, err)
		require.Nil(t, provider)
		require.Contains(t, err.Error(), "failed to connect to couchdb: failed to ping couchDB")
	})
}

func TestCreateProvider(t *testing.T) {
	t.Run("Successfully create memory storage provider", func(t *testing.T) {
		parameters := edvParameters{databaseType: databaseTypeMemOption}

		provider, err := createEDVProvider(&parameters)
		require.NoError(t, err)
		require.IsType(t, &memedvprovider.MemEDVProvider{}, provider)
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
		require.Equal(t, fmt.Errorf("failed to connect to couchdb: %w", couchdbedvprovider.ErrMissingDatabaseURL), err)
	})
	t.Run("Error - CouchDB url is invalid", func(t *testing.T) {
		parameters := edvParameters{databaseType: databaseTypeCouchDBOption, databaseURL: "%", databaseTimeout: 1}

		provider, err := createEDVProvider(&parameters)
		require.Nil(t, provider)
		require.EqualError(t, err, fmt.Sprintf("failed to connect to couchdb: %s",
			`failure while instantiate Kivik CouchDB client: parse "http://%": invalid URL escape "%"`))
	})
}

func TestListenAndServe(t *testing.T) {
	h := HTTPServer{}
	err := h.ListenAndServe("localhost:8080", "test.key", "test.cert", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "open test.key: no such file or directory")
}

func TestCreateConfigStore(t *testing.T) {
	t.Run("Success - mem", func(t *testing.T) {
		provider := memedvprovider.NewProvider()

		err := createConfigStore(provider)
		require.NoError(t, err)
	})
	t.Run("Success - other providers", func(t *testing.T) {
		err := createConfigStore(&mockEDVProvider{})
		require.NoError(t, err)
	})
	t.Run("Success - create duplicate store", func(t *testing.T) {
		err := createConfigStore(&mockEDVProvider{errCreateStore: storage.ErrDuplicateStore})
		require.Nil(t, err)
	})
	t.Run("failure - other error in create store", func(t *testing.T) {
		errTest := errors.New("error in create store")

		err := createConfigStore(&mockEDVProvider{errCreateStore: errTest})
		require.Equal(t, fmt.Errorf(errCreateConfigStore, errTest), err)
	})
	t.Run("failure - open store error", func(t *testing.T) {
		errTest := errors.New("error in open store")

		err := createConfigStore(&mockEDVProvider{errOpenStore: errTest})
		require.Equal(t, fmt.Errorf(errCreateConfigStore, errTest), err)
	})
	t.Run("failure - create referenceID index error", func(t *testing.T) {
		errTest := errors.New("error in create refID index")

		err := createConfigStore(&mockEDVProvider{errStoreCreateReferenceIDIndex: errTest})
		require.Equal(t, fmt.Errorf(errCreateConfigStore, errTest), err)
	})
}

func TestGetTimeout(t *testing.T) {
	t.Run("failure - invalid timeout flag", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "localhost:8080", "--" + databaseTypeFlagName, "mem",
			"--" + databaseTimeoutFlagName, "NotAnInt"}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.NotNil(t, err)
		require.EqualError(t, err,
			"failed to parse timeout NotAnInt: strconv.Atoi: parsing \"NotAnInt\": invalid syntax")
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
