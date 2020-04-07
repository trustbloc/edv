/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edv/pkg/edvprovider/memedvprovider"
	"github.com/trustbloc/edv/pkg/internal/common/support"
	"github.com/trustbloc/edv/pkg/restapi/edv"
	"github.com/trustbloc/edv/pkg/restapi/edv/edverrors"
	"github.com/trustbloc/edv/pkg/restapi/edv/models"
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
)

const (
	testVaultID            = "testvault"
	testVaultIDWithSlashes = "http://example.com/" + testVaultID
	testDocumentID         = "VJYHHJx4C8J9Fsgz7rZqSp"
	testEncryptedDocJWE    = `{"protected":"eyJlbmMiOiJjaGFjaGEyMHBvbHkxMzA1X2lldGYiLCJ0eXAiOiJKV00vMS4wIiwiYWxnIjoiQ` +
		`XV0aGNyeXB0IiwicmVjaXBpZW50cyI6W3siZW5jcnlwdGVkX2tleSI6ImdLcXNYNm1HUXYtS3oyelQzMndIbE5DUjFiVU54ZlRTd0ZYcFVWb` +
		`3FIMjctQUN0bURpZHBQdlVRcEdKSDZqMDkiLCJoZWFkZXIiOnsia2lkIjoiNzd6eWlNeHY0SlRzc2tMeFdFOWI1cVlDN2o1b3Fxc1VMUnFhc` +
		`VNqd1oya1kiLCJzZW5kZXIiOiJiNmhrRkpXM2RfNmZZVjAtcjV0WEJoWnBVVmtrYXhBSFBDUEZxUDVyTHh3aGpwdFJraTRURjBmTEFNcy1se` +
		`Wd0Ym9PQmtnUDhWNWlwaDdndEVNcTAycmFDTEstQm5GRWo3dWk5Rmo5NkRleFRlRzl6OGdab1lveXY5ZE09IiwiaXYiOiJjNHMzdzBlRzhyZ` +
		`GhnaC1EZnNjOW5Cb3BYVHA1OEhNZiJ9fV19","iv":"e8mXGCAamvwYcdf2","ciphertext":"dLKWmjFyL-G1uqF588Ya0g10QModI-q0f` +
		`7vw_v3_jhzskuNqX7Yx4aSD7x2jhUdat82kHS4qLYw8BuUGvGimI_sCQ9m3On` +
		`QTHSjZnpg7VWRqAULBC3MSTtBa1DtZjZL4C0Y=","tag":"W4yJzyuGYzuZtZMRv2bDUg=="}`
)

type failingReadCloser struct{}

func (f failingReadCloser) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("failingReadCloser always fails")
}

func (f failingReadCloser) Close() error {
	return fmt.Errorf("failingReadCloser always fails")
}

func TestClient_New(t *testing.T) {
	client := New("", WithTLSConfig(&tls.Config{ServerName: "name"}))

	require.NotNil(t, client)

	require.NotNil(t, client.httpClient.Transport)
}

func TestClient_CreateDataVault_ValidConfig(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	validConfig := getTestValidDataVaultConfiguration(false)
	location, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)
	require.Equal(t, srvAddr+"/encrypted-data-vaults/testvault", location)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDataVault_VaultIDContainsSlash(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	validConfig := getTestValidDataVaultConfiguration(true)
	location, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)
	require.Equal(t, srvAddr+"/encrypted-data-vaults/http:%2F%2Fexample.com%2Ftestvault", location)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDataVault_InvalidConfig(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	invalidConfig := models.DataVaultConfiguration{}
	location, err := client.CreateDataVault(&invalidConfig)
	require.Empty(t, location)
	require.NotNil(t, err)
	require.Equal(t, "the EDV server returned the following error: referenceId can't be blank", err.Error())

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDataVault_DuplicateVault(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	validConfig := getTestValidDataVaultConfiguration(false)
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	location, err := client.CreateDataVault(&validConfig)
	require.Empty(t, location)
	require.Equal(t, "a duplicate data vault exists", err.Error())

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDataVault_ServerUnreachable(t *testing.T) {
	srvAddr := randomURL()

	client := New("http://" + srvAddr)

	validConfig := getTestValidDataVaultConfiguration(false)
	location, err := client.CreateDataVault(&validConfig)
	require.Empty(t, location)

	// For some reason on the Azure CI a different error is returned. So we check for both.
	// Azure CI returns the "E0F" version, and locally "connection refused" is returned.
	testPassed := strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection refused")
	if !testPassed {
		t.FailNow()
	}
}

func TestClient_CreateDocument(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	validConfig := getTestValidDataVaultConfiguration(false)

	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	location, err := client.CreateDocument(testVaultID, getTestValidEncryptedDocument())
	require.NoError(t, err)
	require.Equal(t, srvAddr+"/encrypted-data-vaults/testvault/docs/"+testDocumentID, location)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDocument_VaultIDContainsSlash(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	validConfig := getTestValidDataVaultConfiguration(true)

	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	location, err := client.CreateDocument(testVaultIDWithSlashes, getTestValidEncryptedDocument())
	require.NoError(t, err)
	require.Equal(t,
		srvAddr+"/encrypted-data-vaults/http:%2F%2Fexample.com%2Ftestvault/docs/"+testDocumentID,
		location)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDocument_NoVault(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	location, err := client.CreateDocument(testVaultID, getTestValidEncryptedDocument())
	require.Empty(t, location)
	require.Equal(t, fmt.Sprintf("the EDV server returned the following error: %s",
		edverrors.ErrVaultNotFound.Error()), err.Error())

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDocument_ServerUnreachable(t *testing.T) {
	srvAddr := randomURL()

	client := New("http://" + srvAddr)

	location, err := client.CreateDocument(testVaultID, &models.EncryptedDocument{})
	require.Empty(t, location)

	// For some reason on the Azure CI "E0F" is returned and locally "connection refused" is returned.
	testPassed := strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection refused")
	if !testPassed {
		t.FailNow()
	}
}

func TestClient_ReadDocument(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	validConfig := getTestValidDataVaultConfiguration(false)
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	_, err = client.CreateDocument(testVaultID, getTestValidEncryptedDocument())
	require.NoError(t, err)

	document, err := client.ReadDocument(testVaultID, testDocumentID)
	require.NoError(t, err)

	require.Equal(t, testDocumentID, document.ID)
	require.Equal(t, 0, document.Sequence)
	require.Equal(t, testEncryptedDocJWE, string(document.JWE))

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_UnmarshalFail(t *testing.T) {
	srvAddr := randomURL()

	mockReadDocumentHTTPHandler :=
		support.NewHTTPHandler("/encrypted-data-vaults/{vaultIDPathVariable}/docs/{docID}", http.MethodGet,
			mockReadDocumentHandler)

	srv := startMockEDVServer(srvAddr, mockReadDocumentHTTPHandler)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	document, err := client.ReadDocument(testVaultID, testDocumentID)
	require.Nil(t, document)
	require.EqualError(t, err, "invalid character 'h' in literal true (expecting 'r')")

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_VaultIDContainsSlash(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	validConfig := getTestValidDataVaultConfiguration(true)
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	_, err = client.CreateDocument(testVaultIDWithSlashes, getTestValidEncryptedDocument())
	require.NoError(t, err)

	document, err := client.ReadDocument(testVaultIDWithSlashes, testDocumentID)
	require.NoError(t, err)

	require.Equal(t, testDocumentID, document.ID)
	require.Equal(t, 0, document.Sequence)
	require.Equal(t, testEncryptedDocJWE, string(document.JWE))

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_VaultNotFound(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	validConfig := getTestValidDataVaultConfiguration(false)
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	_, err = client.CreateDocument(testVaultID, getTestValidEncryptedDocument())
	require.NoError(t, err)

	document, err := client.ReadDocument("wrongvault", testDocumentID)
	require.Nil(t, document)
	require.Equal(t, fmt.Sprintf("failed to retrieve document: %s",
		edverrors.ErrVaultNotFound.Error()), err.Error())

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_NotFound(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	validConfig := getTestValidDataVaultConfiguration(false)
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	document, err := client.ReadDocument(testVaultID, testDocumentID)
	require.Nil(t, document)
	require.Equal(t, fmt.Sprintf("failed to retrieve document: %s", edverrors.ErrDocumentNotFound.Error()), err.Error())

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_ServerUnreachable(t *testing.T) {
	srvAddr := randomURL()

	client := New("http://" + srvAddr)

	document, err := client.ReadDocument(testVaultID, testDocumentID)
	require.Nil(t, document)
	require.Contains(t, err.Error(), "connection refused")
}

func TestClient_ReadDocument_UnableToReachReadCredentialEndpoint(t *testing.T) {
	srvAddr := randomURL()

	// This mock server will be reachable,
	// but won't have the Read Credential endpoint that the client is going to try to hit.
	srv := startMockEDVServer(srvAddr, nil)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr)

	document, err := client.ReadDocument(testVaultID, testDocumentID)
	require.Nil(t, document)
	require.Equal(t, "unable to reach the EDV server Read Credential endpoint", err.Error())

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestGetErrorReadFail(t *testing.T) {
	badResp := http.Response{
		Body: failingReadCloser{},
	}
	err := getError(&badResp)
	require.Equal(t, "failed to read response message: failingReadCloser always fails", err.Error())
}

func TestCloseBody_Fail(t *testing.T) {
	var logContents bytes.Buffer

	log.SetOutput(&logContents)

	badResp := http.Response{
		Body: failingReadCloser{},
	}
	closeReadCloser(badResp.Body)

	require.Contains(t, logContents.String(), "Failed to close response body: failingReadCloser always fails")
}

func TestSendPostJSON_Unmarshallable(t *testing.T) {
	unmarshallableMap := make(map[string]interface{})
	unmarshallableMap[""] = make(chan int)

	client := New("")
	_, err := client.sendCreateRequest(unmarshallableMap, "", "")

	require.Equal(t, "failed to marshal object: json: unsupported type: chan int", err.Error())
}

func getTestValidDataVaultConfiguration(includeSlashInVaultID bool) models.DataVaultConfiguration {
	testDataVaultConfiguration := models.DataVaultConfiguration{
		Sequence:   0,
		Controller: "",
		Invoker:    "",
		Delegator:  "",
		KEK:        models.IDTypePair{},
		HMAC:       models.IDTypePair{},
	}

	if includeSlashInVaultID {
		testDataVaultConfiguration.ReferenceID = testVaultIDWithSlashes
	} else {
		testDataVaultConfiguration.ReferenceID = testVaultID
	}

	return testDataVaultConfiguration
}

func getTestValidEncryptedDocument() *models.EncryptedDocument {
	return &models.EncryptedDocument{
		ID:       testDocumentID,
		Sequence: 0,
		JWE:      []byte(testEncryptedDocJWE),
	}
}

// Returns a reference to the server so the caller can stop it.
func startEDVServer(t *testing.T, srvAddr string) *http.Server {
	edvService, err := edv.New(memedvprovider.NewProvider(), "")
	require.NoError(t, err)

	handlers := edvService.GetOperations()
	router := mux.NewRouter()
	router.UseEncodedPath()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	srv := http.Server{Addr: srvAddr, Handler: router}
	go func(srv *http.Server) {
		err := srv.ListenAndServe()
		if err.Error() != "http: Server closed" {
			log.Fatal("server failure")
		}
	}(&srv)

	return &srv
}

// Returns a reference to the server so the caller can stop it.
func startMockEDVServer(srvAddr string, httpHandler operation.Handler) *http.Server {
	router := mux.NewRouter()

	if httpHandler != nil {
		router.HandleFunc(httpHandler.Path(), httpHandler.Handle()).Methods(httpHandler.Method())
	}

	srv := http.Server{Addr: srvAddr, Handler: router}
	go func(srv *http.Server) {
		err := srv.ListenAndServe()
		if err.Error() != "http: Server closed" {
			log.Fatal("server failure")
		}
	}(&srv)

	return &srv
}

// Just writes some invalid JSON to the response.
func mockReadDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	_, err := rw.Write([]byte("this is invalid JSON and will cause json.Unmarshal to fail"))
	if err != nil {
		log.Fatal("failed to write in mock read document handler")
	}
}

func waitForServerToStart(t *testing.T, srvAddr string) {
	if err := listenFor(srvAddr); err != nil {
		t.Fatal(err)
	}
}

func listenFor(host string) error {
	timeout := time.After(10 * time.Second)

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout: server is not available")
		default:
			conn, err := net.Dial("tcp", host)
			if err != nil {
				continue
			}

			return conn.Close()
		}
	}
}

func randomURL() string {
	return fmt.Sprintf("localhost:%d", mustGetRandomPort(3))
}

func mustGetRandomPort(n int) int {
	for ; n > 0; n-- {
		port, err := getRandomPort()
		if err != nil {
			continue
		}

		return port
	}
	panic("cannot acquire the random port")
}

func getRandomPort() (int, error) {
	const network = "tcp"

	addr, err := net.ResolveTCPAddr(network, "localhost:0")
	if err != nil {
		return 0, err
	}

	listener, err := net.ListenTCP(network, addr)
	if err != nil {
		return 0, err
	}

	err = listener.Close()
	if err != nil {
		return 0, err
	}

	return listener.Addr().(*net.TCPAddr).Port, nil
}
