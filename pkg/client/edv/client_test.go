/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/edge-core/pkg/storage/memstore"

	"github.com/trustbloc/edv/pkg/restapi/edv"
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
)

const (
	testVaultID               = "testvault"
	testVaultIDWithSlashes    = "http://example.com/" + testVaultID
	testDocumentID            = "testdocument"
	testDocumentIDWithSlashes = "http://example.com/" + testDocumentID
)

type failingReadCloser struct{}

func (f failingReadCloser) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("failingReadCloser always fails")
}

func (f failingReadCloser) Close() error {
	return fmt.Errorf("failingReadCloser always fails")
}

func TestClient_New(t *testing.T) {
	client := New("")

	require.NotNil(t, client)
}

func TestClient_CreateDataVault_ValidConfig(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

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

	client := Client{edvServerURL: "http://" + srvAddr}

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

	client := Client{edvServerURL: "http://" + srvAddr}

	invalidConfig := operation.DataVaultConfiguration{}
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

	client := Client{edvServerURL: "http://" + srvAddr}

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

	client := Client{edvServerURL: "http://" + srvAddr}

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

	client := Client{edvServerURL: "http://" + srvAddr}

	validConfig := getTestValidDataVaultConfiguration(false)

	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	location, err := storeTestDocument(client, false)
	require.NoError(t, err)
	require.Equal(t, srvAddr+"/encrypted-data-vaults/testvault/docs/testdocument", location)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDocument_VaultIDAndDocIDContainsSlash(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

	validConfig := getTestValidDataVaultConfiguration(true)

	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	location, err := storeTestDocument(client, true)
	require.NoError(t, err)
	require.Equal(t,
		srvAddr+"/encrypted-data-vaults/http:%2F%2Fexample.com%2Ftestvault/docs/http:%2F%2Fexample.com%2Ftestdocument",
		location)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDocument_NoVault(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

	location, err := storeTestDocument(client, false)
	require.Empty(t, location)
	require.Equal(t, fmt.Sprintf("the EDV server returned the following error: %s", operation.VaultNotFoundErrMsg),
		err.Error())

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDocument_ServerUnreachable(t *testing.T) {
	srvAddr := randomURL()

	client := Client{edvServerURL: "http://" + srvAddr}

	location, err := client.CreateDocument(testVaultID, &operation.StructuredDocument{})
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

	client := Client{edvServerURL: "http://" + srvAddr}

	validConfig := getTestValidDataVaultConfiguration(false)
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	_, err = storeTestDocument(client, false)
	require.NoError(t, err)

	docRaw, err := client.ReadDocument(testVaultID, testDocumentID)
	require.NoError(t, err)

	document := operation.StructuredDocument{}
	err = json.Unmarshal(docRaw, &document)
	require.NoError(t, err)

	require.Equal(t, testDocumentID, document.ID)
	require.Equal(t, "2020-01-10", document.Meta["created"])
	require.Equal(t, "Hello EDV!", document.Content["message"])

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_VaultIDAndDocIDContainsSlash(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

	validConfig := getTestValidDataVaultConfiguration(true)
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	_, err = storeTestDocument(client, true)
	require.NoError(t, err)

	docRaw, err := client.ReadDocument(testVaultIDWithSlashes, testDocumentIDWithSlashes)
	require.NoError(t, err)

	document := operation.StructuredDocument{}
	err = json.Unmarshal(docRaw, &document)
	require.NoError(t, err)

	require.Equal(t, testDocumentIDWithSlashes, document.ID)
	require.Equal(t, "2020-01-10", document.Meta["created"])
	require.Equal(t, "Hello EDV!", document.Content["message"])

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_VaultNotFound(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

	validConfig := getTestValidDataVaultConfiguration(false)
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	_, err = storeTestDocument(client, false)
	require.NoError(t, err)

	docRaw, err := client.ReadDocument("wrongvault", testDocumentID)
	require.Nil(t, docRaw)
	require.Equal(t, fmt.Sprintf("failed to retrieve document: %s", operation.VaultNotFoundErrMsg), err.Error())

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_NotFound(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

	validConfig := getTestValidDataVaultConfiguration(false)
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	docRaw, err := client.ReadDocument(testVaultID, testDocumentID)
	require.Nil(t, docRaw)
	require.Equal(t, fmt.Sprintf("failed to retrieve document: %s", operation.DocumentNotFoundErrMsg), err.Error())

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_ServerUnreachable(t *testing.T) {
	srvAddr := randomURL()

	client := Client{edvServerURL: "http://" + srvAddr}

	resp, err := client.ReadDocument(testVaultID, testDocumentID)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "connection refused")
}

func TestClient_ReadDocument_UnableToReachReadCredentialEndpoint(t *testing.T) {
	srvAddr := randomURL()

	// This mock server will be reachable,
	// but won't have the Read Credential endpoint that the client is going to try to hit.
	srv := startMockServer(srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

	docRaw, err := client.ReadDocument(testVaultID, testDocumentID)
	require.Nil(t, docRaw)
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

func storeTestDocument(client Client, includeSlashInVaultIDAndDocID bool) (string, error) {
	meta := make(map[string]interface{})
	meta["created"] = "2020-01-10"

	content := make(map[string]interface{})
	content["message"] = "Hello EDV!"

	testDocument := operation.StructuredDocument{
		Meta:    meta,
		Content: content,
	}

	var vaultID string

	if includeSlashInVaultIDAndDocID {
		vaultID = testVaultIDWithSlashes
		testDocument.ID = testDocumentIDWithSlashes
	} else {
		vaultID = testVaultID
		testDocument.ID = testDocumentID
	}

	return client.CreateDocument(vaultID, &testDocument)
}

func getTestValidDataVaultConfiguration(includeSlashInVaultID bool) operation.DataVaultConfiguration {
	testDataVaultConfiguration := operation.DataVaultConfiguration{
		Sequence:   0,
		Controller: "",
		Invoker:    "",
		Delegator:  "",
		KEK:        operation.IDTypePair{},
		HMAC:       operation.IDTypePair{},
	}

	if includeSlashInVaultID {
		testDataVaultConfiguration.ReferenceID = testVaultIDWithSlashes
	} else {
		testDataVaultConfiguration.ReferenceID = testVaultID
	}

	return testDataVaultConfiguration
}

// Returns a reference to the server so the caller can stop it.
func startEDVServer(t *testing.T, srvAddr string) *http.Server {
	edvService, err := edv.New(memstore.NewProvider())
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
func startMockServer(srvAddr string) *http.Server {
	router := mux.NewRouter()

	srv := http.Server{Addr: srvAddr, Handler: router}
	go func(srv *http.Server) {
		err := srv.ListenAndServe()
		if err.Error() != "http: Server closed" {
			log.Fatal("server failure")
		}
	}(&srv)

	return &srv
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
