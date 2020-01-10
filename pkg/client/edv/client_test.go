/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edv/pkg/restapi/edv"
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
	"github.com/trustbloc/edv/pkg/storage/memstore"
)

const (
	testVaultID    = "testvault"
	testDocumentID = "testdocument"
)

func TestClient_New(t *testing.T) {
	client := New("")

	require.NotNil(t, client)
}

func TestClient_CreateDataVault_ValidConfig(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

	validConfig := getTestValidDataVaultConfiguration()
	location, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)
	require.Equal(t, srvAddr+"/encrypted-data-vaults/testvault", location)

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

	validConfig := getTestValidDataVaultConfiguration()
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

	validConfig := getTestValidDataVaultConfiguration()
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

	validConfig := getTestValidDataVaultConfiguration()

	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	location, err := storeTestDocument(client)
	require.NoError(t, err)
	require.Equal(t, srvAddr+"/encrypted-data-vaults/testvault/docs/testdocument", location)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDocument_NoVault(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

	location, err := storeTestDocument(client)
	require.Empty(t, location)
	require.Equal(t, "the EDV server returned the following error: specified vault does not exist", err.Error())

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

func TestClient_RetrieveDocument(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

	validConfig := getTestValidDataVaultConfiguration()
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	_, err = storeTestDocument(client)
	require.NoError(t, err)

	docRaw, err := client.RetrieveDocument(testVaultID, testDocumentID)
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

func TestClient_RetrieveDocument_VaultNotFound(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

	validConfig := getTestValidDataVaultConfiguration()
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	_, err = storeTestDocument(client)
	require.NoError(t, err)

	docRaw, err := client.RetrieveDocument("wrongvault", testDocumentID)
	require.Nil(t, docRaw)
	require.Equal(t, "the EDV server returned the following error: specified vault does not exist", err.Error())

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_RetrieveDocument_NotFound(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr)

	waitForServerToStart(t, srvAddr)

	client := Client{edvServerURL: "http://" + srvAddr}

	validConfig := getTestValidDataVaultConfiguration()
	_, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	docRaw, err := client.RetrieveDocument(testVaultID, testDocumentID)
	require.Nil(t, docRaw)
	require.Equal(t,
		fmt.Sprintf("no document with an id of %s could be found in the vault with id %s", testDocumentID, testVaultID),
		err.Error())

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_RetrieveDocument_ServerUnreachable(t *testing.T) {
	srvAddr := randomURL()

	client := Client{edvServerURL: "http://" + srvAddr}

	resp, err := client.RetrieveDocument(testVaultID, testDocumentID)
	require.Nil(t, resp)
	require.Contains(t, err.Error(), "connection refused")
}

type badReadCloser struct{}

func (m badReadCloser) Read(p []byte) (n int, err error) {
	return 0, errors.New("badReadCloser always fails")
}

func (m badReadCloser) Close() error {
	return errors.New("badReadCloser always fails")
}

func TestGetErrorReadFail(t *testing.T) {
	badResp := http.Response{
		Body: badReadCloser{},
	}
	err := getError(&badResp)
	require.Equal(t, "failed to read response message: badReadCloser always fails", err.Error())
}

func TestCloseBody_Fail(t *testing.T) {
	var logContents bytes.Buffer

	log.SetOutput(&logContents)

	badResp := http.Response{
		Body: badReadCloser{},
	}
	closeBody(&badResp)

	require.Contains(t, logContents.String(), "Failed to close response body: badReadCloser always fails")
}

func TestGetDocumentFromResponse_Fail(t *testing.T) {
	badResp := http.Response{
		Body: badReadCloser{},
	}
	_, err := getDocumentFromResponse(&badResp)
	require.Equal(t, "failed to read response message while retrieving document: badReadCloser always fails", err.Error())
}

func TestSendPostJSON_Unmarshallable(t *testing.T) {
	unmarshallableMap := make(map[string]interface{})
	unmarshallableMap[""] = make(chan int)

	client := New("")
	_, err := client.sendPostJSON(unmarshallableMap, "", "")

	require.Equal(t, "failed to marshal object: json: unsupported type: chan int", err.Error())
}

func storeTestDocument(client Client) (string, error) {
	meta := make(map[string]interface{})
	meta["created"] = "2020-01-10"

	content := make(map[string]interface{})
	content["message"] = "Hello EDV!"

	document := operation.StructuredDocument{
		ID:      testDocumentID,
		Meta:    meta,
		Content: content,
	}

	return client.CreateDocument(testVaultID, &document)
}

func getTestValidDataVaultConfiguration() operation.DataVaultConfiguration {
	return operation.DataVaultConfiguration{
		Sequence:    0,
		Controller:  "",
		Invoker:     "",
		Delegator:   "",
		ReferenceID: testVaultID,
		KEK:         operation.IDTypePair{},
		HMAC:        operation.IDTypePair{},
	}
}

// Returns a reference to the server so the caller can stop it.
func startEDVServer(t *testing.T, srvAddr string) *http.Server {
	edvService, err := edv.New(memstore.NewProvider())
	require.NoError(t, err)

	handlers := edvService.GetOperations()
	router := mux.NewRouter()

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
			return errors.New("timeout: server is not available")
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
