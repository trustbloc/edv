/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/stretchr/testify/require"

	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/internal/common/support"
	"github.com/trustbloc/edv/pkg/restapi"
	"github.com/trustbloc/edv/pkg/restapi/messages"
	"github.com/trustbloc/edv/pkg/restapi/models"
	"github.com/trustbloc/edv/pkg/restapi/operation"
)

const (
	testReferenceID = "testRefID"
	testVaultID     = "Sr7yHjomhn1aeaFnxREfRN"
	testDocumentID  = "VJYHHJx4C8J9Fsgz7rZqSp"
	testDocumentID2 = "AJYHHJx4C8J9Fsgz7rZqSp"
	testJWE         = `{"protected":"eyJlbmMiOiJjaGFjaGEyMHBvbHkxMzA1X2lldGYiLCJ0eXAiOiJKV00vMS4wIiwiYWxnIjoiQ` +
		`XV0aGNyeXB0IiwicmVjaXBpZW50cyI6W3siZW5jcnlwdGVkX2tleSI6ImdLcXNYNm1HUXYtS3oyelQzMndIbE5DUjFiVU54ZlRTd0ZYcFVWb` +
		`3FIMjctQUN0bURpZHBQdlVRcEdKSDZqMDkiLCJoZWFkZXIiOnsia2lkIjoiNzd6eWlNeHY0SlRzc2tMeFdFOWI1cVlDN2o1b3Fxc1VMUnFhc` +
		`VNqd1oya1kiLCJzZW5kZXIiOiJiNmhrRkpXM2RfNmZZVjAtcjV0WEJoWnBVVmtrYXhBSFBDUEZxUDVyTHh3aGpwdFJraTRURjBmTEFNcy1se` +
		`Wd0Ym9PQmtnUDhWNWlwaDdndEVNcTAycmFDTEstQm5GRWo3dWk5Rmo5NkRleFRlRzl6OGdab1lveXY5ZE09IiwiaXYiOiJjNHMzdzBlRzhyZ` +
		`GhnaC1EZnNjOW5Cb3BYVHA1OEhNZiJ9fV19","iv":"e8mXGCAamvwYcdf2","ciphertext":"dLKWmjFyL-G1uqF588Ya0g10QModI-q0f` +
		`7vw_v3_jhzskuNqX7Yx4aSD7x2jhUdat82kHS4qLYw8BuUGvGimI_sCQ9m3On` +
		`QTHSjZnpg7VWRqAULBC3MSTtBa1DtZjZL4C0Y=","tag":"W4yJzyuGYzuZtZMRv2bDUg=="}`
	testJWE2 = `{"protected":"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ","encrypted_k` +
		`ey":"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKA` +
		`q7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfw` +
		`X7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWX` +
		`RcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg","iv":"48V1_ALb6US04U3b","ciphertext":"5eym8TW_c8SuK0ltJ` +
		`3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A","tag":"XFBoMYUZodetZdvTiFvSkQ"}`

	queryVaultEndpointPath = "/encrypted-data-vaults/{vaultIDPathVariable}/query"
	testQueryVaultResponse = `["docID1","docID2"]`
)

var errFailingMarshal = errors.New("failingMarshal always fails")

type mockHTTPClient struct{}

func (*mockHTTPClient) Do(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

func TestClient_New(t *testing.T) {
	t.Run("WithTLSConfig", func(t *testing.T) {
		client := New("", WithHeaders(func(req *http.Request) (*http.Header, error) {
			return nil, nil
		}), WithTLSConfig(&tls.Config{ServerName: "name", MinVersion: tls.VersionTLS12}))

		require.NotNil(t, client)

		hClient, ok := client.httpClient.(*http.Client)
		require.True(t, ok)

		require.NotNil(t, hClient.Transport)
	})
	t.Run("WithTLSConfig (with custom client)", func(t *testing.T) {
		hClient := &mockHTTPClient{}

		client := New("",
			WithHTTPClient(hClient),
			WithTLSConfig(&tls.Config{ServerName: "name"}), //nolint:gosec
		)

		require.NotNil(t, client)
		require.Equal(t, hClient, client.httpClient)
	})
	t.Run("WithTLSConfig (nil client)", func(t *testing.T) {
		client := New("",
			WithHTTPClient(nil),
			WithTLSConfig(&tls.Config{ServerName: "name"}), //nolint:gosec
		)

		require.NotNil(t, client)
		require.Nil(t, client.httpClient)
	})
	t.Run("WithHTTPClient", func(t *testing.T) {
		hClient := &http.Client{}

		client := New("", WithHTTPClient(hClient))

		require.Equal(t, hClient, client.httpClient)
	})
}

func TestClient_CreateDataVault_ValidConfig(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	validConfig := getTestValidDataVaultConfiguration()
	location, _, err := client.CreateDataVault(&validConfig,
		WithRequestHeader(func(req *http.Request) (*http.Header, error) {
			return nil, nil
		}))
	require.NoError(t, err)
	require.Contains(t, location, srvAddr+"/encrypted-data-vaults/")

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDataVault_InvalidConfig(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	invalidConfig := models.DataVaultConfiguration{}

	location, _, err := client.CreateDataVault(&invalidConfig)
	require.Empty(t, location)

	require.Contains(t, err.Error(), "Received invalid data vault configuration")
	require.Contains(t, err.Error(), "status code 400")

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDataVault_ServerUnreachable(t *testing.T) {
	srvAddr := randomURL()

	client := New("http://" + srvAddr)

	validConfig := getTestValidDataVaultConfiguration()
	location, _, err := client.CreateDataVault(&validConfig)
	require.Empty(t, location)

	// For some reason on the Azure CI "E0F" is returned while locally "connection refused" is returned.
	testPassed := strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection refused")
	require.True(t, testPassed)
}

func TestClient_CreateDocument(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	validConfig := getTestValidDataVaultConfiguration()

	vaultLocationURL, _, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	vaultID := getVaultIDFromURL(vaultLocationURL)

	location, err := client.CreateDocument(vaultID, getTestValidEncryptedDocument(testJWE),
		WithRequestHeader(func(req *http.Request) (*http.Header, error) {
			return nil, nil
		}))
	require.NoError(t, err)
	require.Equal(t, srvAddr+"/encrypted-data-vaults/"+vaultID+"/documents/"+testDocumentID, location)

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDocument_NoVault(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	location, err := client.CreateDocument(testVaultID, getTestValidEncryptedDocument(testJWE))
	require.Empty(t, location)
	require.Error(t, err)
	require.Contains(t, err.Error(), messages.ErrVaultNotFound.Error())
	require.Contains(t, err.Error(), "status code 400")

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_CreateDocument_ServerUnreachable(t *testing.T) {
	srvAddr := randomURL()

	client := New("http://" + srvAddr)

	location, err := client.CreateDocument(testVaultID, &models.EncryptedDocument{})
	require.Empty(t, location)

	// For some reason on the Azure CI "E0F" is returned while locally "connection refused" is returned.
	testPassed := strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection refused")
	require.True(t, testPassed)
}

func TestClient_ReadDocument(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	validConfig := getTestValidDataVaultConfiguration()
	vaultLocationURL, _, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	vaultID := getVaultIDFromURL(vaultLocationURL)

	_, err = client.CreateDocument(vaultID, getTestValidEncryptedDocument(testJWE))
	require.NoError(t, err)

	document, err := client.ReadDocument(vaultID, testDocumentID,
		WithRequestHeader(func(req *http.Request) (*http.Header, error) {
			return nil, nil
		}))
	require.NoError(t, err)

	require.Equal(t, testDocumentID, document.ID)
	require.Equal(t, uint64(0), document.Sequence)
	require.Equal(t, testJWE, string(document.JWE))

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_UnmarshalFail(t *testing.T) {
	srvAddr := randomURL()

	mockReadDocumentHTTPHandler :=
		support.NewHTTPHandler("/encrypted-data-vaults/{vaultIDPathVariable}/documents/{docID}", http.MethodGet,
			mockReadDocumentHandler)

	srv := startMockEDVServer(srvAddr, mockReadDocumentHTTPHandler)

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	document, err := client.ReadDocument(testVaultID, testDocumentID)
	require.Nil(t, document)
	require.EqualError(t, err, "invalid character 'h' in literal true (expecting 'r')")

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_VaultNotFound(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	document, err := client.ReadDocument(testVaultID, testDocumentID)
	require.Nil(t, document)
	require.Contains(t, err.Error(), messages.ErrVaultNotFound.Error())
	require.Contains(t, err.Error(), "status code 404")

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_ReadDocument_NotFound(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	validConfig := getTestValidDataVaultConfiguration()
	vaultLocationURL, _, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	vaultID := getVaultIDFromURL(vaultLocationURL)

	document, err := client.ReadDocument(vaultID, testDocumentID)
	require.Nil(t, document)
	require.Contains(t, err.Error(), messages.ErrDocumentNotFound.Error())

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
	require.Contains(t, err.Error(), "404 page not found")

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_UpdateDocument(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	validConfig := getTestValidDataVaultConfiguration()
	vaultLocationURL, _, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	vaultID := getVaultIDFromURL(vaultLocationURL)

	_, err = client.CreateDocument(vaultID, getTestValidEncryptedDocument(testJWE))
	require.NoError(t, err)

	err = client.UpdateDocument(vaultID, testDocumentID, getTestValidEncryptedDocument(testJWE2),
		WithRequestHeader(func(req *http.Request) (*http.Header, error) {
			return nil, nil
		}))
	require.NoError(t, err)

	document, err := client.ReadDocument(vaultID, testDocumentID)
	require.NoError(t, err)

	require.Equal(t, testJWE2, string(document.JWE))

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_UpdateDocument_VaultNotFound(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	err := client.UpdateDocument(testVaultID, testDocumentID,
		getTestValidEncryptedDocument(testJWE))
	require.Error(t, err)
	require.Contains(t, err.Error(), messages.ErrVaultNotFound.Error())
	require.Contains(t, err.Error(), "status code 404")

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_UpdateDocument_ServerUnreachable(t *testing.T) {
	srvAddr := randomURL()

	client := New("http://" + srvAddr)

	err := client.UpdateDocument(testVaultID, testDocumentID, &models.EncryptedDocument{})

	testPassed := strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection refused")
	require.True(t, testPassed)
}

func TestClient_DeleteDocument(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	validConfig := getTestValidDataVaultConfiguration()
	vaultLocationURL, _, err := client.CreateDataVault(&validConfig)
	require.NoError(t, err)

	vaultID := getVaultIDFromURL(vaultLocationURL)

	_, err = client.CreateDocument(vaultID, getTestValidEncryptedDocument(testJWE))
	require.NoError(t, err)

	err = client.DeleteDocument(vaultID, testDocumentID,
		WithRequestHeader(func(req *http.Request) (*http.Header, error) {
			return nil, nil
		}))
	require.NoError(t, err)

	receivedDoc, err := client.ReadDocument(vaultID, testDocumentID)
	require.Nil(t, receivedDoc)
	require.Error(t, err, fmt.Sprintf(messages.ReadDocumentFailure, testDocumentID, vaultID, messages.ErrDocumentNotFound))

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_DeleteDocument_VaultNotFound(t *testing.T) {
	srvAddr := randomURL()

	srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

	waitForServerToStart(t, srvAddr)

	client := New("http://" + srvAddr + "/encrypted-data-vaults")

	err := client.DeleteDocument(testVaultID, testDocumentID)
	require.Error(t, err)
	require.Contains(t, err.Error(), messages.ErrVaultNotFound.Error())
	require.Contains(t, err.Error(), "status code 404")

	err = srv.Shutdown(context.Background())
	require.NoError(t, err)
}

func TestClient_DeleteDocument_ServerUnreachable(t *testing.T) {
	srvAddr := randomURL()

	client := New("http://" + srvAddr)

	err := client.DeleteDocument(testVaultID, testDocumentID)

	testPassed := strings.Contains(err.Error(), "EOF") || strings.Contains(err.Error(), "connection refused")
	require.True(t, testPassed)
}

func TestClient_QueryVault(t *testing.T) {
	t.Run("Success, returning only document locations", func(t *testing.T) {
		srvAddr := randomURL()

		mockQueryVaultHTTPHandler :=
			support.NewHTTPHandler(queryVaultEndpointPath, http.MethodPost,
				mockSuccessQueryVaultHandler)

		srv := startMockEDVServer(srvAddr, mockQueryVaultHTTPHandler)

		waitForServerToStart(t, srvAddr)

		client := New("http://" + srvAddr + "/encrypted-data-vaults")

		ids, _, err := client.QueryVault("testVaultID", &models.Query{})
		require.NoError(t, err)
		require.Equal(t, "docID1", ids[0])
		require.Equal(t, "docID2", ids[1])

		err = srv.Shutdown(context.Background())
		require.NoError(t, err)
	})
	t.Run("Success, returning full documents", func(t *testing.T) {
		srvAddr := randomURL()

		mockQueryVaultHTTPHandler :=
			support.NewHTTPHandler(queryVaultEndpointPath, http.MethodPost,
				mockSuccessQueryVaultFullDocumentsHandler)

		srv := startMockEDVServer(srvAddr, mockQueryVaultHTTPHandler)

		waitForServerToStart(t, srvAddr)

		client := New("http://" + srvAddr + "/encrypted-data-vaults")

		locations, docs, err := client.QueryVault("testVaultID",
			&models.Query{
				Equals:              []map[string]string{{"name": "value"}},
				ReturnFullDocuments: true,
			})
		require.NoError(t, err)
		require.Empty(t, locations)
		require.Equal(t, "docID1", docs[0].ID)
		require.Equal(t, "docID2", docs[1].ID)

		err = srv.Shutdown(context.Background())
		require.NoError(t, err)
	})
	t.Run("Failure: server unreachable", func(t *testing.T) {
		srvAddr := randomURL()

		client := New("http://" + srvAddr + "/encrypted-data-vaults")

		ids, _, err := client.QueryVault("testVaultID", &models.Query{})

		// Multiple error strings are possible depending on the environment.
		testPassed := (strings.Contains(err.Error(), "EOF") ||
			strings.Contains(err.Error(), "connection refused")) && len(ids) == 0
		require.True(t, testPassed)
	})
	t.Run("Failure: unable to unmarshal response into string array", func(t *testing.T) {
		srvAddr := randomURL()

		mockQueryVaultHTTPHandler :=
			support.NewHTTPHandler(queryVaultEndpointPath, http.MethodPost,
				mockFailQueryVaultHandler)

		srv := startMockEDVServer(srvAddr, mockQueryVaultHTTPHandler)

		waitForServerToStart(t, srvAddr)

		client := New("http://" + srvAddr + "/encrypted-data-vaults")

		ids, _, err := client.QueryVault("testVaultID", &models.Query{})
		require.EqualError(t, err, "invalid character 'h' in literal true (expecting 'r')")
		require.Empty(t, ids)

		err = srv.Shutdown(context.Background())
		require.NoError(t, err)
	})
	t.Run("Failure: unable to unmarshal response into encrypted documents", func(t *testing.T) {
		srvAddr := randomURL()

		mockQueryVaultHTTPHandler :=
			support.NewHTTPHandler(queryVaultEndpointPath, http.MethodPost,
				mockFailQueryVaultHandler)

		srv := startMockEDVServer(srvAddr, mockQueryVaultHTTPHandler)

		waitForServerToStart(t, srvAddr)

		client := New("http://" + srvAddr + "/encrypted-data-vaults")

		_, _, err := client.QueryVault("testVaultID", &models.Query{
			Equals:              []map[string]string{{"name": "value"}},
			ReturnFullDocuments: true,
		})
		require.EqualError(t, err, "invalid character 'h' in literal true (expecting 'r')")

		err = srv.Shutdown(context.Background())
		require.NoError(t, err)
	})
	t.Run("Failure: vault doesn't exist", func(t *testing.T) {
		srvAddr := randomURL()

		srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{})

		waitForServerToStart(t, srvAddr)

		client := New("http://" + srvAddr + "/encrypted-data-vaults")

		ids, _, err := client.QueryVault(testVaultID,
			&models.Query{Equals: []map[string]string{{"name": "value"}}})
		require.Error(t, err)
		require.Contains(t, err.Error(), messages.ErrVaultNotFound.Error())
		require.Contains(t, err.Error(), "status code 400")
		require.Empty(t, ids)

		err = srv.Shutdown(context.Background())
		require.NoError(t, err)
	})
	t.Run("Failure: error while marshalling query", func(t *testing.T) {
		client := Client{marshal: failingMarshal}

		ids, _, err := client.QueryVault("testVaultID", &models.Query{})
		require.Equal(t, errFailingMarshal, err)
		require.Empty(t, ids)
	})
}

func TestClient_Batch(t *testing.T) {
	upsertNewDoc1 := models.VaultOperation{
		Operation:         models.UpsertDocumentVaultOperation,
		EncryptedDocument: models.EncryptedDocument{ID: testDocumentID, JWE: []byte(testJWE)},
	}

	upsertNewDoc2 := models.VaultOperation{
		Operation:         models.UpsertDocumentVaultOperation,
		EncryptedDocument: models.EncryptedDocument{ID: testDocumentID2, JWE: []byte(testJWE2)},
	}

	upsertExistingDoc1 := models.VaultOperation{
		Operation:         models.UpsertDocumentVaultOperation,
		EncryptedDocument: models.EncryptedDocument{ID: testDocumentID, JWE: []byte(testJWE)},
	}

	deleteExistingDoc1 := models.VaultOperation{
		Operation:  models.DeleteDocumentVaultOperation,
		DocumentID: testDocumentID,
	}
	//
	invalidOperation := models.VaultOperation{
		Operation: "invalidOperationName",
	}

	t.Run("Success: upsert (create), upsert (create), upsert (update)", func(t *testing.T) {
		srvAddr := randomURL()

		srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{Batch: true})

		waitForServerToStart(t, srvAddr)

		client := New("http://" + srvAddr + "/encrypted-data-vaults")

		validConfig := getTestValidDataVaultConfiguration()
		vaultLocationURL, _, err := client.CreateDataVault(&validConfig)
		require.NoError(t, err)

		vaultID := getVaultIDFromURL(vaultLocationURL)

		batch := models.Batch{upsertNewDoc1, upsertNewDoc2, upsertExistingDoc1}

		responses, err := client.Batch(vaultID, &batch,
			WithRequestHeader(func(req *http.Request) (*http.Header, error) {
				return nil, nil
			}))
		require.NoError(t, err)
		require.Len(t, responses, len(batch))
		require.Equal(t, srvAddr+"/encrypted-data-vaults/"+vaultID+"/documents/"+testDocumentID, responses[0])
		require.Equal(t, srvAddr+"/encrypted-data-vaults/"+vaultID+"/documents/"+testDocumentID2, responses[1])
		require.Equal(t, srvAddr+"/encrypted-data-vaults/"+vaultID+"/documents/"+testDocumentID, responses[2])

		err = srv.Shutdown(context.Background())
		require.NoError(t, err)
	})
	t.Run("Success: upsert (create), upsert (create), delete", func(t *testing.T) {
		srvAddr := randomURL()

		srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{Batch: true})

		waitForServerToStart(t, srvAddr)

		client := New("http://" + srvAddr + "/encrypted-data-vaults")

		validConfig := getTestValidDataVaultConfiguration()
		vaultLocationURL, _, err := client.CreateDataVault(&validConfig)
		require.NoError(t, err)

		vaultID := getVaultIDFromURL(vaultLocationURL)

		batch := models.Batch{upsertNewDoc1, upsertNewDoc2, deleteExistingDoc1}

		responses, err := client.Batch(vaultID, &batch,
			WithRequestHeader(func(req *http.Request) (*http.Header, error) {
				return nil, nil
			}))
		require.NoError(t, err)
		require.Len(t, responses, len(batch))
		require.Equal(t, srvAddr+"/encrypted-data-vaults/"+vaultID+"/documents/"+testDocumentID, responses[0])
		require.Equal(t, srvAddr+"/encrypted-data-vaults/"+vaultID+"/documents/"+testDocumentID2, responses[1])
		require.Equal(t, "", responses[2])

		err = srv.Shutdown(context.Background())
		require.NoError(t, err)
	})
	t.Run("Failure: upsert (create), invalid operation type, delete", func(t *testing.T) {
		srvAddr := randomURL()

		srv := startEDVServer(t, srvAddr, &operation.EnabledExtensions{Batch: true})

		waitForServerToStart(t, srvAddr)

		client := New("http://" + srvAddr + "/encrypted-data-vaults")

		validConfig := getTestValidDataVaultConfiguration()
		vaultLocationURL, _, err := client.CreateDataVault(&validConfig)
		require.NoError(t, err)

		vaultID := getVaultIDFromURL(vaultLocationURL)

		batch := models.Batch{upsertNewDoc1, invalidOperation, deleteExistingDoc1}

		expectedResponses := []string{
			"validated but not executed",
			"invalidOperationName is not a valid vault operation", "not validated or executed",
		}

		expectedResponsesBytes, err := json.Marshal(expectedResponses)
		require.NoError(t, err)

		responses, err := client.Batch(vaultID, &batch,
			WithRequestHeader(func(req *http.Request) (*http.Header, error) {
				return nil, nil
			}))
		require.EqualError(t, err, fmt.Sprintf("the EDV server returned status code 400 "+
			"along with the following message: %s", expectedResponsesBytes))
		require.Nil(t, responses)

		err = srv.Shutdown(context.Background())
		require.NoError(t, err)
	})
	t.Run("Failure: upsert (create), invalid operation type, delete", func(t *testing.T) {
		client := New("EDVServerURL")
		client.marshal = failingMarshal

		responses, err := client.Batch("VaultID", &models.Batch{},
			WithRequestHeader(func(req *http.Request) (*http.Header, error) {
				return nil, nil
			}))
		require.EqualError(t, err, errFailingMarshal.Error())
		require.Nil(t, responses)
	})
}

func getTestValidDataVaultConfiguration() models.DataVaultConfiguration {
	testDataVaultConfiguration := models.DataVaultConfiguration{
		Sequence:   0,
		Controller: "did:example:123456789",
		Invoker:    []string{"did:example:11111"},
		Delegator:  []string{"did:example:22222"},
		KEK: models.IDTypePair{
			ID:   "https://example.com/kms/12345",
			Type: "AesKeyWrappingKey2019",
		},
		HMAC: models.IDTypePair{
			ID:   "https://example.com/kms/67891",
			Type: "Sha256HmacKey2019",
		},
		ReferenceID: testReferenceID,
	}

	return testDataVaultConfiguration
}

func getTestValidEncryptedDocument(testJWE string) *models.EncryptedDocument {
	return &models.EncryptedDocument{
		ID:       testDocumentID,
		Sequence: 0,
		JWE:      []byte(testJWE),
	}
}

// Returns a reference to the server so the caller can stop it.
func startEDVServer(t *testing.T, srvAddr string, enabledExtensions *operation.EnabledExtensions) *http.Server {
	t.Helper()

	edvProvider, err := edvprovider.NewProvider(mem.NewProvider(),
		"configurations", "documents", 100)
	require.NoError(t, err)

	edvService, err := restapi.New(&operation.Config{Provider: edvProvider, EnabledExtensions: enabledExtensions})
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
			logger.Fatalf("server failure")
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
			logger.Fatalf("server failure")
		}
	}(&srv)

	return &srv
}

// Just writes some invalid JSON to the response.
func mockReadDocumentHandler(rw http.ResponseWriter, req *http.Request) {
	_, err := rw.Write([]byte("this is invalid JSON and will cause json.Unmarshal to fail"))
	if err != nil {
		logger.Fatalf("failed to write in mock read document handler")
	}
}

// Just writes an arbitrary valid response.
func mockSuccessQueryVaultHandler(rw http.ResponseWriter, req *http.Request) {
	_, err := rw.Write([]byte(testQueryVaultResponse))
	if err != nil {
		logger.Fatalf("failed to write in mock success query vault handler")
	}
}

// Just writes an arbitrary valid response.
func mockSuccessQueryVaultFullDocumentsHandler(rw http.ResponseWriter, req *http.Request) {
	docsBytes, err := json.Marshal([]models.EncryptedDocument{{ID: "docID1"}, {ID: "docID2"}})
	if err != nil {
		logger.Fatalf("failed to marshal docs in mock success query vault full documents handler")
	}

	_, err = rw.Write(docsBytes)
	if err != nil {
		logger.Fatalf("failed to write in mock success query vault full documennts handler")
	}
}

// Just writes some invalid JSON to the response.
func mockFailQueryVaultHandler(rw http.ResponseWriter, req *http.Request) {
	_, err := rw.Write([]byte("this is invalid JSON and will cause json.Unmarshal to fail"))
	if err != nil {
		logger.Fatalf("failed to write in mock fail query vault handler")
	}
}

func failingMarshal(_ interface{}) ([]byte, error) {
	return nil, errFailingMarshal
}

func waitForServerToStart(t *testing.T, srvAddr string) {
	t.Helper()

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

// Extract and return vaultID from vaultLocationURL: /encrypted-data-vaults/{vaultID}
func getVaultIDFromURL(vaultLocationURL string) string {
	vaultLocationSplitUp := strings.Split(vaultLocationURL, "/")

	return vaultLocationSplitUp[len(vaultLocationSplitUp)-1]
}
