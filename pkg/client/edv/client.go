/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
)

// Client is used to interact with an EDV server.
type Client struct {
	edvServerURL string
}

// New returns a new instance of an EDV client.
func New(edvServerURL string) *Client {
	return &Client{edvServerURL: edvServerURL}
}

// CreateDataVault sends the EDV server a request to create a new data vault.
// The location of the newly created data vault is returned.
func (c *Client) CreateDataVault(config *operation.DataVaultConfiguration) (string, error) {
	return c.sendPostJSON(config, "/data-vaults", "a duplicate data vault exists")
}

// CreateDocument sends the EDV server a request to store the specified document.
// The location of the newly created document is returned.
func (c *Client) CreateDocument(vaultID string, document *operation.StructuredDocument) (string, error) {
	return c.sendPostJSON(document, fmt.Sprintf("/encrypted-data-vaults/%s/docs", vaultID), "")
}

// RetrieveDocument sends the EDV server a request to retrieve the specified document.
// The requested document is returned.
func (c *Client) RetrieveDocument(vaultID, docID string) ([]byte, error) {
	resp, err := http.Get(c.edvServerURL + "/encrypted-data-vaults/" + vaultID + "/docs/" + docID)
	if err != nil {
		return nil, fmt.Errorf("failed to send GET message: %w", err)
	}

	defer closeBody(resp)

	if resp.StatusCode == http.StatusBadRequest {
		return nil, getError(resp)
	} else if resp.StatusCode == http.StatusNotFound {
		return nil,
			fmt.Errorf(fmt.Sprintf("no document with an id of %s could be found in the vault with id %s", docID, vaultID))
	}

	return getDocumentFromResponse(resp)
}

func getDocumentFromResponse(resp *http.Response) ([]byte, error) {
	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response message while retrieving document: %w", err)
	}

	return respData, nil
}

func closeBody(resp *http.Response) {
	err := resp.Body.Close()
	if err != nil {
		log.Errorf("Failed to close response body: %s", err.Error())
	}
}

func (c *Client) sendPostJSON(objectToMarshal interface{}, endpoint, statusConflictErrText string) (string, error) {
	jsonToSend, err := json.Marshal(objectToMarshal)
	if err != nil {
		return "", fmt.Errorf("failed to marshal object: %w", err)
	}

	resp, err := http.Post(c.edvServerURL+endpoint, "application/json", bytes.NewBuffer(jsonToSend))
	if err != nil {
		return "", fmt.Errorf("failed to send POST message: %w", err)
	}

	defer closeBody(resp)

	if resp.StatusCode == http.StatusBadRequest {
		return "", getError(resp)
	} else if resp.StatusCode == http.StatusConflict {
		return "", errors.New(statusConflictErrText)
	}

	return resp.Header.Get("Location"), nil
}

func getError(resp *http.Response) error {
	respMsg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response message: %w", err)
	}

	return fmt.Errorf("the EDV server returned the following error: %s", string(respMsg))
}
