/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
)

// Client is used to interact with an EDV server.
type Client struct {
	edvServerURL string
	httpClient   *http.Client
}

// Option configures the edv client
type Option func(opts *Client)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *Client) {
		opts.httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
}

// New returns a new instance of an EDV client.
func New(edvServerURL string, opts ...Option) *Client {
	c := &Client{edvServerURL: edvServerURL, httpClient: &http.Client{}}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// CreateDataVault sends the EDV server a request to create a new data vault.
// The location of the newly created data vault is returned.
func (c *Client) CreateDataVault(config *operation.DataVaultConfiguration) (string, error) {
	return c.sendCreateRequest(config, "/data-vaults", "a duplicate data vault exists")
}

// CreateDocument sends the EDV server a request to store the specified document.
// The location of the newly created document is returned.
func (c *Client) CreateDocument(vaultID string, document *operation.EncryptedDocument) (string, error) {
	return c.sendCreateRequest(document, fmt.Sprintf("/encrypted-data-vaults/%s/docs", url.PathEscape(vaultID)), "")
}

// ReadDocument sends the EDV server a request to retrieve the specified document.
// The requested document is returned.
func (c *Client) ReadDocument(vaultID, docID string) (*operation.EncryptedDocument, error) {
	// The linter falsely claims that the body is not being closed
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/encrypted-data-vaults/%s/docs/%s", //nolint: bodyclose
		c.edvServerURL, url.PathEscape(vaultID), url.PathEscape(docID)))
	if err != nil {
		return nil, fmt.Errorf("failed to send GET message: %w", err)
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response message while retrieving document: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		document := operation.EncryptedDocument{}

		err = json.Unmarshal(respBytes, &document)
		if err != nil {
			return nil, err
		}

		return &document, nil
	case http.StatusNotFound:
		return nil, getStatusNotFoundErr(respBytes)
	default:
		return nil, fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
			resp.StatusCode, respBytes)
	}
}

func (c *Client) sendCreateRequest(objectToMarshal interface{},
	endpoint, statusConflictErrText string) (string, error) {
	jsonToSend, err := json.Marshal(objectToMarshal)
	if err != nil {
		return "", fmt.Errorf("failed to marshal object: %w", err)
	}

	resp, err := c.httpClient.Post(c.edvServerURL+endpoint, "application/json", bytes.NewBuffer(jsonToSend))
	if err != nil {
		return "", fmt.Errorf("failed to send POST message: %w", err)
	}

	defer closeReadCloser(resp.Body)

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return "", getError(resp)
	case http.StatusConflict:
		return "", fmt.Errorf("%s", statusConflictErrText)
	default:
		if resp.StatusCode != http.StatusCreated {
			respText, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return "", fmt.Errorf("unable to read response: %w", err)
			}

			return "", fmt.Errorf("%s", string(respText))
		}
	}

	return resp.Header.Get("Location"), nil
}

func closeReadCloser(respBody io.ReadCloser) {
	err := respBody.Close()
	if err != nil {
		log.Errorf("Failed to close response body: %s", err.Error())
	}
}

func getError(resp *http.Response) error {
	respMsg, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response message: %w", err)
	}

	return fmt.Errorf("the EDV server returned the following error: %s", string(respMsg))
}

func getStatusNotFoundErr(respBytes []byte) error {
	respString := string(respBytes)

	serverEndpointReached := respString == operation.VaultNotFoundErrMsg || respString == operation.DocumentNotFoundErrMsg
	if serverEndpointReached {
		return fmt.Errorf(fmt.Sprintf("failed to retrieve document: %s", respBytes))
	}

	return fmt.Errorf("unable to reach the EDV server Read Credential endpoint")
}
