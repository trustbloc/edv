/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package client

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edv/pkg/restapi/models"
)

var logger = log.New("EDV-Client")

type marshalFunc func(interface{}) ([]byte, error)

// Client is used to interact with an EDV server.
type Client struct {
	edvServerURL string
	httpClient   *http.Client
	marshal      marshalFunc
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
	c := &Client{edvServerURL: edvServerURL, httpClient: &http.Client{}, marshal: json.Marshal}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// CreateDataVault sends the EDV server a request to create a new data vault.
// The location of the newly created data vault is returned.
func (c *Client) CreateDataVault(config *models.DataVaultConfiguration) (string, error) {
	jsonToSend, err := c.marshal(config)
	if err != nil {
		return "", fmt.Errorf("failed to marshal data vault configuration: %w", err)
	}

	logger.Debugf("Sending request to create a new data vault with the following data vault configuration: %s",
		jsonToSend)

	return c.sendPOSTCreateRequest(jsonToSend, "")
}

// CreateDocument sends the EDV server a request to store the specified document.
// The location of the newly created document is returned.
func (c *Client) CreateDocument(vaultID string, document *models.EncryptedDocument) (string, error) {
	jsonToSend, err := c.marshal(document)
	if err != nil {
		return "", fmt.Errorf("failed to marshal document: %w", err)
	}

	logger.Debugf("Sending request to create the following document: %s", jsonToSend)

	return c.sendPOSTCreateRequest(jsonToSend, fmt.Sprintf("/%s/documents", url.PathEscape(vaultID)))
}

// ReadDocument sends the EDV server a request to retrieve the specified document.
// The requested document is returned.
func (c *Client) ReadDocument(vaultID, docID string) (*models.EncryptedDocument, error) {
	endpoint := fmt.Sprintf("%s/%s/documents/%s", c.edvServerURL, url.PathEscape(vaultID), url.PathEscape(docID))

	// The linter falsely claims that the body is not being closed
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := c.httpClient.Get(endpoint) //nolint: bodyclose
	if err != nil {
		return nil, fmt.Errorf("failed to send GET message: %w", err)
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response message while retrieving document: %w", err)
	}

	logger.Debugf(`Sent GET request to %s.
Response status code: %d
Response body: %s`, endpoint, resp.StatusCode, respBytes)

	switch resp.StatusCode {
	case http.StatusOK:
		document := models.EncryptedDocument{}

		err = json.Unmarshal(respBytes, &document)
		if err != nil {
			return nil, err
		}

		return &document, nil
	default:
		return nil, fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
			resp.StatusCode, respBytes)
	}
}

// QueryVault queries the given vault and returns the URLs of all documents that match the given query.
func (c *Client) QueryVault(vaultID string, query *models.Query) ([]string, error) {
	jsonToSend, err := c.marshal(query)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/queries", c.edvServerURL, url.PathEscape(vaultID))

	// The linter falsely claims that the body is not being closed
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := c.httpClient.Post(endpoint, "application/json", //nolint: bodyclose
		bytes.NewBuffer(jsonToSend))
	if err != nil {
		return nil, fmt.Errorf("failed to send POST message: %w", err)
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response message while retrieving document: %w", err)
	}

	logger.Debugf(`Sent POST request to %s.
Request body: %s

Response status code: %d
Response body: %s`, endpoint, jsonToSend, resp.StatusCode, respBytes)

	if resp.StatusCode == http.StatusOK {
		var docURLs []string

		err = json.Unmarshal(respBytes, &docURLs)
		if err != nil {
			return nil, err
		}

		return docURLs, nil
	}

	return nil, fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
		resp.StatusCode, respBytes)
}

func (c *Client) sendPOSTCreateRequest(jsonToSend []byte, endpointPathToAppend string) (string, error) {
	fullEndpoint := c.edvServerURL + endpointPathToAppend

	resp, err := c.httpClient.Post(fullEndpoint, "application/json", //nolint: bodyclose
		bytes.NewBuffer(jsonToSend))
	if err != nil {
		return "", fmt.Errorf("failed to send POST request: %w", err)
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	logger.Debugf(`Sent POST request to %s.
Request body: %s

Response status code: %d
Response body: %s`, fullEndpoint, jsonToSend, resp.StatusCode, respBytes)

	if resp.StatusCode == http.StatusCreated {
		return resp.Header.Get("Location"), nil
	}

	return "", fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
		resp.StatusCode, respBytes)
}

func closeReadCloser(respBody io.ReadCloser) {
	err := respBody.Close()
	if err != nil {
		logger.Errorf("Failed to close response body: %s", err)
	}
}
