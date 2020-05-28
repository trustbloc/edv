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

	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edv/pkg/restapi/edv/edverrors"
	"github.com/trustbloc/edv/pkg/restapi/edv/models"
)

var logger = log.New("edv-client")

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
	return c.sendCreateRequest(config, "",
		"a duplicate data vault exists (status code 409 received)")
}

// CreateDocument sends the EDV server a request to store the specified document.
// The location of the newly created document is returned.
func (c *Client) CreateDocument(vaultID string, document *models.EncryptedDocument) (string, error) {
	return c.sendCreateRequest(document, fmt.Sprintf("/%s/documents", url.PathEscape(vaultID)),
		"a document with that id already exists (status code 409 received)")
}

// ReadDocument sends the EDV server a request to retrieve the specified document.
// The requested document is returned.
func (c *Client) ReadDocument(vaultID, docID string) (*models.EncryptedDocument, error) {
	// The linter falsely claims that the body is not being closed
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/%s/documents/%s", //nolint: bodyclose
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
		document := models.EncryptedDocument{}

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

// QueryVault queries the given vault and returns the URLs of all documents that match the given query.
func (c *Client) QueryVault(vaultID string, query *models.Query) ([]string, error) {
	jsonToSend, err := c.marshal(query)
	if err != nil {
		return nil, err
	}

	// The linter falsely claims that the body is not being closed
	// https://github.com/golangci/golangci-lint/issues/637
	resp, err := c.httpClient.Post(fmt.Sprintf("%s/%s/queries", //nolint: bodyclose
		c.edvServerURL, url.PathEscape(vaultID)), "application/json", bytes.NewBuffer(jsonToSend))
	if err != nil {
		return nil, fmt.Errorf("failed to send POST message: %w", err)
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response message while retrieving document: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var docURLs []string

		err = json.Unmarshal(respBytes, &docURLs)
		if err != nil {
			return nil, err
		}

		return docURLs, nil
	default:
		return nil, fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
			resp.StatusCode, respBytes)
	}
}

func (c *Client) sendCreateRequest(objectToMarshal interface{},
	endpoint, statusConflictErrText string) (string, error) {
	jsonToSend, err := c.marshal(objectToMarshal)
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
		logger.Errorf("Failed to close response body: %s", err.Error())
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

	serverEndpointReached :=
		respString == edverrors.ErrVaultNotFound.Error() || respString == edverrors.ErrDocumentNotFound.Error()
	if serverEndpointReached {
		return fmt.Errorf(fmt.Sprintf("failed to retrieve document: %s", respBytes))
	}

	return fmt.Errorf("unable to reach the EDV server Read Credential endpoint")
}
