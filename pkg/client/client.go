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

const (
	failSendRequestForAllDocuments = "failure while sending request to retrieve all documents from vault %s: %w"
	failSendRequestForDocument     = "failure while sending request to vault %s to retrieve document %s: %w"
)

var logger = log.New("edv-client")

type addHeaders func(req *http.Request) (*http.Header, error)

type marshalFunc func(interface{}) ([]byte, error)

// Client is used to interact with an EDV server.
type Client struct {
	edvServerURL string
	httpClient   *http.Client
	marshal      marshalFunc
	headersFunc  addHeaders
}

// Option configures the edv client
type Option func(opts *Client)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *Client) {
		opts.httpClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	}
}

// WithHeaders option is for setting additional http request headers
func WithHeaders(addHeadersFunc addHeaders) Option {
	return func(opts *Client) {
		opts.headersFunc = addHeadersFunc
	}
}

// ReqOpts is used to interact with an EDV operation.
type ReqOpts struct {
	addHeadersFunc addHeaders
}

// ReqOption edv req option
type ReqOption func(opts *ReqOpts)

// WithRequestHeader option is for setting additional http request headers
func WithRequestHeader(addHeadersFunc addHeaders) ReqOption {
	return func(opts *ReqOpts) {
		opts.addHeadersFunc = addHeadersFunc
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
func (c *Client) CreateDataVault(config *models.DataVaultConfiguration, opts ...ReqOption) (string, []byte, error) {
	reqOpt := &ReqOpts{}

	for _, o := range opts {
		o(reqOpt)
	}

	jsonToSend, err := c.marshal(config)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal data vault configuration: %w", err)
	}

	logger.Debugf("Sending request to create a new data vault with the following data vault configuration: %s",
		jsonToSend)

	statusCode, httpHdr, respBytes, err := c.sendHTTPRequest(http.MethodPost, c.edvServerURL, jsonToSend,
		c.getHeaderFunc(reqOpt))
	if err != nil {
		return "", nil, err
	}

	if statusCode == http.StatusCreated {
		return httpHdr.Get("Location"), respBytes, nil
	}

	return "", nil, fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
		statusCode, respBytes)
}

// CreateDocument sends the EDV server a request to store the specified document.
// The location of the newly created document is returned.
func (c *Client) CreateDocument(vaultID string, document *models.EncryptedDocument, opts ...ReqOption) (string, error) {
	reqOpt := &ReqOpts{}

	for _, o := range opts {
		o(reqOpt)
	}

	jsonToSend, err := c.marshal(document)
	if err != nil {
		return "", fmt.Errorf("failed to marshal document: %w", err)
	}

	logger.Debugf("Sending request to create the following document: %s", jsonToSend)

	statusCode, httpHdr, respBytes, err := c.sendHTTPRequest(http.MethodPost,
		c.edvServerURL+fmt.Sprintf("/%s/documents", url.PathEscape(vaultID)), jsonToSend, c.getHeaderFunc(reqOpt))
	if err != nil {
		return "", err
	}

	if statusCode == http.StatusCreated {
		return httpHdr.Get("Location"), nil
	}

	return "", fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
		statusCode, respBytes)
}

// ReadAllDocuments sends the EDV server a request to retrieve all the documents within the specified vault.
func (c *Client) ReadAllDocuments(vaultID string, opts ...ReqOption) ([]models.EncryptedDocument, error) {
	reqOpt := &ReqOpts{}

	for _, o := range opts {
		o(reqOpt)
	}

	endpoint := fmt.Sprintf("%s/%s/documents", c.edvServerURL, url.PathEscape(vaultID))

	statusCode, _, respBody, err := c.sendHTTPRequest(http.MethodGet, endpoint, nil, c.getHeaderFunc(reqOpt))
	if err != nil {
		return nil, fmt.Errorf(failSendRequestForAllDocuments, vaultID, err)
	}

	switch statusCode {
	case http.StatusOK:
		var documents []models.EncryptedDocument

		err = json.Unmarshal(respBody, &documents)
		if err != nil {
			return nil, err
		}

		return documents, nil
	default:
		return nil, fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
			statusCode, respBody)
	}
}

// ReadDocument sends the EDV server a request to retrieve the specified document.
// The requested document is returned.
func (c *Client) ReadDocument(vaultID, docID string, opts ...ReqOption) (*models.EncryptedDocument, error) {
	reqOpt := &ReqOpts{}

	for _, o := range opts {
		o(reqOpt)
	}

	endpoint := fmt.Sprintf("%s/%s/documents/%s", c.edvServerURL, url.PathEscape(vaultID), url.PathEscape(docID))

	statusCode, _, respBody, err := c.sendHTTPRequest(http.MethodGet, endpoint, nil, c.getHeaderFunc(reqOpt))
	if err != nil {
		return nil, fmt.Errorf(failSendRequestForDocument, vaultID, docID, err)
	}

	switch statusCode {
	case http.StatusOK:
		document := models.EncryptedDocument{}

		err = json.Unmarshal(respBody, &document)
		if err != nil {
			return nil, err
		}

		return &document, nil
	default:
		return nil, fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
			statusCode, respBody)
	}
}

// QueryVault queries the given vault and returns the URLs of all documents that match the given query.
func (c *Client) QueryVault(vaultID string, query *models.Query, opts ...ReqOption) ([]string, error) {
	reqOpt := &ReqOpts{}

	for _, o := range opts {
		o(reqOpt)
	}

	jsonToSend, err := c.marshal(query)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/%s/query", c.edvServerURL, url.PathEscape(vaultID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodPost, endpoint, jsonToSend, c.getHeaderFunc(reqOpt))
	if err != nil {
		return nil, err
	}

	if statusCode == http.StatusOK {
		var docURLs []string

		err = json.Unmarshal(respBytes, &docURLs)
		if err != nil {
			return nil, err
		}

		return docURLs, nil
	}

	return nil, fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
		statusCode, respBytes)
}

// UpdateDocument sends the EDV server a request to update the specified document.
func (c *Client) UpdateDocument(vaultID, docID string, document *models.EncryptedDocument, opts ...ReqOption) error {
	reqOpt := &ReqOpts{}

	for _, o := range opts {
		o(reqOpt)
	}

	jsonToSend, err := c.marshal(document)
	if err != nil {
		return fmt.Errorf("failed to marshal document: %w", err)
	}

	logger.Debugf("Sending request to update the following document: %s", jsonToSend)

	endpoint := c.edvServerURL + fmt.Sprintf("/%s/documents/%s", url.PathEscape(vaultID), url.PathEscape(docID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(http.MethodPost, endpoint, jsonToSend, c.getHeaderFunc(reqOpt))
	if err != nil {
		return err
	}

	if statusCode == http.StatusOK || statusCode == http.StatusNoContent {
		return nil
	}

	return fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
		statusCode, respBytes)
}

// DeleteDocument sends the EDV server a request to delete the specified document.
func (c *Client) DeleteDocument(vaultID, docID string, opts ...ReqOption) error {
	reqOpt := &ReqOpts{}

	for _, o := range opts {
		o(reqOpt)
	}

	endpoint := c.edvServerURL + fmt.Sprintf("/%s/documents/%s", url.PathEscape(vaultID), url.PathEscape(docID))

	statusCode, _, respBytes, err := c.sendHTTPRequest(
		http.MethodDelete, endpoint, nil, c.getHeaderFunc(reqOpt))
	if err != nil {
		return err
	}

	if statusCode == http.StatusOK {
		return nil
	}

	return fmt.Errorf("the EDV server returned status code %d along with the following message: %s",
		statusCode, respBytes)
}

func (c *Client) sendHTTPRequest(method, endpoint string, body []byte,
	addHeadersFunc addHeaders) (int, http.Header, []byte, error) {
	req, errReq := http.NewRequest(method, endpoint, bytes.NewBuffer(body))
	if errReq != nil {
		return -1, nil, nil, errReq
	}

	if addHeadersFunc != nil {
		httpHeaders, err := addHeadersFunc(req)
		if err != nil {
			return -1, nil, nil, fmt.Errorf("add optional request headers error: %w", err)
		}

		if httpHeaders != nil {
			req.Header = httpHeaders.Clone()
		}
	}

	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req) //nolint: bodyclose
	if err != nil {
		return -1, nil, nil, err
	}

	defer closeReadCloser(resp.Body)

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return -1, nil, nil, err
	}

	logger.Debugf(`sent %s request to %s response status code: %d response body: %s`, method, endpoint,
		resp.StatusCode, respBytes)

	return resp.StatusCode, resp.Header, respBytes, nil
}

func (c *Client) getHeaderFunc(reqOpt *ReqOpts) addHeaders {
	headersFunc := c.headersFunc

	if reqOpt.addHeadersFunc != nil {
		headersFunc = reqOpt.addHeadersFunc
	}

	return headersFunc
}

func closeReadCloser(respBody io.ReadCloser) {
	err := respBody.Close()
	if err != nil {
		logger.Errorf("Failed to close response body: %s", err)
	}
}
