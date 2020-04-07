/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import (
	"github.com/trustbloc/edv/pkg/edvprovider"
	"github.com/trustbloc/edv/pkg/restapi/edv/operation"
)

// New returns new controller instance.
func New(provider edvprovider.EDVProvider, dbPrefix string) (*Controller, error) {
	var allHandlers []operation.Handler

	edvService := operation.New(provider, dbPrefix)
	allHandlers = append(allHandlers, edvService.GetRESTHandlers()...)

	return &Controller{handlers: allHandlers}, nil
}

// Controller contains handlers for controller
type Controller struct {
	handlers []operation.Handler
}

// GetOperations returns all controller endpoints
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
