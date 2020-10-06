/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package edv-rest EDV REST API.
//
//     Schemes: http
//     Version: 0.1.0
//     License: SPDX-License-Identifier: Apache-2.0
//
//     Consumes:
//     - application/json
//
//     Produces:
//     - application/json
//
// swagger:meta
package main

import (
	"github.com/spf13/cobra"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/edv/cmd/edv-rest/startcmd"
)

var logger = log.New("edv-rest")

func main() {
	rootCmd := &cobra.Command{
		Use: "edv-rest",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(startcmd.GetStartCmd(&startcmd.HTTPServer{}, &startcmd.ActualDBInitializer{}))

	if err := rootCmd.Execute(); err != nil {
		logger.Fatalf("Failed to run edv: %s", err)
	}
}
