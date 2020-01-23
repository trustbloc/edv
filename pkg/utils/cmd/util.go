/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// GetUserSetVar returns values either command line flag or environment variable
func GetUserSetVar(cmd *cobra.Command, flagName, envKey string) (string, error) {
	if cmd.Flags().Changed(flagName) {
		value, err := cmd.Flags().GetString(flagName)
		if err != nil {
			return "", fmt.Errorf(flagName+" flag not found: %s", err)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)

	if isSet {
		return value, nil
	}

	return "", fmt.Errorf("neither %s (command line flag) nor %s (environment variable) have been set", flagName, envKey)
}
