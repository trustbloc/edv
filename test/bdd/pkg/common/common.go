/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import "fmt"

// UnexpectedValueError returns an error message indicating that an unexpected value was found.
func UnexpectedValueError(expected, actual string) error {
	return fmt.Errorf("expected %s but got %s instead", expected, actual)
}
