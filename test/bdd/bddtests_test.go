/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"

	"github.com/trustbloc/edv/test/bdd/dockerutil"
	"github.com/trustbloc/edv/test/bdd/pkg/common"
	bddctx "github.com/trustbloc/edv/test/bdd/pkg/context"
	"github.com/trustbloc/edv/test/bdd/pkg/edv"
	"github.com/trustbloc/edv/test/bdd/pkg/interop"
)

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all
	tags := "all"

	flag.Parse()

	format := "progress"
	if getCmdArg("test.v") == "true" {
		format = "pretty"
	}

	runArg := getCmdArg("test.run")
	if runArg != "" {
		tags = runArg
	}

	status := runBDDTests(tags, format)
	if st := m.Run(); st > status {
		status = st
	}

	os.Exit(status)
}

func runBDDTests(tags, format string) int { //nolint: gocognit
	return godog.RunWithOptions("godogs", func(s *godog.Suite) {
		var composition []*dockerutil.Composition
		var composeFiles = []string{"./fixtures/couchdb", "./fixtures/edv-rest"}
		s.BeforeSuite(func() {
			if os.Getenv("DISABLE_COMPOSITION") != "true" {
				// Need a unique name, but docker does not allow '-' in names
				composeProjectName := strings.ReplaceAll(generateUUID(), "-", "")

				for _, v := range composeFiles {
					composition = appendToComposition(composition, v, composeProjectName)
				}

				fmt.Println("docker-compose up ... waiting for containers to start ...")
				testSleep := 50
				if os.Getenv("TEST_SLEEP") != "" {
					var e error

					testSleep, e = strconv.Atoi(os.Getenv("TEST_SLEEP"))
					if e != nil {
						panic(fmt.Sprintf("Invalid value found in 'TEST_SLEEP': %s", e))
					}
				}

				sleepAndWait(testSleep)
			}
		})
		s.AfterSuite(func() {
			for _, c := range composition {
				if c != nil {
					if err := c.GenerateLogs(c.Dir, "docker-compose.log"); err != nil {
						panic(err)
					}
					if _, err := c.Decompose(c.Dir); err != nil {
						panic(err)
					}
				}
			}
		})
		FeatureContext(s)
	}, godog.Options{
		Tags:          tags,
		Format:        format,
		Paths:         []string{"features"},
		Randomize:     time.Now().UTC().UnixNano(), // randomize scenario execution order
		Strict:        true,
		StopOnFailure: true,
	})
}

func appendToComposition(composition []*dockerutil.Composition,
	composeFile, composeProjectName string) []*dockerutil.Composition {
	newComposition, err := dockerutil.NewComposition(composeProjectName,
		"docker-compose.yml", composeFile)
	if err != nil {
		panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
	}

	composition = append(composition, newComposition)

	return composition
}

func sleepAndWait(numSeconds int) {
	fmt.Printf("*** testSleep=%d", numSeconds)
	println()
	time.Sleep(time.Second * time.Duration(numSeconds))
}

func getCmdArg(argName string) string {
	cmdTags := flag.CommandLine.Lookup(argName)
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		return cmdTags.Value.String()
	}

	return ""
}

// generateUUID returns a UUID based on RFC 4122
func generateUUID() string {
	id := dockerutil.GenerateBytesUUID()
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func FeatureContext(s *godog.Suite) {
	bddContext, err := bddctx.NewBDDContext("fixtures/keys/tls/ec-cacert.pem")
	if err != nil {
		panic(fmt.Sprintf("Failed to create a new NewBDDContext: %s", err))
	}

	bddInteropContext, err := bddctx.NewBDDInteropContext()
	if err != nil {
		panic(fmt.Sprintf("Failed to create a new NewBDDInteropContext: %s", err))
	}

	edv.NewSteps(bddContext).RegisterSteps(s)
	common.NewSteps(bddContext).RegisterSteps(s)
	interop.NewSteps(bddInteropContext).RegisterSteps(s)
}
