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

	"github.com/DATA-DOG/godog"

	"github.com/trustbloc/edv/test/bdd/dockerutil"
	bddctx "github.com/trustbloc/edv/test/bdd/pkg/context"
	"github.com/trustbloc/edv/test/bdd/pkg/edv"
)

const ExpectedDocument = "${EXPECTED_DOCUMENT}"

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

func runBDDTests(tags, format string) int {
	return godog.RunWithOptions("godogs", func(s *godog.Suite) {
		var composition *dockerutil.Composition
		s.BeforeSuite(func() {
			if os.Getenv("DISABLE_COMPOSITION") != "true" {
				// Need a unique name, but docker does not allow '-' in names
				composeProjectName := strings.ReplaceAll(generateUUID(), "-", "")

				var composeErr error
				composition, composeErr = dockerutil.NewComposition(composeProjectName, "docker-compose.yml", "./fixtures/edv-rest")
				if composeErr != nil {
					panic(fmt.Sprintf("Error composing system in BDD context: %s", composeErr))
				}

				fmt.Println("docker-compose up ... waiting for containers to start ...")
				testSleep := 5
				if os.Getenv("TEST_SLEEP") != "" {
					var e error

					testSleep, e = strconv.Atoi(os.Getenv("TEST_SLEEP"))
					if e != nil {
						panic(fmt.Sprintf("Invalid value found in 'TEST_SLEEP': %s", e))
					}
				}
				fmt.Printf("*** testSleep=%d", testSleep)
				time.Sleep(time.Second * time.Duration(testSleep))
			}
		})
		s.AfterSuite(func() {
			if err := composition.GenerateLogs(composition.Dir, composition.ProjectName+".log"); err != nil {
				panic(err)
			}
			if _, err := composition.Decompose(composition.Dir); err != nil {
				panic(err)
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
	bddContext, err := bddctx.NewBDDContext("http://localhost:8080")
	if err != nil {
		panic(fmt.Sprintf("Error returned from NewBDDContext: %s", err))
	}

	// set dynamic args
	bddContext.Args[ExpectedDocument] =
		`{"id":"VJYHHJx4C8J9Fsgz7rZqSp","meta":{"created":"2020-01-10"},"content":{"message":"Hello EDV!"}}`

	edv.NewSteps(bddContext).RegisterSteps(s)
}
