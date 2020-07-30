# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

EDV_REST_PATH=cmd/edv-rest

# Namespace for the EDV server image
DOCKER_OUTPUT_NS   ?= docker.pkg.github.com
EDV_REST_IMAGE_NAME   ?= trustbloc/edv/edv-rest

# OpenAPI spec
OPENAPI_DOCKER_IMG=quay.io/goswagger/swagger
OPENAPI_SPEC_PATH=build/rest/openapi/spec
OPENAPI_DOCKER_IMG_VERSION=v0.23.0

# Tool commands (overridable)
ALPINE_VER ?= 3.10
GO_VER ?= 1.13.1

.PHONY: all
all: checks unit-test bdd-test

.PHONY: checks
checks: license lint generate-openapi-spec

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: edv-rest
edv-rest:
	@echo "Building edv-rest"
	@mkdir -p ./build/bin
	@cd ${EDV_REST_PATH} && go build -o ../../build/bin/edv-rest main.go

.PHONY: edv-rest-docker
edv-rest-docker:
	@echo "Building edv rest docker image"
	@docker build -f ./images/edv-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(EDV_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: bdd-test
bdd-test: edv-rest-docker generate-test-keys
	@rm -Rf ./test/bdd/*.log
	@scripts/check_integration.sh

unit-test:
	@scripts/check_unit.sh

.PHONY: generate-openapi-spec
generate-openapi-spec: clean
	@echo "Generating and validating controller API specifications using Open API"
	@mkdir -p build/rest/openapi/spec
	@SPEC_META=$(VC_REST_PATH) SPEC_LOC=${OPENAPI_SPEC_PATH}  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-openapi-spec.sh

.PHONY: generate-openapi-demo-specs
generate-openapi-demo-specs: clean generate-openapi-spec edv-rest-docker
	@echo "Generate demo agent rest controller API specifications using Open API"
	@SPEC_PATH=${OPENAPI_SPEC_PATH} OPENAPI_DEMO_PATH=test/bdd/fixtures/openapi-demo \
    	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
    	scripts/generate-openapi-demo-specs.sh

.PHONY: run-openapi-demo
run-openapi-demo: generate-openapi-demo-specs
	@echo "Starting OpenAPI demo and EDV containers ..."
	@FIXTURES_PATH=test/bdd/fixtures  \
        scripts/run-openapi-demo.sh

.PHONY: generate-test-keys
generate-test-keys:
	@mkdir -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/edv \
		--entrypoint "/opt/workspace/edv/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
	@rm -Rf ./test/bdd/docker-compose.log

