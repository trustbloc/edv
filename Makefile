# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GO_CMD ?= go
EDV_REST_PATH=cmd/edv-rest

# Namespace for the agent images
DOCKER_OUTPUT_NS   ?= edv
EDV_REST_IMAGE_NAME   ?= edv-rest

# Tool commands (overridable)
GO_CMD     ?= go
ALPINE_VER ?= 3.10
GO_VER ?= 1.13.1

.PHONY: all
all: checks unit-test

.PHONY: checks
checks: license lint

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

unit-test:
	@scripts/check_unit.sh
