# EDV - Build

## Prerequisites (General)
- Go 1.16

## Prerequisites (for running tests and demos)
- Go 1.16
- Docker
- Docker-Compose
- Make

## Targets
```
# run all the project build targets
make all

# run license and linter checks
make checks

# run unit tests
make unit-test

# run bdd tests
make bdd-test

# generate a self-signed cert that can be used to run the EDV server with TLS (for testing purposes)
make generate-test-keys

# start the OpenAPI demo
make run-openapi-demo
```
