# Run the EDV server as a binary

## Build the EDV server

The EDV server can be built from within the `cmd/edv-rest` directory with `go build`.

## Run the EDV server

Start the edv server with `./edv-rest start [flags]`.

## EDV server Parameters

Parameters can be set by command line arguments or environment variables:

```
Flags:
  -u, --host-url string   URL to run the edv instance on. Format: HostName:Port. *

* Indicates a required parameter. It must be set by either command line argument or environment variable.
(If both the command line argument and environment variable are set for a parameter, then the command line argument takes precedence)
```

## Example

```shell
$ cd cmd/edv-rest
$ go build
$ ./edv-rest start --host-url localhost:8080
```
