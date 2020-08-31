# Run the EDV server as a binary

## Build the EDV server

The EDV server can be built from within the `cmd/edv-rest` directory with `go build`.

## Run the EDV server

Start the edv server with `./edv-rest start [flags]`.

## EDV server Parameters

Parameters can be set by command line arguments or environment variables:

```
Flags:
  -p, --database-prefix string   An optional prefix to be used when creating and retrieving underlying databases. This followed by an underscore will be prepended to any incoming vault IDs received in REST calls before creating or accessing underlying databases. Alternatively, this can be set with the following environment variable: EDV_DATABASE_PREFIX
  -t, --database-type string     The type of database to use internally in the EDV. Supported options: mem, couchdb. Note that mem doesn't support encrypted index querying. Alternatively, this can be set with the following environment variable: EDV_DATABASE_TYPE *
  -r, --database-url string      The URL of the database. Not needed if using memstore. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: EDV_DATABASE_URL
  -u, --host-url string          URL to run the edv instance on. Format: HostName:Port. Alternatively, this can be set with the following environment variable: EDV_HOST_URL *
  -l, --log-level string         Logging level to set. Supported options: critical, error, warning, info, debug.Defaults to "info" if not set. Setting to "debug" may adversely impact performance. Alternatively, this can be set with the following environment variable: EDV_LOG_LEVEL
      --tls-cert-file string     TLS certificate file. Alternatively, this can be set with the following environment variable: EDV_TLS_CERT_FILE
      --tls-key-file string      TLS key file. Alternatively, this can be set with the following environment variable: EDV_TLS_KEY_FILE


* Indicates a required parameter. It must be set by either command line argument or environment variable.
(If both the command line argument and environment variable are set for a parameter, then the command line argument takes precedence)
```

## Example

```shell
$ cd cmd/edv-rest
$ go build
$ ./edv-rest start --host-url localhost:8071 --database-type couchdb --database-url localhost:5984 --database-prefix edvprefix
```
