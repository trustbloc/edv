# Run the EDV server as a binary

## Build the EDV server

The EDV server can be built from within the `cmd/edv-rest` directory with `go build`.

## Run the EDV server

Start the edv server with `./edv-rest start [flags]`.

## EDV server Parameters

Parameters can be set by command line arguments or environment variables:

```      
      --auth-enable                      string   Enable authorization. Possible values [true] [false]. Defaults to false if not set. Alternatively, this can be set with the following environment variable: EDV_AUTH_ENABLE
      --cors-enable                      string   Enable cors. Possible values [true] [false]. Defaults to false if not set. Alternatively, this can be set with the following environment variable: EDV_CORS_ENABLE
  -p, --database-prefix                  string   An optional prefix to be used when creating and retrieving underlying databases. This followed by an underscore will be prepended to any incoming vault IDs received in REST calls before creating or accessing underlying databases. Alternatively, this can be set with the following environment variable: EDV_DATABASE_PREFIX
  -s, --database-retrieval-page-size     string   Number of entries within each page when doing bulk operations within underlying databases. Larger values provide better performance at the expense of memory usage. This option is ignored if the database type is mem. Default: 100. Alternatively, this can be set with the following environment variable: EDV_DATABASE_PAGE_SIZE
  -o, --database-timeout                 string   Total time in seconds to wait until the database is available before giving up. Default: 30 seconds. Alternatively, this can be set with the following environment variable: EDV_DATABASE_TIMEOUT
  -t, --database-type                    string   The type of database to use internally in the EDV. Supported options: mem, couchdb. Note that mem doesn't support encrypted index querying. Alternatively, this can be set with the following environment variable: EDV_DATABASE_TYPE
  -r, --database-url                     string   The URL of the database. Not needed if using memstore. For CouchDB, include the username:password@ text. Alternatively, this can be set with the following environment variable: EDV_DATABASE_URL
  -u, --host-url                         string   URL to run the edv instance on. Format: HostName:Port. Alternatively, this can be set with the following environment variable: EDV_HOST_URL
      --localkms-secrets-database-prefix string   An optional prefix to be used when creating and retrieving the underlying KMS secrets database. Alternatively, this can be set with the following environment variable: EDV_LOCALKMS_SECRETS_DATABASE_PREFIX
      --localkms-secrets-database-type   string   The type of database to use for storing KMS secrets for Keystore. Supported options: mem, couchdb. Alternatively, this can be set with the following environment variable: EDV_LOCALKMS_SECRETS_DATABASE_TYPE
      --localkms-secrets-database-url    string   The URL of the database for KMS secrets. Not needed if using in-memory storage. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: EDV_LOCALKMS_SECRETS_DATABASE_URL
  -l, --log-level                        string   Logging level to set. Supported options: critical, error, warning, info, debug.Defaults to "info" if not set. Setting to "debug" may adversely impact performance. Alternatively, this can be set with the following environment variable: EDV_LOG_LEVEL
      --tls-cert-file                    string   TLS certificate file. Alternatively, this can be set with the following environment variable: EDV_TLS_CERT_FILE
      --tls-key-file                     string   TLS key file. Alternatively, this can be set with the following environment variable: EDV_TLS_KEY_FILE
      --with-extensions                  string   Enables features that are extensions of the spec. If set, must be a comma-separated list of some or all of the following possible values: [ReturnFullDocumentsOnQuery,Batch,ReadAllDocuments]. If not set, then no extensions will be used and the EDV server will be strictly conformant with the spec. These can all be safely enabled without breaking any core EDV functionality or non-extension-aware clients.Alternatively, this can be set with the following environment variable: EDV_EXTENSIONS

(If both the command line argument and environment variable are set for a parameter, then the command line argument takes precedence)
```

## Example

```shell
$ cd cmd/edv-rest
$ go build
$ ./edv-rest start --host-url localhost:8071 --database-type couchdb --database-url admin:password@localhost:5984 --database-prefix edvprefix --with-extensions ReturnFullDocumentsOnQuery,Batch --log-level debug
```
