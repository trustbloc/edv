# Extensions
This EDV server implementation includes support for a number of optional features that, as of writing, are considered "at-risk" features in the specification and may not be widely supported by other implementations. They may all be enabled safely without breaking any standard features. Non-extension-aware clients will still work seamlessly.

Note that extensions are disabled by default. See [here](rest/edv_cli.md#edv-server-parameters) for information on how to enable extensions.

## Batch Endpoint
Allows multiple documents to be created, updated, or deleted in one REST call to the EDV server.

Requests to the endpoint must be in [this format](https://github.com/trustbloc/edv/blob/bf581301a90cc95185354e82a76be717f9e59c77/pkg/restapi/models/models.go#L74). The response body will be an array of responses, one for each vault operation. Responses for successful upserts will be the document locations. No distinction is made between document creation and document updates.

With MongoDB or CouchDB as the storage provider, this endpoint will be significantly faster when you have many documents to be stored at once as compared to calling the standard Create and Update Document endpoints one at a time.

Note that, as of writing, the implementation has an important limitation to be aware of: batch deletes are not yet optimized. See [#171](https://github.com/trustbloc/edv/issues/171) for more information.

The request in the spec repo to add this feature can be found [here](https://github.com/decentralized-identity/confidential-storage/issues/138).

## Return Full Documents on Query
Allows query results to be full documents instead of document locations. This allows clients to directly get their documents in one step instead of requiring them to get the full documents in separate REST calls.

Queries must include a "returnFullDocuments" field in the JSON set to true for this endpoint to return full documents.
