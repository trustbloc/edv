# Extensions
This EDV server implementation includes support for an optional feature that, as of writing, is in the spec but is marked "at-risk". It is disabled by default, but can be safely enabled without breaking any standard features. Non-extension-aware clients will still work seamlessly.

Note that the extension is disabled by default. See [here](rest/edv_cli.md#edv-server-parameters) for information on how to enable extensions.

## Batch Endpoint
Allows multiple documents to be created, updated, or deleted in one REST call to the EDV server.

Requests to the endpoint must be in [this format](https://github.com/trustbloc/edv/blob/bf581301a90cc95185354e82a76be717f9e59c77/pkg/restapi/models/models.go#L74). The response body will be an array of responses, one for each vault operation. Responses for successful upserts will be the document locations. No distinction is made between document creation and document updates.

With MongoDB or CouchDB as the storage provider, this endpoint will be significantly faster when you have many documents to be stored at once as compared to calling the standard Create and Update Document endpoints one at a time.

Note that, as of writing, the implementation has an important limitation to be aware of: batch deletes are not yet optimized. See [#171](https://github.com/trustbloc/edv/issues/171) for more information.

This feature is in the spec but is currently considered "at risk" - see [here](https://github.com/decentralized-identity/edv-spec/pull/16) for more information.
