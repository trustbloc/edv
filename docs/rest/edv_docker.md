# Run the EDV server as a docker container

## Build the EDV server
Build the docker image for `edv` by running the following make target from the project root directory. 

`make edv-docker`

## Run the EDV server
After building the docker image, start the EDV server by running the command:

```
 docker run ghcr.io/trustbloc/edv:latest start [flags]
```

Details about flags can be found [here](edv_cli.md#edv-server-parameters).
