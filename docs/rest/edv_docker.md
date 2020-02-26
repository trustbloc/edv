# Run the EDV server as a docker container

## Build the EDV server
Build the docker image for `edv-rest` by running the following make target from the project root directory. 

`make edv-rest-docker`

## Run the EDV server
After building the docker image, start the EDV server by running the command:

```
 docker run docker.pkg.github.com/trustbloc/edv/edv-rest:latest start [flags]
```

Details about flags can be found [here](edv_cli.md#edv-server-parameters).
