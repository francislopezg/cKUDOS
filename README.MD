# cKUDOS

This repository contains a C implementation of OSCORE-KUDOS, based on uOSCORE-uEDHOC 3.0.5, following the specification in https://datatracker.ietf.org/doc/draft-ietf-core-oscore-key-update/. Additionally, it is also included a Dockerized scenario for testing purposes.

## Features
* The implementation supports the No-FS mode and is fully integrated with both default OSCORE and EDHOC.

## How to Build and Run
* Execute `up.sh` to build the docker image containing the solution and to run a Docker container which uses the previously built Docker image.
* Execute `docker exec -it ckudos-h1-1 /bin/bash` to get an interactive shell in the container.
* Once into the container, browse until `/home/kudos/uoscore-uedhoc-3.0.5-kudos/samples/linux_oscore_kudos/client/`.
* Execute `make` to build the Client.

* Execute `docker exec -it ckudos-h1-1 /bin/bash` to get another terminal in the container.
* Browse until `/home/uedhoc/uoscore-uedhoc-3.0.5-kudos/samples/linux_oscore_kudos/server/` and execute `make` to build the Server.
* Execute `./build/server` to run the Server (which contains a CoAP server that waits for connections).

* Back into the Initiator terminal, execute `./build/client` to run the Initiator. 

## How to clean the compilation
* Execute `make clean` in both the Initiator and Responder folders.
* Exit the container's terminal and execute `./down.sh` to stop and remove the Docker container.

## Requirements

- Docker.

## Acknowledgments

- University of Murcia
- Open Source Projects: Docker, uOSCORE-uEDHOC
- Rikard Höglund and Marco Tiloca as OSCORE-KUDOS draft authors

## Authors

- Francisco López-Gómez (University of Murcia).

- Gabriel López-Millán (University of Murcia).

- Rafael Marín-López (University of Murcia).
