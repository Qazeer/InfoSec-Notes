# DFIR - Docker

### Image analysis

```bash
# Lists the images available.
docker image ls

# Automated analysis on the specified image, to retrieve a number of information: exposed service(s), Docker file, etc.
docker run -t --rm -v /var/run/docker.sock:/var/run/docker.sock:ro pegleg/whaler -sV=1.36 <IMAGE>

# Displays information on the specified image.
docker image inspect <IMAGE> | jq

# Validates the trust on the specified image.
docker trust inspect <IMAGE> | jq

# Print the history of the commands used to build the image.
docker image history --no-trunc <IMAGE>
# Adds timestamps to the commands history.
docker history --no-trunc --format "{{.CreatedAt}}: {{.CreatedBy}}" <IMAGE>

# Extract a specific file from an image without running a container.
container_id=`docker create <IMAGE>`
docker cp $container_id:/<FILE_PATH_ON_CONTAINER> <OUTPUT_FILE_PATH>

# Save a docker image as a tar archive, containing for each layers of the image metadata (docker-file like) and image files.
docker save -o <OUTPUT_TAR> <IMAGE>
tar -xvf <OUTPUT_TAR>
cat <LAYER_HASH | *>/json | jq
```
