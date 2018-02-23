# Envoy Filter Docker Build
This docker container pulls down all dependencies required to build the envoy access fabric filter, and builds the artifacts into the image

## running
This directory contains a script for convenience that can be used to build the artifacts, and copy the results to the local directory, then do some cleanup of the artifacts that are created.

If the build is successful all the artifacts are copied into the `bazel-bin` directory. The script supports two arguments, the github org, and the branch. For example: if your org name was `foo` and your branch name was `new-feature`  you would invoke the script in the following manner:

`sh build-envoy-plugin.sh foo new-feature`

By default the script will use `ScaleFT` and `master` as the org and branch respectively.

## known issues
The tests are currently commented out in the `Dockerfile` as they do not currently succeed and will fail when attempting to create the docker image.


