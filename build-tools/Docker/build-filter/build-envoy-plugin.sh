#!/bin/sh

# example invocation with a non-master branch:
# The first argument should be the github org, the second argument should be the branch name
# sh build-envoy-plugin.sh bcoverston make-envoy-plugin-docker

org=${1:-"ScaleFT"}
branch=${2:-"master"}

docker build --build-arg org=$org --build-arg branch=$branch  -t envoybuild .

docker run --name=evb -di envoybuild bash

docker cp -L evb:/access-fabric/envoy_filter_accessfabric/bazel-bin $(pwd)
docker kill evb
docker rm evb
