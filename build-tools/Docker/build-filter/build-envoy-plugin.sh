#!/bin/sh

#TODO add build-arg support into this script. This will default to the master branch
docker build -t envoybuild .

docker run --name=evb -di envoybuild bash

docker cp -L evb:/access-fabric/envoy_filter_accessfabric/bazel-bin $(pwd)
docker kill evb
docker rm evb
