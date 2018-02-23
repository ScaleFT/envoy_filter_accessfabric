# Use an official Python runtime as a parent image
FROM ubuntu:16.04

ARG org=ScaleFT
ARG branch=master

ENV org=$org
ENV branch=$branch

# Set the working directory to /access-fabric
WORKDIR /access-fabric

# Install any needed packages specified in requirements.txt
ENV DEBIAN_FRONTEND=noninteractive

# get bazel and envoy build prereqs
RUN apt-get update && apt-get install openjdk-8-jdk cmake git pkg-config zip g++ zlib1g-dev unzip python curl wget realpath libtool clang-format-5.0 automake golang -y
RUN curl --location --output bazel_installer.sh  https://github.com/bazelbuild/bazel/releases/download/0.7.0/bazel-0.7.0-without-jdk-installer-linux-x86_64.sh

RUN chmod 775 bazel_installer.sh
RUN ./bazel_installer.sh

RUN git clone -b $branch https://github.com/$org/envoy_filter_accessfabric

WORKDIR /access-fabric/envoy_filter_accessfabric/

RUN git submodule update --init
RUN bazel build //src/sft:envoy

RUN bazel test --test_output=streamed //src/sft/... --test_arg="-l debug" --test_env=ENVOY_IP_TEST_VERSIONS=v4only
