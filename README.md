# sft_envoy_filter
HTTP envoy filter that verifies JWTs from the ScaleFT access fabric.

Inspiration taken from:
* https://github.com/ibmibmibm/libjose (MIT)
* https://github.com/istio/proxy (Apache 2.0)

## Building

To build the Envoy static binary:

1. `git submodule update --init`
2. `bazel build //src/sft:envoy`

## Running

A trivial upstream server and test config are located in `test-server`.

1. Build
2. `go run echo_request.go`
3. `bazel-bin/src/sft/envoy -c test-server/envoy.conf -l trace`

## TODO

1. Tests
2. RSA, more generic JWT support
3. Move to AsyncClient directly for JWKS fetching.
