# envoy_filter_accessfabric
HTTP envoy filter that verifies JWTs from the ScaleFT access fabric.

Inspiration/hints taken from:
* https://github.com/ibmibmibm/libjose (MIT)
* https://github.com/istio/proxy (Apache 2.0)

## Building

To build the Envoy static binary:

1. `git submodule update --init`
2. `bazel build //src/sft:envoy`

## Testing

1. `bazel test //src/sft/...`
2. Useful debugging: `bazel test --test_output=streamed //src/sft/... --test_arg="-l debug"`

## Configuring

See `test-server/envoy.conf` for a working example.

See `src/sft/integration_test/envoy.conf` for an example with statically configured keys. This is not recommended as these should be rotated regularly (and ScaleFT does), but it's useful for testing.

## Running

A trivial upstream server (golang) and test config are located in `test-server`.

1. Build
2. `go run echo_request.go`
3. Modify `test-server/envoy.conf` appropriately
3. `bazel-bin/src/sft/envoy -c test-server/envoy.conf -l debug`
4. `curl -v http://localhost:8080 -H "Authenticated-User-Jwt: $JWT"`

## TODO

1. More tests - see `TODO`s in `src/sft/integration_test`
2. Think about adding a dependency for JWT/JWK parsing/validation - it's currently very limited to just EC keys.
3. Reorg/Cleanup: JWKS should be a class. Claim validation should be it's responsibility, not in a god method on the filter.
4. When configured to fetch JWKS, the filter initializes before the cluster is ready, so you have to wait an interval before it can actually fetch the JWKS. We need to figure out how to trigger this or just don't use `RestApiFetcher` and do our own polling.
5. Check for leaks/general code review.
