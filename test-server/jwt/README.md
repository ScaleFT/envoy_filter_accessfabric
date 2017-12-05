#### JWT fixture utility

This small go utility will generate and sign fixutre JWKs/JWTs for unit tests with consistent private keys, making it easy to add and generate jwts for new test cases.

Obviously - the keys included here should never be used for anything but tests.

```go build . && ./jwt```