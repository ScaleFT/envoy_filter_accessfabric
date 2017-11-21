#include "test/integration/http_integration.h"
#include "test/integration/utility.h"
#include "../sft_filter.h"

namespace Envoy {

class SFTFilterIntegrationTestBase : public HttpIntegrationTest,
                                     public testing::TestWithParam<Network::Address::IpVersion> {
public:
  SFTFilterIntegrationTestBase()
      : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam()) {}
  virtual ~SFTFilterIntegrationTestBase() {}

  void SetUp() override {
    fake_upstreams_.emplace_back(new FakeUpstream(0, FakeHttpConnection::Type::HTTP1, version_));
    registerPort("upstream_0", fake_upstreams_.back()->localAddress()->ip()->port());
    createTestServer("src/sft/integration_test/envoy.conf", {"http"});
  }

  void TearDown() override {
    test_server_.reset();
    fake_upstreams_.clear();
  }

protected:
  Http::TestHeaderMapImpl BaseRequestHeaders() {
    return Http::TestHeaderMapImpl{{":method", "GET"}, {":path", "/"}, {":authority", "host"}};
  }

  Http::TestHeaderMapImpl createHeaders(const std::string& token) {
    auto headers = BaseRequestHeaders();
    headers.addCopy("Authenticated-User-Jwt", token);
    return headers;
  }

  std::string InstanceToString(Buffer::Instance& instance) {
    auto len = instance.length();
    return std::string(static_cast<char*>(instance.linearize(len)), len);
  }

  std::map<std::string, std::string> HeadersMapToMap(const Http::HeaderMap& headers) {
    std::map<std::string, std::string> ret;
    headers.iterate(
        [](const Http::HeaderEntry& entry, void* context) -> Http::HeaderMap::Iterate {
          auto ret = static_cast<std::map<std::string, std::string>*>(context);
          Http::LowerCaseString lower_key{entry.key().c_str()};
          (*ret)[std::string(lower_key.get())] = std::string(entry.value().c_str());
          return Http::HeaderMap::Iterate::Continue;
        },
        &ret);
    return ret;
  };

  void ExpectHeaderIncluded(const Http::HeaderMap& headers1, const Http::HeaderMap& headers2) {
    auto map1 = HeadersMapToMap(headers1);
    auto map2 = HeadersMapToMap(headers2);
    for (const auto& kv : map1) {
      EXPECT_EQ(map2[kv.first], kv.second);
    }
  }

  void TestVerification(const Http::HeaderMap& request_headers, const std::string& request_body,
                        bool verification_success, const Http::HeaderMap& expected_headers,
                        const std::string& expected_body) {
    IntegrationCodecClientPtr codec_client;
    FakeHttpConnectionPtr fake_upstream_connection_backend;
    FakeStreamPtr request_stream_backend;
    IntegrationStreamDecoderPtr response(new IntegrationStreamDecoder(*dispatcher_));

    codec_client = makeHttpConnection(lookupPort("http"));

    // Send a request to Envoy.
    if (!request_body.empty()) {
      Http::StreamEncoder& encoder = codec_client->startRequest(request_headers, *response);
      Buffer::OwnedImpl body(request_body);
      codec_client->sendData(encoder, body, true);
    } else {
      codec_client->makeHeaderOnlyRequest(request_headers, *response);
    }

    // Valid JWT case.
    // Check if the request sent to the backend includes the expected one.
    if (verification_success) {
      fake_upstream_connection_backend = fake_upstreams_[0]->waitForHttpConnection(*dispatcher_);
      request_stream_backend = fake_upstream_connection_backend->waitForNewStream(*dispatcher_);
      request_stream_backend->waitForEndStream(*dispatcher_);

      EXPECT_TRUE(request_stream_backend->complete());

      ExpectHeaderIncluded(expected_headers, request_stream_backend->headers());
      if (!expected_body.empty()) {
        EXPECT_EQ(expected_body, InstanceToString(request_stream_backend->body()));
      }

      fake_upstream_connection_backend->close();
      fake_upstream_connection_backend->waitForDisconnect();
    }

    response->waitForEndStream();

    // Invalid JWT case.
    // Check if the response sent to the client includes the expected one.
    if (!verification_success) {
      EXPECT_TRUE(response->complete());

      ExpectHeaderIncluded(expected_headers, response->headers());
      if (!expected_body.empty()) {
        EXPECT_EQ(expected_body, response->body());
      }
    }

    codec_client->close();
  }
};

class SFTVerificationFilterIntegrationTest : public SFTFilterIntegrationTestBase {};

INSTANTIATE_TEST_CASE_P(IpVersions, SFTVerificationFilterIntegrationTest,
                        testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

// Valid jwt signed with a known key.
TEST_P(SFTVerificationFilterIntegrationTest, ValidJWT) {
  const std::string jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjY1Mjg5YjE5LWUwYzYtNDkxOC04OTMzLTc5NjE3ODFh"
                          "ZGIwZCJ9."
                          "eyJhdWQiOlsiYXVkMSJdLCJpYXQiOjEuNTEwOTg5NTYxZSswOSwiaXNzIjoiaXNzMSIsImp0"
                          "aSI6ImlkMSIsInN1YiI6InN1YjEifQ.6VI2lPN09XWiszKN_ioIDAPYpE9Eeu_"
                          "6s1nN7dnPpjtQBK2m8VfqN5bqSCJ-ZFvM3jeRSvZtS3CJV5ZwPd-t1w";

  auto expected_headers = BaseRequestHeaders();
  expected_headers.addCopy("authenticated-user-jwt", jwt);

  TestVerification(createHeaders(jwt), "", true, expected_headers, "");
}

// Similar valid jwt - different allowed audience and signed with second key.
TEST_P(SFTVerificationFilterIntegrationTest, ValidJWT2) {
  const std::string jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVlZmRmODc5LWM5NDEtNDcwMS1iZDVkLWYzNTdiZmY3"
                          "Nzk4ZCJ9."
                          "eyJhdWQiOlsiYXVkMiJdLCJpYXQiOjEuNTEwOTg5NTYxZSswOSwiaXNzIjoiaXNzMSIsImp0"
                          "aSI6ImlkMiIsInN1YiI6InN1YjIifQ.HeXTyMXfUM7J_"
                          "reCkGI3OnbfXc7HbUpz98knlBmwu39CNHx90r4qUbe3KwpLl54P9UiF2PkfOfhUo0NlA6gYl"
                          "Q";

  auto expected_headers = BaseRequestHeaders();
  expected_headers.addCopy("authenticated-user-jwt", jwt);

  TestVerification(createHeaders(jwt), "", true, expected_headers, "");
}

// Omit jwt header from request entirely.
TEST_P(SFTVerificationFilterIntegrationTest, MissingJWT) {
  TestVerification(
      BaseRequestHeaders(), "", false, Http::TestHeaderMapImpl{{":status", "401"}},
      Http::Sft::VerifyStatusToString(Http::Sft::VerifyStatus::JWT_VERIFY_FAIL_NOT_PRESENT));
}

// Change 1 bit in the signature.
TEST_P(SFTVerificationFilterIntegrationTest, InvalidJWTInvalidSignature) {
  const std::string jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVlZmRmODc5LWM5NDEtNDcwMS1iZDVkLWYzNTdiZmY3"
                          "Nzk4ZCJ9."
                          "eyJhdWQiOlsiYXVkMiJdLCJpYXQiOjEuNTEwOTg5NTYxZSswOSwiaXNzIjoiaXNzMSIsImp0"
                          "aSI6ImlkMiIsInN1YiI6InN1YjIifQ.HeXTyMXfUM7J_"
                          "reCkGI3OnbfXc7HbUpz98knlBmwu39CNHx90r3qUbe3KwpLl54P9UiF2PkfOfhUo0NlA6gYl"
                          "Q";

  TestVerification(
      createHeaders(jwt), "", false, Http::TestHeaderMapImpl{{":status", "401"}},
      Http::Sft::VerifyStatusToString(Http::Sft::VerifyStatus::JWT_VERIFY_FAIL_INVALID_SIGNATURE));
}

// Remove entire header block.
TEST_P(SFTVerificationFilterIntegrationTest, InvalidJWTMalformedMissingHeader) {
  const std::string jwt = "eyJhdWQiOlsiYXVkMiJdLCJpYXQiOjEuNTEwOTg5NTYxZSswOSwiaXNzIjoiaXNzMSIsImp0"
                          "aSI6ImlkMiIsInN1YiI6InN1YjIifQ.HeXTyMXfUM7J_"
                          "reCkGI3OnbfXc7HbUpz98knlBmwu39CNHx90r4qUbe3KwpLl54P9UiF2PkfOfhUo0NlA6gYl"
                          "Q";

  TestVerification(
      createHeaders(jwt), "", false, Http::TestHeaderMapImpl{{":status", "401"}},
      Http::Sft::VerifyStatusToString(Http::Sft::VerifyStatus::JWT_VERIFY_FAIL_MALFORMED));
}

// Remove some random bytes from the header block.
TEST_P(SFTVerificationFilterIntegrationTest, InvalidJWTMalformedHeader) {
  const std::string jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6VlZmRmODc5LWM5NDEtNDcwMS1iZDVkLWYzNTdiZmY3"
                          "Nzk4ZCJ9."
                          "eyJhdWQiOlsiYXVkMiJdLCJpYXQiOjEuNTEwOTg5NTYxZSswOSwiaXNzIjoiaXNzMSIsImp0"
                          "aSI6ImlkMiIsInN1YiI6InN1YjIifQ.HeXTyMXfUM7J_"
                          "reCkGI3OnbfXc7HbUpz98knlBmwu39CNHx90r4qUbe3KwpLl54P9UiF2PkfOfhUo0NlA6gYl"
                          "Q";

  TestVerification(
      createHeaders(jwt), "", false, Http::TestHeaderMapImpl{{":status", "401"}},
      Http::Sft::VerifyStatusToString(Http::Sft::VerifyStatus::JWT_VERIFY_FAIL_MALFORMED));
}

// Remove some random bytes from the payload block.
TEST_P(SFTVerificationFilterIntegrationTest, InvalidJWTMalformedPayload) {
  const std::string jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVlZmRmODc5LWM5NDEtNDcwMS1iZDVkLWYzNTdiZmY3"
                          "Nzk4ZCJ9."
                          "eyJhdWQiOlsiYXVkMiJdLCJXQiOjEuNTEwOTg5NTYxZSswOSwiaXNzIjoiaXNzMSIsImp0"
                          "aSI6ImlkMiIsInN1YiI6InN1YjIifQ.HeXTyMXfUM7J_"
                          "reCkGI3OnbfXc7HbUpz98knlBmwu39CNHx90r4qUbe3KwpLl54P9UiF2PkfOfhUo0NlA6gYl"
                          "Q";

  TestVerification(
      createHeaders(jwt), "", false, Http::TestHeaderMapImpl{{":status", "401"}},
      Http::Sft::VerifyStatusToString(Http::Sft::VerifyStatus::JWT_VERIFY_FAIL_MALFORMED));
}

// Remove some random bytes from the signature block.
TEST_P(SFTVerificationFilterIntegrationTest, InvalidJWTMalformedSignature) {
  const std::string jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImVlZmRmODc5LWM5NDEtNDcwMS1iZDVkLWYzNTdiZmY3"
                          "Nzk4ZCJ9."
                          "eyJhdWQiOlsiYXVkMiJdLCJpYXQiOjEuNTEwOTg5NTYxZSswOSwiaXNzIjoiaXNzMSIsImp0"
                          "aSI6ImlkMiIsInN1YiI6InN1YjIifQ.HeXTyMXfUM7J_"
                          "reCkGI3OnbfXc7HbUpz98knlBmwu39CNHx90r4qUbe3KwpLl54P9UiF2PkfOfhUo0NlA6gY"
                          "l";

  TestVerification(
      createHeaders(jwt), "", false, Http::TestHeaderMapImpl{{":status", "401"}},
      Http::Sft::VerifyStatusToString(Http::Sft::VerifyStatus::JWT_VERIFY_FAIL_MALFORMED));
}

// A otherwise valid jwt signed with key we don't know about.
TEST_P(SFTVerificationFilterIntegrationTest, InvalidJWTKeyIDMismatch) {
  const std::string jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6IjZmOTBkZjI2LTYzMTctNDAzNi1iNThhLTYzNzJiOWJm"
                          "ZDJiNiJ9."
                          "eyJhdWQiOlsiYXVkMSJdLCJpYXQiOjEuNTEwOTg5NTYxZSswOSwiaXNzIjoiaXNzMSIsImp0"
                          "aSI6ImlkMSIsInN1YiI6InN1YjEifQ.KPlrw5HFx-MpFKi_I_"
                          "nABxnoCnjvnpQcHe1Dgo1jWLLwOCzseAHXK8CgaoqABGjQ715J0A1KLimC-MF6L6uf5g";

  TestVerification(
      createHeaders(jwt), "", false, Http::TestHeaderMapImpl{{":status", "401"}},
      Http::Sft::VerifyStatusToString(Http::Sft::VerifyStatus::JWT_VERIFY_FAIL_NO_VALIDATORS));
}

// Claims: Issuer mismatch.
TEST_P(SFTVerificationFilterIntegrationTest, InvalidJWTIssuerMismatch) {
  const std::string jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6Ijg0ZDJmZWQ4LWRlODktNGQyZC05NTI0LTE1NjYzZDgx"
                          "N2U3YSJ9."
                          "eyJhdWQiOlsiYXVkMSJdLCJpYXQiOjEuNTEwOTkxMjQzZSswOSwiaXNzIjoiaXNzMiIsImp0"
                          "aSI6ImlkMSIsInN1YiI6InN1YjEifQ.nft0WffH1gSnw8VSCTC8jODULP-"
                          "RzuROQIbQnSbaVQ3crANmIQ8ZQPC16dh-GEIbS1CpSk0onRf2bfY633lY_A";

  TestVerification(
      createHeaders(jwt), "", false, Http::TestHeaderMapImpl{{":status", "401"}},
      Http::Sft::VerifyStatusToString(Http::Sft::VerifyStatus::JWT_VERIFY_FAIL_ISSUER_MISMATCH));
}

// Claims: Audience mismatch.
TEST_P(SFTVerificationFilterIntegrationTest, InvalidJWTAudienceMismatch) {
  const std::string jwt = "eyJhbGciOiJFUzI1NiIsImtpZCI6Ijg0ZDJmZWQ4LWRlODktNGQyZC05NTI0LTE1NjYzZDgx"
                          "N2U3YSJ9."
                          "eyJhdWQiOlsiYXVkMyJdLCJpYXQiOjEuNTEwOTkxMjQzZSswOSwiaXNzIjoiaXNzMSIsImp0"
                          "aSI6ImlkMSIsInN1YiI6InN1YjEifQ."
                          "YKgTcekuNIEAOO95qYNKe5uMbH0fBoNYhdb8k8ssvBjyx7cfmc7xfMDcC6ppIgjf6sEmsOaO"
                          "4lFHL1Wma5A3Hw";

  TestVerification(
      createHeaders(jwt), "", false, Http::TestHeaderMapImpl{{":status", "401"}},
      Http::Sft::VerifyStatusToString(Http::Sft::VerifyStatus::JWT_VERIFY_FAIL_AUDIENCE_MISMATCH));
}

// TODO(morgabra) exp and nbf tests - need to figure out how to mock time.

} // namespace Envoy