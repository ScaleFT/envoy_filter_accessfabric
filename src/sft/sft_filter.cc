#include <string>

#include "sft_filter.h"

#include "common/common/logger.h"
#include "common/http/utility.h"
#include "server/config/network/http_connection_manager.h"

namespace Envoy {
namespace Http {

HttpSampleDecoderFilter::HttpSampleDecoderFilter(
    Http::Sft::SFTConfigSharedPtr config) {
  config_ = config;
}

HttpSampleDecoderFilter::~HttpSampleDecoderFilter() {}

void HttpSampleDecoderFilter::onDestroy() {}

void HttpSampleDecoderFilter::sendUnauthorized(std::string status) {
  Code code = Code(401);
  Utility::sendLocalReply(*decoder_callbacks_, false, code, status);
  return;
}

FilterHeadersStatus HttpSampleDecoderFilter::decodeHeaders(HeaderMap &headers,
                                                           bool) {
  const HeaderEntry *entry = headers.get(config_->headerKey);
  if (!entry) {
    sendUnauthorized("missing authorization header");
    return FilterHeadersStatus::StopIteration;
  }
  const HeaderString &value = entry->value();
  ENVOY_LOG(debug, "JWT: {}", value.c_str());

  Http::Sft::Jwt jwt = Http::Sft::Jwt(value.c_str());
  ENVOY_LOG(debug, "HEADER: {}", jwt.Header()->asJsonString());
  ENVOY_LOG(debug, "PAYLOAD: {}", jwt.Payload()->asJsonString());

  const std::string kid = jwt.Header()->getString("kid", "");
  if (kid == "") {
    sendUnauthorized("jwt header missing 'kid'");
    return FilterHeadersStatus::StopIteration;
  }

  const Http::Sft::JWKS jwks = config_->jwks();
  std::shared_ptr<Http::Sft::evp_pkey> pkey = jwks.get(kid);
  if (!pkey) {
    sendUnauthorized("missing public key");
    return FilterHeadersStatus::StopIteration;
  }

  if (!jwt.VerifySignature(pkey)) {
    sendUnauthorized("signature verification failed");
    return FilterHeadersStatus::StopIteration;
  }

  return FilterHeadersStatus::Continue;
}

FilterDataStatus HttpSampleDecoderFilter::decodeData(Buffer::Instance &, bool) {
  return FilterDataStatus::Continue;
}

FilterTrailersStatus HttpSampleDecoderFilter::decodeTrailers(HeaderMap &) {
  return FilterTrailersStatus::Continue;
}

void HttpSampleDecoderFilter::setDecoderFilterCallbacks(
    StreamDecoderFilterCallbacks &callbacks) {
  decoder_callbacks_ = &callbacks;
}

} // namespace Http
} // namespace Envoy
