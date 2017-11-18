#include <string>

#include "sft_filter.h"

#include "common/common/logger.h"
#include "common/http/utility.h"
#include "server/config/network/http_connection_manager.h"

namespace Envoy {
namespace Http {

SftJwtDecoderFilter::SftJwtDecoderFilter(Http::Sft::SFTConfigSharedPtr config) {
  config_ = config;
}

SftJwtDecoderFilter::~SftJwtDecoderFilter() {}

void SftJwtDecoderFilter::onDestroy() {}

void SftJwtDecoderFilter::sendUnauthorized(std::string status) {
  ENVOY_LOG(debug, "SftJwtDecoderFilter::{}: Unauthorized : {}", __func__,
            status);
  Code code = Code(401);
  Utility::sendLocalReply(*decoder_callbacks_, false, code, status);
  return;
}

FilterHeadersStatus SftJwtDecoderFilter::decodeHeaders(HeaderMap &headers,
                                                       bool) {
  const HeaderEntry *entry = headers.get(config_->headerKey);
  if (!entry) {
    sendUnauthorized("jwt missing header");
    return FilterHeadersStatus::StopIteration;
  }
  const HeaderString &value = entry->value();

  Http::Sft::Jwt jwt = Http::Sft::Jwt(value.c_str());

  if (!jwt.IsParsed()) {
    sendUnauthorized("jwt malformed");
    return FilterHeadersStatus::StopIteration;
  }

  // TODO(morgabra) Move claim validation elsewhere
  // Validate issuer (iss)
  std::string issuer = jwt.Payload()->getString("iss", "");
  if (issuer == "") {
    sendUnauthorized("jwt missing issuer ('iss')");
    return FilterHeadersStatus::StopIteration;
  }
  if (config_->allowed_issuer_ != issuer) {
    sendUnauthorized("jwt issuer ('iss') is not allowed");
    return FilterHeadersStatus::StopIteration;
  }

  // Validate audience (aud) - can be an array or string.
  std::vector<std::string> audience =
      jwt.Payload()->getStringArray("aud", true);
  if (audience.size() == 0) {
    std::string aud = jwt.Payload()->getString("aud", "");
    if (aud == "") {
      sendUnauthorized("jwt missing audience ('aud')");
      return FilterHeadersStatus::StopIteration;
    }
    audience.push_back(aud);
  }

  bool aud_found = false;
  for (auto &allowed : config_->allowed_audiences_) {
    if (std::find(audience.begin(), audience.end(), allowed) !=
        audience.end()) {
      aud_found = true;
    }
    if (aud_found) {
      break;
    }
  }

  if (!aud_found) {
    sendUnauthorized("jwt audience ('aud') is not allowed");
    return FilterHeadersStatus::StopIteration;
  }

  // Verify expiration/not-before (exp/nbf)
  auto now = std::chrono::duration_cast<std::chrono::seconds>(
                 std::chrono::system_clock::now().time_since_epoch())
                 .count();

  if (jwt.Payload()->hasObject("nbf")) {
    int64_t nbf = jwt.Payload()->getInteger("nbf", -1);
    if (nbf < 0) {
      sendUnauthorized("jwt not-before ('nbf') missing or invalid");
      return FilterHeadersStatus::StopIteration;
    }

    if (now < nbf) {
      sendUnauthorized("jwt not-before ('nbf') validation failed");
      return FilterHeadersStatus::StopIteration;
    }
  }

  if (jwt.Payload()->hasObject("exp")) {
    int64_t exp = jwt.Payload()->getInteger("exp", -1);
    if (exp < 0) {
      sendUnauthorized("jwt expiration ('exp') missing or invalid");
      return FilterHeadersStatus::StopIteration;
    }

    if (now > exp) {
      sendUnauthorized("jwt expiration ('exp') validation failed");
      return FilterHeadersStatus::StopIteration;
    }
  }

  // Verify signature
  const std::string kid = jwt.Header()->getString("kid", "");
  if (kid == "") {
    sendUnauthorized("jwt header missing key id ('kid')");
    return FilterHeadersStatus::StopIteration;
  }

  const Http::Sft::JWKS jwks = config_->jwks();
  std::shared_ptr<Http::Sft::evp_pkey> pkey = jwks.get(kid);
  if (!pkey) {
    sendUnauthorized("jwt no public key found for given key id");
    return FilterHeadersStatus::StopIteration;
  }

  if (!jwt.VerifySignature(pkey)) {
    sendUnauthorized("jwt signature verification failed");
    return FilterHeadersStatus::StopIteration;
  }

  return FilterHeadersStatus::Continue;
}

FilterDataStatus SftJwtDecoderFilter::decodeData(Buffer::Instance &, bool) {
  return FilterDataStatus::Continue;
}

FilterTrailersStatus SftJwtDecoderFilter::decodeTrailers(HeaderMap &) {
  return FilterTrailersStatus::Continue;
}

void SftJwtDecoderFilter::setDecoderFilterCallbacks(
    StreamDecoderFilterCallbacks &callbacks) {
  decoder_callbacks_ = &callbacks;
}

}  // namespace Http
}  // namespace Envoy
