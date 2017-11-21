#include <string>

#include "sft_filter.h"

#include "common/common/logger.h"
#include "common/http/utility.h"
#include "server/config/network/http_connection_manager.h"

namespace Envoy {
namespace Http {
namespace Sft {

std::string VerifyStatusToString(VerifyStatus status) {
  static std::map<VerifyStatus, std::string> table = {
      {VerifyStatus::JWT_VERIFY_SUCCESS, "JWT_VERIFY_SUCCESS"},
      {VerifyStatus::JWT_VERIFY_FAIL_UNKNOWN, "JWT_VERIFY_FAIL_UNKNOWN"},
      {VerifyStatus::JWT_VERIFY_FAIL_NOT_PRESENT, "JWT_VERIFY_FAIL_NOT_PRESENT"},
      {VerifyStatus::JWT_VERIFY_FAIL_EXPIRED, "JWT_VERIFY_FAIL_EXPIRED"},
      {VerifyStatus::JWT_VERIFY_FAIL_NOT_BEFORE, "JWT_VERIFY_FAIL_NOT_BEFORE"},
      {VerifyStatus::JWT_VERIFY_FAIL_INVALID_SIGNATURE, "JWT_VERIFY_FAIL_INVALID_SIGNATURE"},
      {VerifyStatus::JWT_VERIFY_FAIL_NO_VALIDATORS, "JWT_VERIFY_FAIL_NO_VALIDATORS"},
      {VerifyStatus::JWT_VERIFY_FAIL_MALFORMED, "JWT_VERIFY_FAIL_MALFORMED"},
      {VerifyStatus::JWT_VERIFY_FAIL_ISSUER_MISMATCH, "JWT_VERIFY_FAIL_ISSUER_MISMATCH"},
      {VerifyStatus::JWT_VERIFY_FAIL_AUDIENCE_MISMATCH, "JWT_VERIFY_FAIL_AUDIENCE_MISMATCH"}};
  return table[status];
}

SftJwtDecoderFilter::SftJwtDecoderFilter(Http::Sft::SFTConfigSharedPtr config) { config_ = config; }

SftJwtDecoderFilter::~SftJwtDecoderFilter() {}

void SftJwtDecoderFilter::sendUnauthorized(VerifyStatus status) {
  std::string statusStr = VerifyStatusToString(status);
  ENVOY_LOG(debug, "SftJwtDecoderFilter::{}: Unauthorized : {}", __func__, statusStr);
  Code code = Code(401);
  Utility::sendLocalReply(*decoder_callbacks_, false, code, statusStr);
  return;
}

VerifyStatus SftJwtDecoderFilter::verify(HeaderMap& headers) {
  ENVOY_LOG(debug, "SftJwtDecoderFilter::{}", __func__);

  // Check if header key/jwt exists.
  const HeaderEntry* entry = headers.get(config_->headerKey);
  if (!entry) {
    return VerifyStatus::JWT_VERIFY_FAIL_NOT_PRESENT;
  }

  // Check if jwt can be parsed.
  Http::Sft::Jwt jwt = Http::Sft::Jwt(entry->value().c_str());

  if (!jwt.IsParsed()) {
    return VerifyStatus::JWT_VERIFY_FAIL_MALFORMED;
  }

  // TODO(morgabra) Move claim validation elsewhere
  // Validate issuer (iss)
  std::string issuer = jwt.Payload()->getString("iss", "");
  if (issuer == "") {
    return VerifyStatus::JWT_VERIFY_FAIL_ISSUER_MISMATCH;
  }
  if (config_->allowed_issuer_ != issuer) {
    return VerifyStatus::JWT_VERIFY_FAIL_ISSUER_MISMATCH;
  }

  // Validate audience (aud) - can be an array or string.
  std::vector<std::string> audience = jwt.Payload()->getStringArray("aud", true);
  if (audience.size() == 0) {
    std::string aud = jwt.Payload()->getString("aud", "");
    if (aud == "") {
      return VerifyStatus::JWT_VERIFY_FAIL_AUDIENCE_MISMATCH;
    }
    audience.push_back(aud);
  }

  bool aud_found = false;
  for (auto& allowed : config_->allowed_audiences_) {
    if (std::find(audience.begin(), audience.end(), allowed) != audience.end()) {
      aud_found = true;
    }
    if (aud_found) {
      break;
    }
  }

  if (!aud_found) {
    return VerifyStatus::JWT_VERIFY_FAIL_AUDIENCE_MISMATCH;
  }

  // Verify expiration/not-before (exp/nbf)
  auto now = std::chrono::duration_cast<std::chrono::seconds>(
                 ProdSystemTimeSource::instance_.currentTime().time_since_epoch())
                 .count();

  if (jwt.Payload()->hasObject("nbf")) {
    int64_t nbf = jwt.Payload()->getInteger("nbf", -1);
    if (nbf < 0) {
      return VerifyStatus::JWT_VERIFY_FAIL_NOT_BEFORE;
    }

    if (now < nbf) {
      return VerifyStatus::JWT_VERIFY_FAIL_NOT_BEFORE;
    }
  }

  if (jwt.Payload()->hasObject("exp")) {
    int64_t exp = jwt.Payload()->getInteger("exp", -1);
    if (exp < 0) {
      return VerifyStatus::JWT_VERIFY_FAIL_EXPIRED;
    }

    if (now > exp) {
      return VerifyStatus::JWT_VERIFY_FAIL_EXPIRED;
    }
  }

  // Verify signature
  const std::string kid = jwt.Header()->getString("kid", "");
  if (kid == "") {
    return VerifyStatus::JWT_VERIFY_FAIL_NO_VALIDATORS;
  }

  const Http::Sft::JWKS jwks = config_->jwks();
  std::shared_ptr<Http::Sft::evp_pkey> pkey = jwks.get(kid);
  if (!pkey) {
    return VerifyStatus::JWT_VERIFY_FAIL_NO_VALIDATORS;
  }

  if (!jwt.VerifySignature(pkey)) {
    return VerifyStatus::JWT_VERIFY_FAIL_INVALID_SIGNATURE;
  }

  return VerifyStatus::JWT_VERIFY_SUCCESS;
}

FilterHeadersStatus SftJwtDecoderFilter::decodeHeaders(HeaderMap& headers, bool) {
  VerifyStatus status = verify(headers);
  if (status != VerifyStatus::JWT_VERIFY_SUCCESS) {
    sendUnauthorized(status);
    return FilterHeadersStatus::StopIteration;
  }
  return FilterHeadersStatus::Continue;
}

FilterDataStatus SftJwtDecoderFilter::decodeData(Buffer::Instance&, bool) {
  return FilterDataStatus::Continue;
}

FilterTrailersStatus SftJwtDecoderFilter::decodeTrailers(HeaderMap&) {
  return FilterTrailersStatus::Continue;
}

void SftJwtDecoderFilter::setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) {
  decoder_callbacks_ = &callbacks;
}

void SftJwtDecoderFilter::onDestroy() {}

} // namespace Sft
} // namespace Http
} // namespace Envoy
