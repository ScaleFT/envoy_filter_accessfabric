#pragma once

#include "sft_config.h"

#include "common/common/logger.h"
#include "server/config/network/http_connection_manager.h"

#include <string>

namespace Envoy {
namespace Http {
namespace Sft {

enum class VerifyStatus {
  WHITELISTED_PATH,
  JWT_VERIFY_SUCCESS,
  JWT_VERIFY_FAIL_UNKNOWN,
  JWT_VERIFY_FAIL_NOT_PRESENT,
  JWT_VERIFY_FAIL_EXPIRED,
  JWT_VERIFY_FAIL_NOT_BEFORE,
  JWT_VERIFY_FAIL_INVALID_SIGNATURE,
  JWT_VERIFY_FAIL_NO_VALIDATORS,
  JWT_VERIFY_FAIL_MALFORMED,
  JWT_VERIFY_FAIL_ISSUER_MISMATCH,
  JWT_VERIFY_FAIL_AUDIENCE_MISMATCH
};

std::string VerifyStatusToString(VerifyStatus status);

class SftJwtDecoderFilter : public StreamDecoderFilter, public Logger::Loggable<Logger::Id::http> {
public:
  SftJwtDecoderFilter(Http::Sft::SFTConfigSharedPtr config);
  ~SftJwtDecoderFilter();

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  FilterHeadersStatus decodeHeaders(HeaderMap& headers, bool) override;
  FilterDataStatus decodeData(Buffer::Instance&, bool) override;
  FilterTrailersStatus decodeTrailers(HeaderMap&) override;
  void setDecoderFilterCallbacks(StreamDecoderFilterCallbacks& callbacks) override;

private:
  StreamDecoderFilterCallbacks* decoder_callbacks_;
  Http::Sft::SFTConfigSharedPtr config_;

  // helpers
  void sendUnauthorized(VerifyStatus status);
  VerifyStatus verify(HeaderMap& headers);
};

} // namespace Sft
} // namespace Http
} // namespace Envoy