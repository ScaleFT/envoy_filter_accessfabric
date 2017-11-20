#pragma once

#include "sft_config.h"

#include "common/common/logger.h"
#include "server/config/network/http_connection_manager.h"

#include <string>

namespace Envoy {
namespace Http {

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
  void sendUnauthorized(std::string status);
  StreamDecoderFilterCallbacks* decoder_callbacks_;
  Http::Sft::SFTConfigSharedPtr config_;
};

} // namespace Http
} // namespace Envoy