#pragma once

#include <string>

#include "envoy/server/filter_config.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for http dynamodb filter.
 */
class HttpSampleDecoderFilterConfig : public NamedHttpFilterConfigFactory {
 public:
  HttpFilterFactoryCb createFilterFactory(const Json::Object &,
                                          const std::string &stat_prefix,
                                          FactoryContext &context) override;
  std::string name() override { return "sft"; }
};

}  // namespace Configuration
}  // namespace Server
}  // namespace Envoy