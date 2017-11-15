#include <string>

#include "sft_config.h"
#include "sft_filter.h"
#include "sft_filter_config.h"

#include "envoy/registry/registry.h"

namespace Envoy {
namespace Server {
namespace Configuration {

HttpFilterFactoryCb SftJwtDecoderFilterConfig::createFilterFactory(
    const Json::Object &json_config, const std::string &,
    FactoryContext &context) {
  Http::Sft::SFTConfigSharedPtr config(new Http::Sft::SFTConfig(
      json_config, context.threadLocal(), context.clusterManager(),
      context.dispatcher(), context.random()));

  return [config](Http::FilterChainFactoryCallbacks &callbacks) -> void {
    callbacks.addStreamDecoderFilter(Http::StreamDecoderFilterSharedPtr{
        new Http::SftJwtDecoderFilter(config)});
  };
};

static Registry::RegisterFactory<SftJwtDecoderFilterConfig,
                                 NamedHttpFilterConfigFactory>
    register_;

}  // namespace Configuration
}  // namespace Server
}  // namespace Envoy
