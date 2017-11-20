#include "sft_config.h"

#include "common/filesystem/filesystem_impl.h"
#include "common/json/json_loader.h"
#include "envoy/json/json_object.h"
#include "envoy/upstream/cluster_manager.h"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace Envoy {
namespace Http {
namespace Sft {

std::shared_ptr<evp_pkey> JWKS::get(const std::string& kid) const {
  auto it = keys_.find(kid);
  if (it != keys_.end()) {
    return it->second;
  }
  return nullptr;
}

SFTConfig::SFTConfig(const Json::Object& json_config, ThreadLocal::SlotAllocator& tls,
                     Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
                     Runtime::RandomGenerator& random)
    : RestApiFetcher(
          cm, json_config.getString("jwks_api_cluster", ""), dispatcher, random,
          std::chrono::milliseconds(json_config.getInteger("jwks_refresh_delay_ms", 60000))),
      tls_(tls.allocateSlot()) {
  allowed_issuer_ = json_config.getString("iss", "");
  if (allowed_issuer_ == "") {
    throw EnvoyException(fmt::format("invalid 'iss' '{}' in sft filter config", allowed_issuer_));
  }

  allowed_audiences_ = json_config.getStringArray("aud", false);

  JWKSSharedPtr empty(new JWKS());

  // Check if we have any static keys, if any fail to parse bail out.
  std::vector<Json::ObjectSharedPtr> static_keys_ = json_config.getObjectArray("keys", true);
  if (static_keys_.size() != 0) {
    ENVOY_LOG(debug, "SFTConfig::{}: Using statically configued jwks", __func__);
    for (auto& key : static_keys_) {
      if (!empty->add(key)) {
        throw EnvoyException(fmt::format("invalid static key in config"));
      }
    }
  }

  tls_->set(
      [empty](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr { return empty; });

  // If we don't have any statically configured keys, ensure we can fetch them.
  if (static_keys_.size() == 0) {
    ENVOY_LOG(debug, "SFTConfig::{}: Using jwks from upstream", __func__);
    if (!cm.get(remote_cluster_name_)) {
      throw EnvoyException(
          fmt::format("unknown cluster '{}' in sft filter config", remote_cluster_name_));
    }
    jwks_api_path_ = json_config.getString("jwks_api_path", "");
    if (jwks_api_path_ == "") {
      throw EnvoyException(fmt::format("empty 'jwks_api_path' in sft jwt auth config"));
    }
    // Start RestApiFetcher.
    initialize();
  }
}

const JWKS& SFTConfig::jwks() { return tls_->getTyped<JWKS>(); }

void SFTConfig::parseResponse(const Http::Message& message) {
  ENVOY_LOG(debug, "SFTConfig::{}: {}", __func__, message.bodyAsString());

  JWKSSharedPtr new_jwks(new JWKS());
  Json::ObjectSharedPtr loader = Json::Factory::loadFromString(message.bodyAsString());
  for (const Json::ObjectSharedPtr& jwk : loader->getObjectArray("keys")) {
    new_jwks->add(jwk);
  }

  tls_->set([new_jwks](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
    return new_jwks;
  });
}

void SFTConfig::onFetchFailure(const EnvoyException* e) {
  ENVOY_LOG(warn, "SFTConfig::{}: {}", __func__, e != nullptr ? e->what() : "fetch failure");
}

void SFTConfig::createRequest(Http::Message& request) {
  ENVOY_LOG(debug, "SFTConfig::{}: {}", __func__, jwks_api_path_);

  request.headers().insertMethod().value().setReference(Http::Headers::get().MethodValues.Get);
  request.headers().insertPath().value(jwks_api_path_);
}

} // namespace Sft
} // namespace Http
} // namespace Envoy