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

std::shared_ptr<evp_pkey> JWKS::get(const std::string &kid) const {
  auto it = keys_.find(kid);
  if (it != keys_.end()) {
    return it->second;
  }
  return nullptr;
}

SFTConfig::SFTConfig(const Json::Object &json_config,
                     ThreadLocal::SlotAllocator &tls,
                     Upstream::ClusterManager &cm,
                     Event::Dispatcher &dispatcher,
                     Runtime::RandomGenerator &random)
    : RestApiFetcher(cm, json_config.getString("jwks_api_cluster"), dispatcher,
                     random,
                     std::chrono::milliseconds(json_config.getInteger(
                         "jwks_refresh_delay_ms", 60000))),
      tls_(tls.allocateSlot()) {
  if (!cm.get(remote_cluster_name_)) {
    throw EnvoyException(fmt::format(
        "unknown cluster '{}' in sft filter config", remote_cluster_name_));
  }

  // TODO(morgabra) This is copied from a filter in Envoy - What does this do?
  // Presumably this is globally shared memory, so all threads get to use the
  // same jwks set. This appears to be the case, but need to read code/verify.
  JWKSSharedPtr empty(new JWKS());
  tls_->set(
      [empty](Event::Dispatcher &) -> ThreadLocal::ThreadLocalObjectSharedPtr {
        return empty;
      });

  allowed_issuer_ = json_config.getString("iss", "");
  if (allowed_issuer_ == "") {
    throw EnvoyException(fmt::format("invalid 'iss' '{}' in sft filter config",
                                     allowed_issuer_));
  }

  allowed_audiences_ = json_config.getStringArray("aud", false);

  jwks_api_path_ = json_config.getString("jwks_api_path");
  if (jwks_api_path_ == "") {
    throw EnvoyException(
        fmt::format("empty 'jwks_api_path' in sft jwt auth config"));
  }

  // Start RestAPIFetcher loop.
  initialize();
}

const JWKS &SFTConfig::jwks() { return tls_->getTyped<JWKS>(); }

void SFTConfig::parseResponse(const Http::Message &message) {
  ENVOY_LOG(debug, "SFTConfig::{}: {}", __func__, message.bodyAsString());

  JWKSSharedPtr new_jwks(new JWKS());
  Json::ObjectSharedPtr loader =
      Json::Factory::loadFromString(message.bodyAsString());
  for (const Json::ObjectSharedPtr &jwk : loader->getObjectArray("keys")) {
    new_jwks->add(jwk);
  }

  tls_->set(
      [new_jwks](Event::Dispatcher &)
          -> ThreadLocal::ThreadLocalObjectSharedPtr { return new_jwks; });
}

void SFTConfig::onFetchFailure(const EnvoyException *e) {
  ENVOY_LOG(warn, "SFTConfig::{}: {}", __func__,
            e != nullptr ? e->what() : "fetch failure");
}

void SFTConfig::createRequest(Http::Message &request) {
  ENVOY_LOG(debug, "SFTConfig::{}: {}", __func__, jwks_api_path_);

  request.headers().insertMethod().value().setReference(
      Http::Headers::get().MethodValues.Get);
  request.headers().insertPath().value(jwks_api_path_);
}

}  // namespace Sft
}  // namespace Http
}  // namespace Envoy