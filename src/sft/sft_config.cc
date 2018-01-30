#include "sft_config.h"

#include "common/filesystem/filesystem_impl.h"
#include "common/json/json_loader.h"
#include "envoy/json/json_object.h"
#include "common/http/message_impl.h"
#include "envoy/upstream/cluster_manager.h"
#include "common/http/utility.h"
#include "common/common/enum_to_int.h"

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

bool JWKS::add(const Json::ObjectSharedPtr jwk) {
  std::string kid = jwk->getString("kid", "");
  if (kid == "") {
    ENVOY_LOG(warn, "jwk missing required key `kid`");
    return false;
  }

  auto key = ParseECPublicKey(jwk);
  if (!key) {
    ENVOY_LOG(warn, "jwk parse error");
    return false;
  }

  ENVOY_LOG(debug, "parsed jwk {}", kid);
  keys_[kid] = key;
  return true;
}

SFTConfig::SFTConfig(const Json::Object& json_config, ThreadLocal::SlotAllocator& tls,
                     Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
                     Stats::Scope& scope, Runtime::RandomGenerator& random)
    : remote_cluster_name_(json_config.getString("jwks_api_cluster", "")), cm_(cm), random_(random),
      refresh_interval_(
          std::chrono::milliseconds(json_config.getInteger("jwks_refresh_delay_ms", 60000))),
      refresh_timer_(dispatcher.createTimer([this]() -> void { refresh(); })),
      stats_(generateStats("scaleft.accessfabric.", scope)), tls_(tls.allocateSlot()) {

  retry_count_ = int(0);

  allowed_issuer_ = json_config.getString("iss", "");
  if (allowed_issuer_ == "") {
    throw EnvoyException(fmt::format("invalid 'iss' '{}' in sft filter config", allowed_issuer_));
  }

  allowed_audiences_ = json_config.getStringArray("aud", false);
  whitelisted_paths_ = json_config.getStringArray("whitelisted_paths", true);

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

    // Start polling.
    refresh();
  }
} // namespace Sft

SFTConfig::~SFTConfig() {
  if (active_request_) {
    active_request_->cancel();
  }
}

SftStats SFTConfig::generateStats(const std::string& prefix, Stats::Scope& scope) {
  return {ALL_SFT_STATS(POOL_COUNTER_PREFIX(scope, prefix), POOL_GAUGE_PREFIX(scope, prefix))};
}

const JWKS& SFTConfig::jwks() { return tls_->getTyped<JWKS>(); }

bool SFTConfig::whitelistMatch(const Http::HeaderMap& headers) {
  const Http::HeaderString& path = headers.Path()->value();
  const char* query_string_start = Http::Utility::findQueryStringStart(path);
  size_t compare_length = path.size();
  if (query_string_start != nullptr) {
    compare_length = query_string_start - path.c_str();
  }
  for (auto& wl_path : whitelisted_paths_) {
    if (compare_length != wl_path.size()) {
      return false;
    }
    if (0 == strncasecmp(path.c_str(), wl_path.c_str(), compare_length)) {
      return true;
    }
  }
  return false;
}

void SFTConfig::refresh() {
  ENVOY_LOG(debug, "SFTConfig::{}", __func__);
  MessagePtr message(new RequestMessageImpl());
  message->headers().insertMethod().value().setReference(Http::Headers::get().MethodValues.Get);
  message->headers().insertPath().value(jwks_api_path_);
  message->headers().insertHost().value(remote_cluster_name_);
  active_request_ = cm_.httpAsyncClientForCluster(remote_cluster_name_)
                        .send(std::move(message), *this,
                              Optional<std::chrono::milliseconds>(std::chrono::milliseconds(5000)));
}

void SFTConfig::requestFailed(Http::AsyncClient::FailureReason) {
  ENVOY_LOG(debug, "SFTConfig::{} retry count: {}", __func__, retry_count_);
  stats().jwks_fetch_failed_.inc();

  if (retry_count_ < 30) {
    retry_count_++;
    requestComplete(std::chrono::milliseconds((retry_count_ * retry_count_) * 1000));
  } else {
    requestComplete(refresh_interval_); // Poll normally
  }
}

void SFTConfig::onFailure(Http::AsyncClient::FailureReason reason) {
  requestFailed(reason);
  return;
}

void SFTConfig::requestComplete(std::chrono::milliseconds interval) {
  ENVOY_LOG(debug, "SFTConfig::{}", __func__);
  active_request_ = nullptr;

  // Add refresh jitter based on the configured interval.
  std::chrono::milliseconds final_delay =
      interval + std::chrono::milliseconds(random_.random() % interval.count());

  ENVOY_LOG(debug, "SFTConfig::{} setting refresh timer: {} ms", __func__, final_delay.count());
  refresh_timer_->enableTimer(final_delay);
}

void SFTConfig::onSuccess(Http::MessagePtr&& response) {
  uint64_t response_code = Http::Utility::getResponseStatus(response->headers());
  if (response_code != enumToInt(Http::Code::OK)) {
    ENVOY_LOG(warn, "SFTConfig::{}: failed request: response {} != 200", __func__, response_code);
    requestFailed(Http::AsyncClient::FailureReason::Reset);
    return;
  }

  try {
    ENVOY_LOG(debug, "SFTConfig::{}: success: {}", __func__, response->bodyAsString());

    JWKSSharedPtr new_jwks(new JWKS());
    Json::ObjectSharedPtr loader = Json::Factory::loadFromString(response->bodyAsString());
    for (const Json::ObjectSharedPtr& jwk : loader->getObjectArray("keys")) {
      new_jwks->add(jwk);
    }

    tls_->set([new_jwks](Event::Dispatcher&) -> ThreadLocal::ThreadLocalObjectSharedPtr {
      return new_jwks;
    });

    retry_count_ = 0;
    stats().jwks_fetch_success_.inc();
    requestComplete(refresh_interval_);
    return;

  } catch (...) {
    ENVOY_LOG(warn, "SFTConfig::{}: failed request: parse failure", __func__);
    requestFailed(Http::AsyncClient::FailureReason::Reset);
    return;
  }
}

} // namespace Sft
} // namespace Http
} // namespace Envoy