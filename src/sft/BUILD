package(default_visibility = ["//visibility:public"])

load(
    "@envoy//bazel:envoy_build_system.bzl",
    "envoy_cc_binary",
    "envoy_cc_library",
    "envoy_cc_test",
)

envoy_cc_library(
    name = "sft_jwt_lib",
    srcs = ["jwt.cc"],
    hdrs = ["jwt.h"],
    repository = "@envoy",
    deps = [
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "sft_config_lib",
    srcs = ["sft_config.cc"],
    hdrs = ["sft_config.h"],
    repository = "@envoy",
    deps = [
        "sft_jwt_lib",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "sft_filter_lib",
    srcs = ["sft_filter.cc"],
    hdrs = ["sft_filter.h"],
    repository = "@envoy",
    deps = [
        "sft_config_lib",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_library(
    name = "sft_filter_config",
    srcs = ["sft_filter_config.cc"],
    hdrs = ["sft_filter_config.h"],
    repository = "@envoy",
    deps = [
        ":sft_filter_lib",
        "@envoy//source/exe:envoy_common_lib",
    ],
)

envoy_cc_binary(
    name = "envoy",
    repository = "@envoy",
    deps = [
        ":sft_filter_config",
        "@envoy//source/exe:envoy_main_entry_lib",
    ],
)