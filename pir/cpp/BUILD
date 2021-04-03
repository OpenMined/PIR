#
# Copyright 2020 the authors listed in CONTRIBUTORS.md
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package(default_visibility = ["//visibility:public"])

PIR_DEFAULT_INCLUDES = ["."]

PIR_DEFAULT_COPTS = ["-std=c++17"]

cc_library(
    name = "pir",
    srcs = [
        "client.cpp",
        "context.cpp",
        "context.h",
        "ct_reencoder.cpp",
        "ct_reencoder.h",
        "database.cpp",
        "database.h",
        "parameters.cpp",
        "parameters.h",
        "serialization.cpp",
        "serialization.h",
        "server.cpp",
        "string_encoder.cpp",
        "string_encoder.h",
        "utils.cpp",
        "utils.h",
        "status_asserts.h",
    ],
    hdrs = [
        "client.h",
        "server.h",
    ],
    copts = PIR_DEFAULT_COPTS,
    includes = PIR_DEFAULT_INCLUDES,
    deps = [
        "//pir/proto:payload_cc_proto",
        "@com_google_absl//absl/memory",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:optional",
        "@com_google_absl//absl/types:span",
        "@com_microsoft_seal//:seal",
    ],
)

cc_test(
    name = "pir_test",
    srcs = [
        "client_test.cpp",
        "correctness_test.cpp",
        "ct_reencoder_test.cpp",
        "database_test.cpp",
        "parameters_test.cpp",
        "serialization_test.cpp",
        "server_test.cpp",
        "status_asserts.h",
        "string_encoder_test.cpp",
        "test_base.cpp",
        "test_base.h",
        "utils_test.cpp",
    ],
    copts = PIR_DEFAULT_COPTS,
    includes = PIR_DEFAULT_INCLUDES,
    linkstatic = True,
    deps = [
        ":pir",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_binary(
    name = "benchmark",
    srcs = [
        "benchmark.cpp",
        "status_asserts.h",
        "test_base.cpp",
        "test_base.h",
    ],
    copts = PIR_DEFAULT_COPTS,
    includes = PIR_DEFAULT_INCLUDES,
    linkstatic = True,
    deps = [
        ":pir",
        "@com_google_absl//absl/status:statusor",
        "@com_google_benchmark//:benchmark_main",
        "@com_google_googletest//:gtest",
    ],
)
