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
load("@rules_foreign_cc//tools/build_defs:cmake.bzl", "cmake_external")

PIR_DEFAULT_INCLUDES = [".", "com_microsoft_seal/include/SEAL-3.5/"]
PIR_DEFAULT_COPTS =  ["-std=c++17"]

cc_library(
    name = "pir_context",
    srcs = ["context.cpp"],
    hdrs = ["context.h"],
    includes = PIR_DEFAULT_INCLUDES,
    deps = [
        ":com_microsoft_seal",
        "@com_google_absl//absl/memory",
        "@private_join_and_compute//util:status",
    ],
   copts = PIR_DEFAULT_COPTS,
)

cc_library(
    name = "pir_client",
    srcs = ["client.cpp"],
    hdrs = ["client.h"],
    includes = PIR_DEFAULT_INCLUDES,
    deps = [
        ":pir_context",
        "@com_google_absl//absl/memory",
        "@private_join_and_compute//util:status",
    ],
   copts = PIR_DEFAULT_COPTS,
)

cc_test(
    name = "pir_client_test",
    srcs = ["client_test.cpp"],
    includes = PIR_DEFAULT_INCLUDES,
    deps = [
        ":pir_client",
        ":pir_context",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    
    ],
   copts = PIR_DEFAULT_COPTS,
)

cc_library(
    name = "pir_server",
    srcs = ["server.cpp"],
    hdrs = ["server.h"],
    includes = PIR_DEFAULT_INCLUDES,
    deps = [
        ":pir_context",
        "@com_google_absl//absl/memory",
        "@private_join_and_compute//util:status",
    ],
   copts = PIR_DEFAULT_COPTS,
)

cc_test(
    name = "pir_server_test",
    srcs = ["server_test.cpp"],
    includes = PIR_DEFAULT_INCLUDES,
    deps = [
        ":pir_server",
        ":pir_client",
        ":pir_context",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    
    ],
   copts = PIR_DEFAULT_COPTS,
)


cc_test(
    name = "seal_test",
    srcs = ["seal_test.cpp"],
    includes = PIR_DEFAULT_INCLUDES,
    deps = [
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        ":com_microsoft_seal",
    ],
   copts = PIR_DEFAULT_COPTS,
)


cmake_external(
   name = "com_microsoft_seal",
   cmake_options = [
        "-DSEAL_USE_MSGSL=OFF",
        "-DSEAL_USE_ZLIB=OFF",
        "-DCMAKE_CXX_STANDARD=17",
   ],
   cache_entries = {
        "MAKE_INSTALL_PREFIX": "$EXT_BUILD_DEPS/seal",
        "SEAL_LIB_BUILD_TYPE": "Static_PIC",
   },
   lib_source = "@com_microsoft_seal//:src",
   install_prefix = "native/src",
   static_libraries = ["libseal-3.5.a"],
   visibility = ["//visibility:public"],
)
