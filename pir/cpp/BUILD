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

PIR_DEFAULT_COPTS =  ["-std=c++17"]

cc_library(
    name = "pir",
    srcs = ["client.cpp", "server.cpp", 
            "context.cpp", "context.h", 
            "parameters.h", "parameters.cpp",
            "payload.h", "payload.cpp",
            "database.cpp", "database.h",
            "utils.cpp", "utils.h",
            ],
    hdrs = ["client.h", "server.h"],
    includes = PIR_DEFAULT_INCLUDES,
    deps = [
        "@com_microsoft_seal//:seal",
        "@com_google_absl//absl/memory",
        "@private_join_and_compute//util:status",
        "@com_tencent_rapidjson//:rapidjson",
    ],
   copts = PIR_DEFAULT_COPTS,
)

cc_test(
    name = "pir_test",
    srcs = ["client_test.cpp", "server_test.cpp"],
    includes = PIR_DEFAULT_INCLUDES,
    deps = [
        ":pir",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    
    ],
   copts = PIR_DEFAULT_COPTS,
   linkstatic = True,
)
cc_binary(
    name = "benchmark",
    srcs = ["benchmark.cpp"],
    deps = [
        ":pir",
        "@com_google_benchmark//:benchmark_main",
    ],
    includes = PIR_DEFAULT_INCLUDES,
    copts = PIR_DEFAULT_COPTS,
    linkstatic = True,
)
