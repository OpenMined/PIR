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

PIR_DEFAULT_LINKOPTS = [
    "-lrt",
]

cc_test(
    name = "seal_test",
    srcs = ["seal_test.cpp"],
    linkopts = PIR_DEFAULT_LINKOPTS,
    includes = [".", "com_microsoft_seal/include/SEAL-3.5/"],
    deps = [
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        ":com_microsoft_seal",
    ],
   copts = ["-pthread", "-std=c++17", "-D_GLIBCXX_USE_CXX11_ABI=1", "-fPIC"],
)

cmake_external(
   name = "com_microsoft_seal",
   cmake_options = [
        "-DSEAL_USE_MSGSL=OFF",
        "-DSEAL_USE_ZLIB=OFF",
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
