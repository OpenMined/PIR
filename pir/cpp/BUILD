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

PSI_CARDINALITY_DEFAULT_LINKOPTS = [
    # Needed on some Linux systems. See also
    # https://github.com/google/cctz/issues/47
    # https://github.com/tensorflow/tensorflow/issues/15129
    "-lrt",
]

cc_test(
    name = "seal_test",
    srcs = ["seal_test.cpp"],
    linkopts = PSI_CARDINALITY_DEFAULT_LINKOPTS,
    deps = [
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
    ],
)
