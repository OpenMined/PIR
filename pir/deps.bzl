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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")
load("@rules_foreign_cc//:workspace_definitions.bzl", "rules_foreign_cc_dependencies")

def pir_deps():
    if "com_google_googletest" not in native.existing_rules():
        http_archive(
            name = "com_google_googletest",
            sha256 = "94c634d499558a76fa649edb13721dce6e98fb1e7018dfaeba3cd7a083945e91",
            strip_prefix = "googletest-release-1.10.0",
            url = "https://github.com/google/googletest/archive/release-1.10.0.zip",
        )

    if "com_google_benchmark" not in native.existing_rules():
        http_archive(
            name = "com_google_benchmark",
            sha256 = "a9d41abe1bd45a707d39fdfd46c01b92e340923bc5972c0b54a48002a9a7cfa3",
            strip_prefix = "benchmark-8cead007830bdbe94b7cc259e873179d0ef84da6",
            url = "https://github.com/google/benchmark/archive/8cead007830bdbe94b7cc259e873179d0ef84da6.zip",
        )

    if "com_google_absl" not in native.existing_rules():
        http_archive(
            name = "com_google_absl",
            sha256 = "d29785bb94deaba45946d40bde5b356c66a4eb76505de0181ea9a23c46bc5ed4",
            strip_prefix = "abseil-cpp-592924480acf034aec0454160492a20bccdbdf3e",
            url = "https://github.com/abseil/abseil-cpp/archive/592924480acf034aec0454160492a20bccdbdf3e.zip",
        )

    if "com_github_glog_glog" not in native.existing_rules():
        http_archive(
            name = "com_github_glog_glog",
            sha256 = "ec64c82f3c2cd5be25d18f52bcca2840c1b29cf3d109cd61149935838645817b",
            strip_prefix = "glog-381e349a5bc3fd858a84b80c48ac465ad79c4a71",
            urls = ["https://github.com/schoppmp/glog/archive/381e349a5bc3fd858a84b80c48ac465ad79c4a71.zip"],
        )

    if "com_github_gflags_gflags" not in native.existing_rules():
        http_archive(
            name = "com_github_gflags_gflags",
            sha256 = "34af2f15cf7367513b352bdcd2493ab14ce43692d2dcd9dfc499492966c64dcf",
            strip_prefix = "gflags-2.2.2",
            urls = [
                "https://github.com/gflags/gflags/archive/v2.2.2.tar.gz",
            ],
        )

    if "com_microsoft_seal" not in native.existing_rules():
        http_archive(
            name = "com_microsoft_seal",
            build_file = "//third_party:seal.BUILD",
            sha256 = "13674a39a48c0d1c6ff544521cf10ee539ce1af75c02bfbe093f7621869e3406",
            strip_prefix = "SEAL-3.5.6",
            urls = ["https://github.com/microsoft/SEAL/archive/v3.5.6.tar.gz"],
        )

    rules_proto_dependencies()

    rules_proto_toolchains()

    rules_foreign_cc_dependencies()
