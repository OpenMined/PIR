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

    if "com_tencent_rapidjson" not in native.existing_rules():
        http_archive(
            name = "com_tencent_rapidjson",
            build_file = "//third_party:rapidjson.BUILD",
            sha256 = "e6fc99c7df7f29995838a764dd68df87b71db360f7727ace467b21b82c85efda",
            strip_prefix = "rapidjson-8f4c021fa2f1e001d2376095928fc0532adf2ae6/include",
            url = "https://github.com/Tencent/rapidjson/archive/8f4c021fa2f1e001d2376095928fc0532adf2ae6.zip",
        )

    if "com_google_absl" not in native.existing_rules():
        http_archive(
            name = "com_google_absl",
            sha256 = "9ab2dbebf6f209d6680bd3088a837c07f0788852ab81700aef6e2f2a746a7acb",
            strip_prefix = "abseil-cpp-b35973e3e35cb1eccb086d6a549c253c49579474",
            url = "https://github.com/abseil/abseil-cpp/archive/b35973e3e35cb1eccb086d6a549c253c49579474.zip",
        )

    if "private_join_and_compute" not in native.existing_rules():
        http_archive(
            name = "private_join_and_compute",
            sha256 = "64be17ff362ff0338be49fe28658df73cc539c1b0f1d84b957d4a567097929ca",
            strip_prefix = "private-join-and-compute-eaec47fa64619e9a6467630663c7af70a4eadfcc",
            url = "https://github.com/google/private-join-and-compute/archive/eaec47fa64619e9a6467630663c7af70a4eadfcc.zip",
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
                "https://mirror.bazel.build/github.com/gflags/gflags/archive/v2.2.2.tar.gz",
                "https://github.com/gflags/gflags/archive/v2.2.2.tar.gz",
            ],
        )



    if "SEAL" not in native.existing_rules():
        http_archive(
            name = "com_microsoft_seal",
            sha256 = "9dfb1482d0bade6c1c76f2aa06aca6203f98aadc4ad94ca0f316be916b45fbd5",
            strip_prefix = "SEAL-3.5.1",
            build_file_content = """filegroup(name = "src", srcs = glob(["**"]), visibility = ["//visibility:public"])""",
            urls = ["https://github.com/microsoft/SEAL/archive/v3.5.1.tar.gz"],
        )

    rules_proto_dependencies()

    rules_proto_toolchains()

    rules_foreign_cc_dependencies()
