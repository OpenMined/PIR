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
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

def pir_preload():
    if "rules_proto" not in native.existing_rules():
        ver = "f7a30f6f80006b591fa7c437fe5a951eb10bcbcf"
        http_archive(
            name = "rules_proto",
            sha256 = "9fc210a34f0f9e7cc31598d109b5d069ef44911a82f507d5a88716db171615a8",
            strip_prefix = "rules_proto-" + ver,
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/rules_proto/archive/" + ver + ".tar.gz",
                "https://github.com/bazelbuild/rules_proto/archive/" + ver + ".tar.gz",
            ],
        )

    if "rules_foreign_cc" not in native.existing_rules():
        git_repository(
            name = "rules_foreign_cc",
            remote = "https://github.com/bazelbuild/rules_foreign_cc",
            init_submodules = True,
            commit="d54c78ab86b40770ee19f0949db9d74a831ab9f0",
            )
