//
// Copyright 2020 the authors listed in CONTRIBUTORS.md
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#include "client.h"

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;

PIRClient::PIRClient(std::unique_ptr<PIRContext> context)
    : context_(std::move(context)) {}

StatusOr<std::unique_ptr<PIRClient>> PIRClient::Create() {
  auto context = PIRContext::Create().ValueOrDie();
  return absl::WrapUnique(new PIRClient(std::move(context)));
}

StatusOr<std::string> PIRClient::CreateRequest(uint64_t index) const {
  return {};
}

StatusOr<std::string> PIRClient::ProcessResponse(
    const std::string &response) const {
  return {};
}

}  // namespace pir
