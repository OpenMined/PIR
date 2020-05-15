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
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

PIRClient::PIRClient(std::unique_ptr<PIRContext> context)
    : context_(std::move(context)) {}

StatusOr<std::unique_ptr<PIRClient>> PIRClient::Create() {
  auto context = PIRContext::Create().ValueOrDie();
  return absl::WrapUnique(new PIRClient(std::move(context)));
}

StatusOr<std::unique_ptr<PIRClient>> PIRClient::CreateFromParams(
    const std::string& params) {
  auto context = PIRContext::CreateFromParams(params).ValueOrDie();
  return absl::WrapUnique(new PIRClient(std::move(context)));
}

StatusOr<std::string> PIRClient::CreateRequest(std::size_t desiredIndex,
                                               std::size_t dbSize) const {
  if (desiredIndex >= dbSize) {
    return InvalidArgumentError("invalid index");
  }
  std::vector<std::uint64_t> request(dbSize, 0);
  request[desiredIndex] = 1;

  return context_->Encrypt(request);
}

StatusOr<std::vector<uint64_t>> PIRClient::ProcessResponse(
    const std::string& response) const {
  return context_->Decrypt(response);
}

}  // namespace pir
