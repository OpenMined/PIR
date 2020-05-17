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
#include "server.h"

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

PIRServer::PIRServer(std::unique_ptr<PIRContext> context,
                     const seal::Plaintext& db)
    : context_(std::move(context)), db_(std::move(db)) {}

StatusOr<std::unique_ptr<PIRServer>> PIRServer::Create(
    const std::vector<std::uint64_t>& database) {
  auto context = PIRContext::Create(database.size());
  auto encoded = context->Encode(database);

  if (!encoded.ok()) {
    return encoded.status();
  }
  auto db = encoded.ValueOrDie();
  return absl::WrapUnique(new PIRServer(std::move(context), std::move(db)));
}

StatusOr<std::string> PIRServer::ProcessRequest(
    const std::string& request) const {
  auto deserialized = context_->Deserialize(request);

  if (!deserialized.ok()) {
    return deserialized.status();
  }

  auto ct = deserialized.ValueOrDie();
  try {
    context_->Evaluator()->multiply_plain_inplace(ct, db_);
  } catch (std::exception& e) {
    return InvalidArgumentError(e.what());
  }
  return context_->Serialize(ct);
}

StatusOr<std::string> PIRServer::Params() {
  return context_->SerializeParams();
}

}  // namespace pir
