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
#include "payload.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/status_macros.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

PIRServer::PIRServer(std::unique_ptr<PIRContext> context,
                     std::unique_ptr<PIRDatabase> db)
    : context_(std::move(context)), db_(std::move(db)) {}

StatusOr<std::unique_ptr<PIRServer>> PIRServer::Create(
    const std::unique_ptr<RawDatabase>& rawdb,
    std::optional<std::shared_ptr<PIRParameters>> optparams) {
  auto params = optparams.value_or(PIRParameters::Create(rawdb->size()));

  if (params->DBSize() != rawdb->size()) {
    return InvalidArgumentError("database size mismatch");
  }

  ASSIGN_OR_RETURN(auto context, PIRContext::Create(params));
  ASSIGN_OR_RETURN(auto db, rawdb->Encode(context));

  return absl::WrapUnique(new PIRServer(std::move(context), std::move(db)));
}

StatusOr<PIRPayload> PIRServer::ProcessRequest(
    const PIRPayload& payload) const {
  ASSIGN_OR_RETURN(auto result,
                   db_->multiply(context_->Evaluator(), payload.Get()));

  return PIRPayload::Load(result);
}

}  // namespace pir
