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
#include "database.h"

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

StatusOr<std::unique_ptr<PIRDatabase>> PIRDatabase::Create(
    const std::unique_ptr<PIRContext>& context,
    const std::vector<std::uint64_t>& database) {
  auto encoded = context->Encode(database);

  if (!encoded.ok()) {
    return encoded.status();
  }
  auto db = encoded.ValueOrDie();
  return absl::WrapUnique(new PIRDatabase(db, database.size()));
}

StatusOr<seal::Ciphertext> PIRDatabase::multiply(
    const std::shared_ptr<seal::Evaluator>& eval, const seal::Ciphertext& in) {
  seal::Ciphertext out;
  try {
    eval->multiply_plain(in, db_, out);
  } catch (std::exception& e) {
    return InvalidArgumentError(e.what());
  }
  return out;
}
}  // namespace pir
