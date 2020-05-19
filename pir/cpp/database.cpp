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

#include <iostream>

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

StatusOr<std::unique_ptr<PIRDatabase>> PIRDatabase::Create(
    const std::unique_ptr<PIRContext>& context,
    const std::vector<std::int64_t>& database) {
  db_type db(database.size());

  for (size_t idx = 0; idx < database.size(); ++idx) {
    try {
      context->Encoder()->encode(database[idx], db[idx]);
    } catch (std::exception& e) {
      return InvalidArgumentError(e.what());
    }
  }

  return absl::WrapUnique(
      new PIRDatabase(context->Evaluator(), db, database.size()));
}

StatusOr<std::vector<seal::Ciphertext>> PIRDatabase::multiply(
    const std::vector<seal::Ciphertext>& in) {
  std::vector<seal::Ciphertext> result(in.size());

  for (size_t idx = 0; idx < in.size(); ++idx) {
    seal::Ciphertext ct;
    try {
      evaluator_->multiply_plain(in[idx], db_[idx], ct);
    } catch (std::exception& e) {
      return InvalidArgumentError(e.what());
    }
    result[idx] = ct;
  }
  return result;
}
}  // namespace pir
