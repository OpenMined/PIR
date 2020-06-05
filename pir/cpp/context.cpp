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
#include "pir/cpp/context.h"

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

PIRContext::PIRContext(const Parameters& params) : parameters_(params) {
  auto encryptionParams = GenerateEncryptionParams(params.he_parameters());
  context_ = seal::SEALContext::Create(encryptionParams);

  encoder_ = std::make_shared<seal::IntegerEncoder>(this->context_);
  evaluator_ = std::make_shared<seal::Evaluator>(context_);
}

StatusOr<std::unique_ptr<PIRContext>> PIRContext::Create(
    const Parameters& param) {
  return absl::WrapUnique(new PIRContext(param));
}

}  // namespace pir
