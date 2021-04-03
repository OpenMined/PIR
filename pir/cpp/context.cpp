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

#include "pir/cpp/serialization.h"
#include "pir/cpp/status_asserts.h"
#include "seal/seal.h"

namespace pir {

using absl::InternalError;
using absl::InvalidArgumentError;
using absl::StatusOr;
using seal::EncryptionParameters;

PIRContext::PIRContext(shared_ptr<PIRParameters> params,
                       const EncryptionParameters& enc_params,
                       shared_ptr<seal::SEALContext> context)
    : parameters_(params), encryption_params_(enc_params), context_(context) {
  encoder_ = std::make_shared<seal::IntegerEncoder>(this->context_);
  evaluator_ = std::make_shared<seal::Evaluator>(context_);
}

StatusOr<std::unique_ptr<PIRContext>> PIRContext::Create(
    shared_ptr<PIRParameters> params) {
  ASSIGN_OR_RETURN(auto enc_params, SEALDeserialize<EncryptionParameters>(
                                        params->encryption_parameters()));

  try {
    auto context = seal::SEALContext::Create(enc_params);
    return absl::WrapUnique(new PIRContext(params, enc_params, context));
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return InternalError("this should never happen");
}

}  // namespace pir
