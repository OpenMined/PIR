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

#ifndef PIR_CONTEXT_H_
#define PIR_CONTEXT_H_

#include "absl/status/statusor.h"
#include "pir/cpp/parameters.h"
#include "seal/seal.h"

namespace pir {

using absl::StatusOr;

using ::std::optional;
using ::std::shared_ptr;
using ::std::string;
using ::std::vector;

using seal::EncryptionParameters;

class PIRContext {
 public:
  /**
   * Creates a new context
   * @param[in] params PIR parameters
   * @returns InvalidArgument if the SEAL parameter deserialization fails
   **/
  static StatusOr<std::unique_ptr<PIRContext>> Create(
      shared_ptr<PIRParameters> /*params*/);
  /**
   * Returns an Evaluator instance.
   **/
  std::shared_ptr<seal::Evaluator>& Evaluator() { return evaluator_; }
  /**
   * Returns the SEAL context.
   **/
  std::shared_ptr<seal::SEALContext>& SEALContext() { return context_; }
  /**
   * Returns the PIR parameters protobuffer.
   **/
  shared_ptr<PIRParameters> Params() { return parameters_; }
  /**
   * Returns the dimensions sum.
   **/
  size_t DimensionsSum() {
    return std::accumulate(Params()->dimensions().begin(),
                           Params()->dimensions().end(), 0);
  }
  /**
   * Returns the encryption parameters used to create SEAL context.
   **/
  const EncryptionParameters& EncryptionParams() { return encryption_params_; }

  /**
   * Returns the encoder
   **/
  std::shared_ptr<seal::IntegerEncoder>& Encoder() { return encoder_; }

 private:
  PIRContext(shared_ptr<PIRParameters> /*params*/,
             const EncryptionParameters& /*enc_params*/,
             shared_ptr<seal::SEALContext> /*seal_context*/);

  shared_ptr<PIRParameters> parameters_;
  EncryptionParameters encryption_params_;
  shared_ptr<seal::SEALContext> context_;
  shared_ptr<seal::Evaluator> evaluator_;
  shared_ptr<seal::IntegerEncoder> encoder_;
};

}  // namespace pir

#endif  // PIR_CONTEXT_H_
