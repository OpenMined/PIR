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
#include "context.h"

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"
#include "utils.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

PIRContext::PIRContext(std::shared_ptr<PIRParameters> params)
    : parameters_(params),
      context_(seal::SEALContext::Create(params->GetEncryptionParams())) {
  encoder_ = std::make_shared<EncoderFactory>(context_);
  evaluator_ = std::make_shared<seal::Evaluator>(context_);
}

StatusOr<std::unique_ptr<PIRContext>> PIRContext::Create(
    std::shared_ptr<PIRParameters> param) {
  return absl::WrapUnique(new PIRContext(param));
}

StatusOr<std::string> PIRContext::Serialize(
    const seal::Ciphertext& ciphertext) {
  std::stringstream stream;

  try {
    ciphertext.save(stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return stream.str();
}

StatusOr<seal::Ciphertext> PIRContext::Deserialize(const std::string& in) {
  seal::Ciphertext ciphertext(context_);

  try {
    std::stringstream stream;
    stream << in;
    ciphertext.load(context_, stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return ciphertext;
}

StatusOr<std::string> PIRContext::Encrypt(const std::vector<int64_t>& in) {
  seal::Ciphertext ciphertext(context_);

  auto plaintext = encoder_->encode<seal::BatchEncoder>(in);

  if (!plaintext.ok()) {
    return plaintext.status();
  }

  /*try {
    encryptor_->encrypt(plaintext.ValueOrDie(), ciphertext);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }*/

  return Serialize(ciphertext);
}

StatusOr<std::vector<int64_t>> PIRContext::Decrypt(const std::string& in) {
  // if (!decryptor_.has_value()) {
  //  return InvalidArgumentError("public context");
  //}
  auto ciphertext = Deserialize(in);
  if (!ciphertext.ok()) {
    return ciphertext.status();
  }
  seal::Plaintext plaintext;

  /*try {
    decryptor_.value()->decrypt(ciphertext.ValueOrDie(), plaintext);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }*/

  return encoder_->decode<seal::BatchEncoder, std::vector<int64_t>>(plaintext);
}

}  // namespace pir
