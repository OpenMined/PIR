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

PIRContext::PIRContext(const PIRParameters& params, bool is_public)
    : parameters_(params),
      context_(seal::SEALContext::Create(params.UnsafeGetEncryptionParams())) {
  seal::KeyGenerator keygen(context_);
  encoder_ = std::make_shared<seal::BatchEncoder>(context_);

  encryptor_ = std::make_shared<seal::Encryptor>(context_, keygen.public_key());
  evaluator_ = std::make_shared<seal::Evaluator>(context_);

  if (is_public) return;

  decryptor_ = std::make_shared<seal::Decryptor>(context_, keygen.secret_key());
}

StatusOr<std::unique_ptr<PIRContext>> PIRContext::Create(PIRParameters param,
                                                         bool is_public) {
  if (!param.HasEncryptionParams()) {
    param.GetEncryptionParams() = generateEncryptionParams();
  }
  return absl::WrapUnique(new PIRContext(param, is_public));
}

StatusOr<seal::Plaintext> PIRContext::Encode(const std::vector<uint64_t>& in) {
  seal::Plaintext plaintext;

  try {
    encoder_->encode(in, plaintext);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return plaintext;
}

StatusOr<std::vector<uint64_t>> PIRContext::Decode(const seal::Plaintext& in) {
  std::vector<uint64_t> result;

  try {
    encoder_->decode(in, result);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return result;
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

StatusOr<std::string> PIRContext::Encrypt(const std::vector<uint64_t>& in) {
  seal::Ciphertext ciphertext(context_);

  auto plaintext = Encode(in);

  if (!plaintext.ok()) {
    return plaintext.status();
  }

  try {
    encryptor_->encrypt(plaintext.ValueOrDie(), ciphertext);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return Serialize(ciphertext);
}

StatusOr<std::vector<uint64_t>> PIRContext::Decrypt(const std::string& in) {
  if (!decryptor_.has_value()) {
    return InvalidArgumentError("public context");
  }
  auto ciphertext = Deserialize(in);
  if (!ciphertext.ok()) {
    return ciphertext.status();
  }
  seal::Plaintext plaintext;

  try {
    decryptor_.value()->decrypt(ciphertext.ValueOrDie(), plaintext);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return Decode(plaintext);
}

std::shared_ptr<seal::Evaluator>& PIRContext::Evaluator() { return evaluator_; }
}  // namespace pir
