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
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;

std::string serializeParams(const seal::EncryptionParameters& parms) {
  std::stringstream stream;
  parms.save(stream);
  return stream.str();
}

seal::EncryptionParameters deserializeParams(const std::string& input) {
  seal::EncryptionParameters parms;

  std::stringstream stream;
  stream << input;
  parms.load(stream);

  return parms;
}

PIRContext::PIRContext(const seal::EncryptionParameters& parms)
    : parms_(parms), context_(seal::SEALContext::Create(parms)) {
  seal::KeyGenerator keygen(context_);
  public_key_ = std::make_shared<seal::PublicKey>(keygen.public_key());
  secret_key_ = std::make_shared<seal::SecretKey>(keygen.secret_key());
  encoder_ = std::make_shared<seal::BatchEncoder>(context_);

  encryptor_ = std::make_shared<seal::Encryptor>(context_, *public_key_);
  decryptor_ =
      std::make_shared<seal::Decryptor>(context_, *secret_key_.value());

  evaluator_ = std::make_shared<seal::Evaluator>(context_);
}

StatusOr<std::unique_ptr<PIRContext>> PIRContext::Create() {
  auto parms = generateEncryptionParams();

  return absl::WrapUnique(new PIRContext(parms));
}

StatusOr<std::unique_ptr<PIRContext>> PIRContext::CreateFromParams(
    const std::string& parmsStr) {
  return absl::WrapUnique(new PIRContext(deserializeParams(parmsStr)));
}

StatusOr<seal::Plaintext> PIRContext::Encode(const std::vector<uint64_t>& in) {
  seal::Plaintext plaintext;
  encoder_->encode(in, plaintext);
  return plaintext;
}

StatusOr<std::vector<uint64_t>> PIRContext::Decode(const seal::Plaintext& in) {
  std::vector<uint64_t> result;
  encoder_->decode(in, result);
  return result;
}

StatusOr<std::string> PIRContext::Serialize(
    const seal::Ciphertext& ciphertext) {
  std::stringstream stream;
  ciphertext.save(stream);
  return stream.str();
}

StatusOr<seal::Ciphertext> PIRContext::Deserialize(const std::string& in) {
  seal::Ciphertext ciphertext(context_);

  std::stringstream stream;
  stream << in;
  ciphertext.load(context_, stream);

  return ciphertext;
}

StatusOr<std::string> PIRContext::Encrypt(const std::vector<uint64_t>& in) {
  seal::Ciphertext ciphertext(context_);

  auto plaintext = Encode(in).ValueOrDie();

  encryptor_->encrypt(plaintext, ciphertext);

  return Serialize(ciphertext);
}

StatusOr<std::vector<uint64_t>> PIRContext::Decrypt(const std::string& in) {
  seal::Ciphertext ciphertext = Deserialize(in).ValueOrDie();
  seal::Plaintext plaintext;

  decryptor_->decrypt(ciphertext, plaintext);

  return Decode(plaintext);
}

std::string PIRContext::SerializeParams() const {
  return serializeParams(parms_);
}

std::shared_ptr<seal::Evaluator>& PIRContext::Evaluator() { return evaluator_; }

seal::EncryptionParameters PIRContext::generateEncryptionParams(
    uint32_t poly_modulus_degree /*= 4096*/,
    uint32_t plain_modulus /*= 1032193*/) {
  seal::EncryptionParameters parms(seal::scheme_type::BFV);
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_plain_modulus(plain_modulus);
  auto coeff = seal::CoeffModulus::BFVDefault(poly_modulus_degree);
  parms.set_coeff_modulus(coeff);

  return parms;
}
}  // namespace pir
