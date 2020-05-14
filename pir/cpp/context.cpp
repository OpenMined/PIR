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

PIRContext::PIRContext(const seal::EncryptionParameters& parms)
    : parms_(parms), context_(seal::SEALContext::Create(parms)) {
  seal::KeyGenerator keygen(this->context_);
  this->public_key_ = std::make_shared<seal::PublicKey>(keygen.public_key());
  this->secret_key_ = std::make_shared<seal::SecretKey>(keygen.secret_key());
  this->encoder_ = std::make_shared<seal::BatchEncoder>(this->context_);

  this->encryptor_ =
      std::make_shared<seal::Encryptor>(this->context_, *this->public_key_);
  this->decryptor_ = std::make_shared<seal::Decryptor>(
      this->context_, *this->secret_key_.value());
}

StatusOr<std::unique_ptr<PIRContext>> PIRContext::Create() {
  auto parms = generateEncryptionParams();

  return absl::WrapUnique(new PIRContext(parms));
}

StatusOr<std::string> PIRContext::Encrypt(const std::vector<uint64_t>& in) {
  seal::Ciphertext ciphertext(this->context_);
  seal::Plaintext plaintext;

  this->encoder_->encode(in, plaintext);
  this->encryptor_->encrypt(plaintext, ciphertext);

  std::stringstream stream;
  ciphertext.save(stream);
  return stream.str();
}

StatusOr<std::vector<uint64_t>> PIRContext::Decrypt(const std::string& in) {
  seal::Ciphertext ciphertext(this->context_);
  seal::Plaintext plaintext;

  std::stringstream stream;
  stream << in;
  ciphertext.load(this->context_, stream);

  this->decryptor_->decrypt(ciphertext, plaintext);

  std::vector<uint64_t> result;
  this->encoder_->decode(plaintext, result);

  return result;
}

std::string PIRContext::SerializeParams() const {
  std::stringstream stream;
  parms_.save(stream);
  return stream.str();
}

void PIRContext::DeserializeParams(const std::string& input) {
  std::stringstream stream;
  stream << input;
  parms_.load(stream);
  context_ = seal::SEALContext::Create(parms_);
}

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
