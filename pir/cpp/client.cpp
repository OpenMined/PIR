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
#include "client.h"

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

PIRClient::PIRClient(std::unique_ptr<PIRContext> context)
    : context_(std::move(context)) {
  auto sealctx = context_->SEALContext();
  seal::KeyGenerator keygen(sealctx);
  encryptor_ = std::make_shared<seal::Encryptor>(sealctx, keygen.public_key());
  decryptor_ = std::make_shared<seal::Decryptor>(sealctx, keygen.secret_key());

  encoder_ = context_->Encoder();
}

StatusOr<std::unique_ptr<PIRClient>> PIRClient::Create(
    std::shared_ptr<PIRParameters> params) {
  auto context = PIRContext::Create(params);
  if (!context.ok()) {
    return context.status();
  }
  return absl::WrapUnique(new PIRClient(std::move(context.ValueOrDie())));
}

StatusOr<std::string> PIRClient::CreateRequest(std::size_t index) const {
  if (index >= this->DBSize()) {
    return InvalidArgumentError("invalid index");
  }
  std::vector<std::int64_t> request(DBSize(), 0);
  request[index] = 1;

  return this->encrypt(request);
}

StatusOr<std::map<uint64_t, int64_t>> PIRClient::ProcessResponse(
    const std::string& response) const {
  auto decryptedRaw = this->decrypt(response);

  if (!decryptedRaw.ok()) {
    return decryptedRaw.status();
  }
  auto decrypted = decryptedRaw.ValueOrDie();
  std::map<uint64_t, int64_t> result;

  for (size_t idx = 0; idx < decrypted.size(); ++idx)
    if (decrypted[idx] != 0) {
      result[idx] = decrypted[idx];
    }
  return result;
}

StatusOr<std::string> PIRClient::serialize(
    const seal::Ciphertext& ciphertext) const {
  std::stringstream stream;

  try {
    ciphertext.save(stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return stream.str();
}

StatusOr<seal::Ciphertext> PIRClient::deserialize(const std::string& in) const {
  auto sealctx = context_->SEALContext();
  seal::Ciphertext ciphertext(sealctx);

  try {
    std::stringstream stream;
    stream << in;
    ciphertext.load(sealctx, stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return ciphertext;
}

StatusOr<std::string> PIRClient::encrypt(const std::vector<int64_t>& in) const {
  seal::Ciphertext ciphertext(context_->SEALContext());

  auto plaintext = encoder_->encode<seal::BatchEncoder>(in);

  if (!plaintext.ok()) {
    return plaintext.status();
  }

  try {
    encryptor_->encrypt(plaintext.ValueOrDie(), ciphertext);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return this->serialize(ciphertext);
}

StatusOr<std::vector<int64_t>> PIRClient::decrypt(const std::string& in) const {
  auto ciphertext = this->deserialize(in);
  if (!ciphertext.ok()) {
    return ciphertext.status();
  }
  seal::Plaintext plaintext;

  try {
    decryptor_->decrypt(ciphertext.ValueOrDie(), plaintext);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return encoder_->decode<seal::BatchEncoder, std::vector<int64_t>>(plaintext);
}

}  // namespace pir
