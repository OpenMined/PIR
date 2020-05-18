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

#include "seal/seal.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;

constexpr uint32_t DEFAULT_POLY_MODULUS_DEGREE = 4096;

class PIRParameters {
 public:
  PIRParameters(std::size_t dbsize,
                std::optional<seal::EncryptionParameters> parms = {})
      : database_size_(dbsize), parms_(parms) {}

  std::size_t GetDatabaseSize() const { return database_size_; }

  bool HasEncryptionParams() const { return parms_.has_value(); }
  std::optional<seal::EncryptionParameters>& GetEncryptionParams() {
    return parms_;
  }

  seal::EncryptionParameters UnsafeGetEncryptionParams() const {
    return parms_.value();
  }

 private:
  // Database parameters
  std::size_t database_size_;

  // Encryption parameters&helpers
  std::optional<seal::EncryptionParameters> parms_;
};

class PIRContext {
 public:
  /**
   * Creates a new context
   * @param[in] params PIR parameters
   * @returns InvalidArgument if the SEAL parameter deserialization fails
   **/
  static StatusOr<std::unique_ptr<PIRContext>> Create(PIRParameters /*params*/,
                                                      bool /*is_public*/);

  /**
   * Encodes a vector to a Plaintext
   * @param[in] in Array to be encoded
   * @returns InvalidArgument if the SEAL encoding fails
   **/
  StatusOr<seal::Plaintext> Encode(const std::vector<uint64_t>& in);
  /**
   * Decodes a plaintext to a vector
   * @param[in] in Plaintext to be decoded
   * @returns InvalidArgument if the SEAL decoding fails
   **/
  StatusOr<std::vector<uint64_t>> Decode(const seal::Plaintext& in);

  /**
   * Encodes, encrypts and serializes a vector
   * @param[in] in Vector to be encrypted
   * @returns InvalidArgument if the SEAL encryption fails
   **/
  StatusOr<std::string> Encrypt(const std::vector<uint64_t>& in);

  /**
   * Deserializes, decrypts and decodes a vector
   * @param[in] in Serialized ciphertext
   * @returns InvalidArgument if the SEAL decryption fails
   **/
  StatusOr<std::vector<uint64_t>> Decrypt(const std::string& in);

  /**
   * Serializes a ciphertext
   * @param[in] in Ciphertext to be serialized
   * @returns InvalidArgument if the context serialization fails
   **/
  StatusOr<std::string> Serialize(const seal::Ciphertext&);
  /**
   * Deserializes a ciphertext
   * @param[in] in Serialized ciphertext
   * @returns InvalidArgument if the context deserialization fails
   **/
  StatusOr<seal::Ciphertext> Deserialize(const std::string& in);

  /**
   * Returns an Evaluator instance
   **/
  std::shared_ptr<seal::Evaluator>& Evaluator();

  /**
   * Returns the PIR parameters
   **/
  const PIRParameters& Parameters() const { return parameters_; }

 private:
  PIRContext(const PIRParameters& /*params*/, bool /*is_public*/);

  PIRParameters parameters_;

  std::shared_ptr<seal::SEALContext> context_;
  std::shared_ptr<seal::BatchEncoder> encoder_;
  std::shared_ptr<seal::Encryptor> encryptor_;
  std::shared_ptr<seal::Evaluator> evaluator_;

  std::optional<std::shared_ptr<seal::Decryptor>> decryptor_ = {};
};

}  // namespace pir

#endif  // PIR_CONTEXT_H_
