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

class PIRContext {
 public:
  static StatusOr<std::unique_ptr<PIRContext>> Create();

  std::string SerializeParams() const;
  void DeserializeParams(const std::string& input);

  StatusOr<std::string> Encrypt(const std::vector<uint64_t>&);
  StatusOr<std::vector<uint64_t>> Decrypt(const std::string& in);
  std::string PublicKey();

 private:
  PIRContext(const seal::EncryptionParameters&);

  static seal::EncryptionParameters generateEncryptionParams(
      uint32_t poly_modulus_degree = 4096, uint32_t plain_modulus = 1032193);

  seal::EncryptionParameters parms_;

  std::shared_ptr<seal::SEALContext> context_;
  std::shared_ptr<seal::PublicKey> public_key_;
  std::optional<std::shared_ptr<seal::SecretKey>> secret_key_;
  std::shared_ptr<seal::BatchEncoder> encoder_;
  std::shared_ptr<seal::Encryptor> encryptor_;
  std::shared_ptr<seal::Decryptor> decryptor_;
};

}  // namespace pir

#endif  // PIR_CONTEXT_H_
