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

#ifndef PIR_PARAMETERS_H_
#define PIR_PARAMETERS_H_

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::std::optional;
using ::std::size_t;

using ::seal::EncryptionParameters;
using ::seal::Modulus;

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

StatusOr<std::string> serializeEncryptionParams(
    const seal::EncryptionParameters& parms);
StatusOr<seal::EncryptionParameters> deserializeEncryptionParams(
    const std::string& input);

seal::EncryptionParameters generateEncryptionParams(
    std::optional<uint32_t> poly_mod_opt = {},
    std::optional<Modulus> plain_mod_opt = {},
    std::optional<std::vector<Modulus>> coeff_opt = {},
    std::optional<seal::scheme_type> scheme = {});

class PIRParameters {
 public:
  /**
   * Creates a new PIR Parameters container.
   * @param[in] Database size
   * @param[in] SEAL Paramenters
   **/
  static std::shared_ptr<PIRParameters> Create(
      size_t dbsize,
      seal::EncryptionParameters sealParams = generateEncryptionParams()) {
    return absl::WrapUnique(new PIRParameters(dbsize, sealParams));
  }
  /**
   * Returns the database size.
   **/
  size_t DBSize() const { return database_size_; }

  /**
   * Returns the encryption parameters.
   **/
  const EncryptionParameters& GetEncryptionParams() const { return parms_; }

  PIRParameters() = delete;

 private:
  PIRParameters(size_t dbsize, seal::EncryptionParameters sealParams)
      : database_size_(dbsize), parms_(sealParams) {}

  // Database parameters
  size_t database_size_;

  // Encryption parameters&helpers
  EncryptionParameters parms_;
};

}  // namespace pir

#endif  // PIR_PARAMETERS_H_
