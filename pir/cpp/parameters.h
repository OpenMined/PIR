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

#include <vector>

#include "absl/memory/memory.h"
#include "pir/proto/payload.pb.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::std::optional;
using ::std::size_t;
using ::std::vector;

using ::seal::EncryptionParameters;
using ::seal::Modulus;

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

constexpr uint32_t DEFAULT_POLY_MODULUS_DEGREE = 4096;

HEParameters generateHEParams(
    std::optional<uint32_t> poly_mod_opt = {},
    std::optional<Modulus> plain_mod_opt = {},
    std::optional<std::vector<Modulus>> coeff_opt = {},
    std::optional<seal::scheme_type> scheme = {});

seal::EncryptionParameters generateEncryptionParams(const HEParameters& params);

class PIRParameters {
 public:
  /**
   * Creates a new PIR Parameters container.
   * @param[in] Database size
   * @param[in] Number of dimensions in database representation.
   * @param[in] SEAL Paramenters
   */
  static std::shared_ptr<PIRParameters> Create(
      size_t dbsize, size_t dimensions = 1,
      HEParameters sealParams = generateHEParams()) {
    return absl::WrapUnique(new PIRParameters(
        dbsize, calculate_dimensions(dbsize, dimensions), sealParams));
  }

  /**
   * Returns the database size.
   */
  size_t DBSize() const { return parameters_.database_size(); }

  /**
   * Returns a vector with the size of each dimension of the multi-dimensional
   * representation of the database.
   */
  vector<uint32_t> Dimensions() const {
    return std::vector<uint32_t>(parameters_.dimensions().begin(),
                                 parameters_.dimensions().end());
  }

  /**
   * Returns the encryption parameters.
   */
  EncryptionParameters GetEncryptionParams() const {
    return generateEncryptionParams(parameters_.he_parameters());
  }

  PIRParameters() = delete;

  /**
   * Helper function to calculate the dimensions for representing a database of
   * db_size elements as a hypercube with num_dimensions dimensions.
   * @param[in] db_size Number of elements in the database
   * @param[in] num_dimensions Number of dimensions
   * @returns vector of dimension sizes
   */
  static std::vector<uint32_t> calculate_dimensions(uint32_t db_size,
                                                    uint32_t num_dimensions);

 private:
  PIRParameters(size_t dbsize, const vector<uint32_t>& dimensions,
                HEParameters heParams) {
    parameters_.set_database_size(dbsize);
    *parameters_.mutable_he_parameters() = heParams;
    for (auto& dim : dimensions) parameters_.add_dimensions(dim);
  }

  Parameters parameters_;
};

}  // namespace pir

#endif  // PIR_PARAMETERS_H_
