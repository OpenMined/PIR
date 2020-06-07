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
#include "pir/cpp/parameters.h"

#include "pir/cpp/database.h"
#include "pir/cpp/serialization.h"
#include "pir/cpp/utils.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;
using seal::EncryptionParameters;

EncryptionParameters GenerateEncryptionParams(
    std::optional<uint32_t> poly_mod_opt, std::optional<Modulus> plain_mod_opt,
    std::optional<std::vector<Modulus>> coeff_opt) {
  auto poly_modulus_degree = poly_mod_opt.value_or(DEFAULT_POLY_MODULUS_DEGREE);
  auto plain_modulus = plain_mod_opt.value_or(
      seal::PlainModulus::Batching(poly_modulus_degree, 20));
  auto coeff =
      coeff_opt.value_or(seal::CoeffModulus::BFVDefault(poly_modulus_degree));

  EncryptionParameters parms(seal::scheme_type::BFV);
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_plain_modulus(plain_modulus);
  parms.set_coeff_modulus(coeff);
  return parms;
}

StatusOr<EncryptionParameters> GenerateEncryptionParams(
    const PIRParameters& params) {
  return SEALDeserialize<EncryptionParameters>(params.he_parameters());
}

StatusOr<PIRParameters> CreatePIRParameters(size_t dbsize, size_t dimensions,
                                            EncryptionParameters heParams) {
  PIRParameters parameters;
  parameters.set_database_size(dbsize);

  RETURN_IF_ERROR(SEALSerialize<EncryptionParameters>(
      heParams, parameters.mutable_he_parameters()));

  for (auto& dim : PIRDatabase::calculate_dimensions(dbsize, dimensions))
    parameters.add_dimensions(dim);

  return parameters;
}

}  // namespace pir
