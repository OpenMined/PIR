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
using ::std::shared_ptr;
using ::std::size_t;
using ::std::vector;

using ::seal::EncryptionParameters;
using ::seal::Modulus;

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

constexpr uint32_t DEFAULT_POLY_MODULUS_DEGREE = 4096;

/*
 * Helper function to generate encryption parameters.
 * @param[in] optional The polynomial modulus degree
 * @param[in] optional The plaintext modulus
 * @param[in] optional The coefficient modulus
 * */
EncryptionParameters GenerateEncryptionParams(
    optional<uint32_t> poly_mod_opt = {}, optional<Modulus> plain_mod_opt = {},
    optional<std::vector<Modulus>> coeff_opt = {});
/*
 * Helper function to create the PIRParameters
 * @param[in] the database size
 * @param[in] the encryption parameters
 * @param[in] the database dimensions
 * @returns InvalidArgument if EncryptionParameters serialization fails.
 * */
StatusOr<std::shared_ptr<PIRParameters>> CreatePIRParameters(
    size_t dbsize, size_t dimensions = 1,
    EncryptionParameters enc_params = GenerateEncryptionParams());
}  // namespace pir

#endif  // PIR_PARAMETERS_H_
