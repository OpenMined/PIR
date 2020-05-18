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
#include "server.h"

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "seal/util/polyarithsmallmod.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

PIRServer::PIRServer(std::unique_ptr<PIRContext> context,
                     std::unique_ptr<PIRDatabase> db)
    : context_(std::move(context)), db_(std::move(db)) {}

StatusOr<std::unique_ptr<PIRServer>> PIRServer::Create(
    const std::vector<std::uint64_t>& database) {
  auto params = PIRParameters(database.size());

  auto rawctx = PIRContext::Create(params, /*is_public=*/true);
  if (!rawctx.ok()) {
    return rawctx.status();
  }
  auto context = std::move(rawctx.ValueOrDie());

  auto rawdb = PIRDatabase::Create(context, database);
  if (!rawdb.ok()) {
    return rawdb.status();
  }
  auto db = std::move(rawdb.ValueOrDie());

  return absl::WrapUnique(new PIRServer(std::move(context), std::move(db)));
}

StatusOr<std::string> PIRServer::ProcessRequest(
    const std::string& request) const {
  auto deserialized = context_->Deserialize(request);

  if (!deserialized.ok()) {
    return deserialized.status();
  }

  auto ct = deserialized.ValueOrDie();

  auto out = db_->multiply(context_->Evaluator(), ct);
  if (!out.ok()) {
    return out.status();
  }
  return context_->Serialize(out.ValueOrDie());
}

void PIRServer::substitute_power_x_inplace(seal::Ciphertext& ct, uint32_t power,
                                           const seal::GaloisKeys& gal_keys) {
  context_->Evaluator()->apply_galois_inplace(ct, power, gal_keys);
}

void PIRServer::multiply_power_of_X(const seal::Ciphertext& encrypted, int k,
                                    seal::Ciphertext& destination) {
  // This has to get the actual params from the SEALContext. Using just the
  // params from PIR doesn't work.
  const auto& params = context_->SealContext()->first_context_data()->parms();
  auto poly_modulus_degree = params.poly_modulus_degree();

  auto coeff_mod_count = params.coeff_modulus().size();
  auto coeff_count = poly_modulus_degree;
  auto encrypted_count = encrypted.size();

  uint32_t index = (k >= 0) ? k : (poly_modulus_degree * 2 + k);

  // First copy over.
  destination = encrypted;

  // Prepare for destination
  // Multiply X^index for each ciphertext polynomial
  for (int i = 0; i < encrypted_count; i++) {
    for (int j = 0; j < coeff_mod_count; j++) {
      seal::util::negacyclic_shift_poly_coeffmod(
          encrypted.data(i) + (j * coeff_count), coeff_count, index,
          params.coeff_modulus()[j], destination.data(i) + (j * coeff_count));
    }
  }
}

std::vector<seal::Ciphertext> PIRServer::oblivious_expansion(
    const seal::Ciphertext& ct, const size_t num_items,
    const seal::GaloisKeys gal_keys) {
  auto poly_modulus_degree =
      context_->Parameters().UnsafeGetEncryptionParams().poly_modulus_degree();
  size_t logm = ceil(log2(num_items));
  std::vector<seal::Ciphertext> results(1 << logm);
  results[0] = ct;

  for (size_t j = 0; j < logm; ++j) {
    const size_t two_power_j = (1 << j);
    for (size_t k = 0; k < two_power_j; ++k) {
      auto c0 = results[k];
      seal::Ciphertext c1;
      // TODO: not sure which is faster: substitution operator, or multiply by
      // factor of x? We can do one of them only once depending on order.
      multiply_power_of_X(c0, -two_power_j, c1);

      results[k] = c0;
      substitute_power_x_inplace(c0, (poly_modulus_degree >> j) + 1, gal_keys);
      context_->Evaluator()->add_inplace(results[k], c0);

      results[k + two_power_j] = c1;
      substitute_power_x_inplace(c1, (poly_modulus_degree >> j) + 1, gal_keys);
      context_->Evaluator()->add_inplace(results[k + two_power_j], c1);
    }
  }
  results.resize(num_items);
  return results;
}

}  // namespace pir
