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
#include "database.h"

#include <iostream>

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/status_macros.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InternalError;
using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

StatusOr<std::shared_ptr<PIRDatabase>> PIRDatabase::Create(
    const raw_db_type& rawdb, std::shared_ptr<PIRParameters> params) {
  db_type db(rawdb.size());
  ASSIGN_OR_RETURN(auto context, PIRContext::Create(params));

  for (size_t idx = 0; idx < rawdb.size(); ++idx) {
    try {
      context->Encoder()->encode(rawdb[idx], db[idx]);
    } catch (std::exception& e) {
      return InvalidArgumentError(e.what());
    }
  }
  return std::make_shared<PIRDatabase>(db, std::move(context));
}

using seal::Ciphertext;
using seal::Evaluator;
using seal::Plaintext;
using std::vector;

// Recursive function to do the dot product of each dimension.
// Calls itself to move down dimensions until you get to the bottom dimension.
// Bottom dimension just does a dot product with the DB, and returns the result.
// Upper levels then take those results, and dot product again with the
// selection vector, until you get back to the top.
// NB: the database iterator is passed by reference so we keep track of where
// we are in the database. Be very careful with that iterator!
Ciphertext multiply_dims(
    Evaluator& evaluator, vector<uint32_t> dimensions,
    vector<Ciphertext>::const_iterator selection_vector_it,
    const vector<Ciphertext>::const_iterator selection_vector_end,
    vector<Plaintext>::const_iterator& database_it,
    const std::vector<Plaintext>::const_iterator database_end, size_t depth) {
  const size_t this_dimension = dimensions[0];
  auto remaining_dimensions = vector(dimensions.begin() + 1, dimensions.end());

  string depth_string(depth, ' ');

  Ciphertext result;
  bool first_pass = true;
  for (size_t i = 0; i < this_dimension; ++i) {
    // std::cout << depth_string << "i = " << i << std::endl;
    // make sure we don't go past end of DB
    if (database_it == database_end) break;
    Ciphertext temp_ct;
    if (remaining_dimensions.empty()) {
      // base case: have to multiply against DB
      // std::cout << depth_string << "Base case multiplication" << std::endl;
      evaluator.multiply_plain(*(selection_vector_it + i), *(database_it++),
                               temp_ct);

    } else {
      temp_ct = multiply_dims(
          evaluator, remaining_dimensions, selection_vector_it + this_dimension,
          selection_vector_end, database_it, database_end, depth + 1);

      // std::cout << depth_string << "Multiplying by selection vector" <<
      // std::endl;
      evaluator.multiply_inplace(temp_ct, *(selection_vector_it + i));
      // TODO: relinearize after multiply?
    }

    if (first_pass) {
      result = temp_ct;
      first_pass = false;
    } else {
      // std::cout << depth_string << "Summing" << std::endl;
      evaluator.add_inplace(result, temp_ct);
    }
  }
  // if (first_pass) std::cout << "Still on first pass!" << std::endl;
  // std::cout << depth_string << "Finished" << std::endl;
  return result;
}

StatusOr<Ciphertext> PIRDatabase::multiply(
    const vector<Ciphertext>& selection_vector) const {
  auto dimensions = context_->Parameters()->Dimensions();
  const size_t dim_sum = std::accumulate(dimensions.begin(), dimensions.end(),
                                         decltype(dimensions)::value_type(0));

  if (selection_vector.size() != dim_sum) {
    return InvalidArgumentError(
        "Selection vector size does not match dimensions");
  }

  auto database_it = db_.begin();
  try {
    return multiply_dims(*(context_->Evaluator()), dimensions,
                         selection_vector.begin(), selection_vector.end(),
                         database_it, db_.end(), 0);
  } catch (std::exception& e) {
    return InternalError(e.what());
  }
}

vector<uint32_t> PIRDatabase::calculate_indices(const vector<uint32_t>& dims,
                                                uint32_t index) {
  vector<uint32_t> results(dims.size(), 0);
  for (int i = results.size() - 1; i >= 0; --i) {
    results[i] = index % dims[i];
    index = index / dims[i];
  }
  return results;
}

}  // namespace pir
