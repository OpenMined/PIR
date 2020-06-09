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
#include "pir/cpp/database.h"

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
using seal::Ciphertext;
using seal::Evaluator;
using seal::Plaintext;
using std::vector;

StatusOr<std::shared_ptr<PIRDatabase>> PIRDatabase::Create(
    const raw_db_type& rawdb, const PIRParameters& params) {
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

/**
 * Helper class to make the recursive multiplication operation on the
 * multi-dimensional representation of the database easier. Encapsulates all of
 * the variables needed to do the multiplication, and keeps track of the
 * database iterator to separate it from the database itself.
 */
class DatabaseMultiplier {
 public:
  /**
   * Create a multiplier for the given scenario.
   * @param[in] database Database against which to multiply.
   * @param[in] selection_vector multi-dimensional selection vector
   * @param[in] evaluator Evaluator to use for homomorphic operations.
   * @param[in] relin_keys If not nullptr, relinearization will be done after
   *    every homomorphic multiplication.
   * @param[in] decryptor If not nullptr, outputs to cout the noise budget
   *    remaining after every homomorphic operation.
   */
  DatabaseMultiplier(const vector<Plaintext>& database,
                     const vector<Ciphertext>& selection_vector,
                     shared_ptr<Evaluator> evaluator,
                     const seal::RelinKeys* const relin_keys,
                     seal::Decryptor* const decryptor)
      : database_(database),
        selection_vector_(selection_vector),
        evaluator_(evaluator),
        relin_keys_(relin_keys),
        decryptor_(decryptor) {}

  /**
   * Do the multiplication using the given dimension sizes.
   */
  Ciphertext multiply(const RepeatedField<uint32_t>& dimensions) {
    database_it_ = database_.begin();
    return multiply(dimensions, selection_vector_.begin(), 0);
  }

 private:
  /**
   * Recursive function to do the dot product of each dimension with the db.
   * Calls itself to move down dimensions until you get to the bottom dimension.
   * Bottom dimension just does a dot product with the DB, and returns the
   * result. Upper levels then take those results, and dot product again with
   * the selection vector, until you get back to the top. NB: Database iterator
   * is kept at the class level so that we move through the database one element
   * at a time.
   *
   * @param[in] dimensions List of remaining demainsion sizes.
   * @param[in] selection_vector_it Iterator into the start of the selection
   *  vector for the current depth.
   * @param[in] depth Current depth.
   */
  Ciphertext multiply(const RepeatedField<uint32_t>& dimensions,
                      vector<Ciphertext>::const_iterator selection_vector_it,
                      size_t depth) {
    const size_t this_dimension = dimensions[0];
    auto remaining_dimensions =
        RepeatedField<uint32_t>(dimensions.begin() + 1, dimensions.end());

    string depth_string(depth, ' ');

    Ciphertext result;
    bool first_pass = true;
    for (size_t i = 0; i < this_dimension; ++i) {
      // make sure we don't go past end of DB
      if (database_it_ == database_.end()) break;
      Ciphertext temp_ct;
      if (remaining_dimensions.empty()) {
        // base case: have to multiply against DB
        evaluator_->multiply_plain(*(selection_vector_it + i),
                                   *(database_it_++), temp_ct);
        print_noise(depth, "base", temp_ct, i);

      } else {
        temp_ct = multiply(remaining_dimensions,
                           selection_vector_it + this_dimension, depth + 1);
        print_noise(depth, "recurse", temp_ct, i);

        evaluator_->multiply_inplace(temp_ct, *(selection_vector_it + i));
        print_noise(depth, "mult", temp_ct, i);

        if (relin_keys_ != nullptr) {
          evaluator_->relinearize_inplace(temp_ct, *relin_keys_);
          print_noise(depth, "relin", temp_ct, i);
        }
      }

      if (first_pass) {
        result = temp_ct;
        first_pass = false;
      } else {
        evaluator_->add_inplace(result, temp_ct);
        print_noise(depth, "result", temp_ct, i);
      }
    }

    print_noise(depth, "final", result);
    return result;
  }

  void print_noise(size_t depth, const string& desc, const Ciphertext& ct,
                   std::optional<size_t> i_opt = {}) {
    if (decryptor_ != nullptr) {
      std::cout << string(depth, ' ');
      if (i_opt) {
        std::cout << "i = " << (*i_opt) << " ";
      }
      std::cout << desc << " noise budget "
                << decryptor_->invariant_noise_budget(ct) << std::endl;
    }
  }

  const vector<Plaintext>& database_;
  const vector<Ciphertext>& selection_vector_;
  shared_ptr<Evaluator> evaluator_;

  // If not null, relinearization keys are applied after each HE op
  const seal::RelinKeys* const relin_keys_;

  // If not null, used to get invariant noise budget after each HE op
  seal::Decryptor* const decryptor_;

  // Current location as we move through the database.
  // Needs to be kept here, as lower levels of recursion move forward.
  vector<Plaintext>::const_iterator database_it_;
};

StatusOr<Ciphertext> PIRDatabase::multiply(
    const vector<Ciphertext>& selection_vector,
    const seal::RelinKeys* const relin_keys,
    seal::Decryptor* const decryptor) const {
  auto& dimensions = context_->Params().dimensions();
  const size_t dim_sum =
      std::accumulate(dimensions.begin(), dimensions.end(), 0);

  if (selection_vector.size() != dim_sum) {
    return InvalidArgumentError(
        "Selection vector size does not match dimensions");
  }

  try {
    DatabaseMultiplier dbm(db_, selection_vector, context_->Evaluator(),
                           relin_keys, decryptor);
    return dbm.multiply(dimensions);
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

std::vector<uint32_t> PIRDatabase::calculate_dimensions(
    uint32_t db_size, uint32_t num_dimensions) {
  std::vector<uint32_t> results;
  for (int i = num_dimensions; i > 0; --i) {
    results.push_back(std::ceil(std::pow(db_size, 1.0 / i)));
    db_size = std::ceil(static_cast<double>(db_size) / results.back());
  }
  return results;
}

}  // namespace pir
