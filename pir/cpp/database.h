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

#ifndef PIR_DATABASE_H_
#define PIR_DATABASE_H_

#include <string>
#include <vector>

#include "pir/cpp/context.h"
#include "seal/seal.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;

using raw_db_type = std::vector<std::int64_t>;
using db_type = std::vector<seal::Plaintext>;

using google::protobuf::RepeatedField;

class PIRDatabase {
 public:
  /**
   * Creates and returns a new PIR database instance.
   * @param[in] db Database to load
   * @param[in] PIR parameters
   **/
  static StatusOr<std::shared_ptr<PIRDatabase>> Create(
      const raw_db_type& /*database*/, const PIRParameters& params);

  /**
   * Multiplies the database represented as a multi-dimensional hypercube with
   * a selection vector. Selection vector is split into sub vectors based on
   * dimensions fetched from PIRParameters in the current context.
   * @param[in] selection_vector Selection vector to multiply against
   * @returns Ciphertext resulting from multiplication, or error
   */
  StatusOr<seal::Ciphertext> multiply(
      const std::vector<seal::Ciphertext>& selection_vector,
      const seal::RelinKeys* const relin_keys = nullptr,
      seal::Decryptor* const decryptor = nullptr) const;

  /**
   * Database size.
   **/
  std::size_t size() const { return db_.size(); }

  /**
   * Helper function to calculate indices within the multi-dimensional
   * representation of the database for a given index in the flat
   * representation.
   * @param[in] dims The dimensions to use in multi-dimensional rep.
   * @param[in] index Index in the flat representation.
   * @returns Vector of indices.
   */
  static vector<uint32_t> calculate_indices(const vector<uint32_t>& dims,
                                            uint32_t index);

  /**
   * Helper function to calculate the multi-dimensional representation of the
   * database
   * @param[in] db_size, The database size.
   * @param[in] num_dimensions The mumber of dimensions.
   * @returns Vector of dimensions.
   */
  static std::vector<uint32_t> calculate_dimensions(uint32_t db_size,
                                                    uint32_t num_dimensions);

  PIRDatabase(db_type db, std::unique_ptr<PIRContext> context)
      : db_(db), context_(std::move(context)) {}

 private:
  db_type db_;
  std::unique_ptr<PIRContext> context_;
};

}  // namespace pir

#endif  // PIR_DATABASE_H_
