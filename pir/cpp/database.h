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

#include "absl/status/statusor.h"
#include "pir/cpp/context.h"
#include "seal/seal.h"

namespace pir {

using absl::Status;
using absl::StatusOr;
using std::shared_ptr;
using std::vector;

/**
 * Representation of a PIR database, helpful for both server and client. Server
 * uses this class to process responses by multiplying a selection vector
 * against database values in multi-dimensional format, while the client uses it
 * without loading the backing data to calculate indices and offsets.
 */
class PIRDatabase {
 public:
  /**
   * Creates and returns an empty PIR database with the params used to generate
   * a context.
   * @param[in] PIR parameters
   **/
  static StatusOr<shared_ptr<PIRDatabase>> Create(
      shared_ptr<PIRParameters> params);

  /**
   * Shortcut to create and return a new PIR database instance using a vector of
   *integers encoded one per database plaintext using IntegerEncoder. Only
   *really used for testing, not intended for actual PIR use.
   * @param[in] db Vector of integers to encode into database of plaintexts
   * @param[in] PIR parameters
   **/
  static StatusOr<shared_ptr<PIRDatabase>> Create(
      const vector<std::int64_t>& /*database*/,
      shared_ptr<PIRParameters> params);

  /**
   * Shortcut to create and return a new PIR database instance using the values
   *given. Values are packed into the database as per the parameters given.
   * @param[in] db Database to load
   * @param[in] PIR parameters
   **/
  static StatusOr<shared_ptr<PIRDatabase>> Create(
      const vector<string>& /*database*/, shared_ptr<PIRParameters> params);

  /**
   * Populate the database plaintexts from a list of integers. Only really used
   * for testing.
   */
  Status populate(const vector<std::int64_t>& /*database*/);

  /**
   * Populate the database plaintexts from a list of strings. Items must match
   * the settings in the context or InvalidArgumentError will be returned.
   */
  Status populate(const vector<string>& /*database*/);

  /**
   * Multiplies the database represented as a multi-dimensional hypercube with
   * a selection vector. Selection vector is split into sub vectors based on
   * dimensions fetched from PIRParameters in the current context.
   * @param[in] selection_vector Selection vector to multiply against
   * @returns Ciphertext resulting from multiplication, or error
   */
  StatusOr<std::vector<seal::Ciphertext>> multiply(
      std::vector<seal::Ciphertext>& selection_vector,
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
  vector<uint32_t> calculate_indices(uint32_t index);

  /**
   * Calculate the offset of an item within a plaintext.
   * @param[in] index Item index in the database
   * @returns Offset in bytes from start of the plaintext that contains item.
   */
  size_t calculate_item_offset(uint32_t index);

  /**
   * Helper function to calculate the multi-dimensional representation of the
   * database
   * @param[in] db_size, The database size.
   * @param[in] num_dimensions The mumber of dimensions.
   * @returns Vector of dimensions.
   */
  static vector<uint32_t> calculate_dimensions(uint32_t db_size,
                                               uint32_t num_dimensions);

  PIRDatabase(std::unique_ptr<PIRContext> context)
      : context_(std::move(context)) {}

 private:
  vector<seal::Plaintext> db_;
  std::unique_ptr<PIRContext> context_;
};

}  // namespace pir

#endif  // PIR_DATABASE_H_
