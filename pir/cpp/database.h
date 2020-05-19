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

#include "context.h"
#include "seal/seal.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;

using raw_db_type = std::vector<std::int64_t>;
using db_type = std::vector<seal::Plaintext>;

class PIRDatabase {
 public:
  /**
   * Creates and returns a new PIR database instance.
   * @param[in] db Database to load
   **/
  static std::unique_ptr<PIRDatabase> Create(const db_type& /*database*/);

  /**
   * Multiplies the database with a ciphertext and returns a new ciphertext.
   * @param[in] Evaluator instance
   * @param[in] vector of Ciphertexts
   * @returns InvalidArgument if the multiplication fails
   **/
  StatusOr<std::vector<seal::Ciphertext>> multiply(
      std::shared_ptr<seal::Evaluator> evaluator,
      const std::vector<seal::Ciphertext>& op);

  /**
   * Database size.
   **/
  std::size_t size() const { return db_.size(); }

 private:
  PIRDatabase(db_type db) : db_(db) {}
  db_type db_;
};

class RawDatabase {
 public:
  /**
   * Creates and returns a new raw database instance.
   * @param[in] db Database to load
   **/
  static std::unique_ptr<RawDatabase> Create(const raw_db_type& /*database*/);

  /**
   * Encodes the current database to plaintext.
   * @param[in] PIRContext instance
   * @returns InvalidArgument if the encoding fails
   **/
  StatusOr<std::unique_ptr<PIRDatabase>> Encode(
      const std::unique_ptr<PIRContext>& context) const;

  /**
   * Database size.
   **/
  std::size_t size() const { return db_.size(); }

 private:
  RawDatabase(raw_db_type db) : db_(db) {}

  raw_db_type db_;
};
}  // namespace pir

#endif  // PIR_DATABASE_H_
