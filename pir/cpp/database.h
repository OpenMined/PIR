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

class PIRDatabase {
 public:
  /**
   * Creates and returns a new database instance.
   * @param[in] db Database to load
   * @returns InvalidArgument if the database encoding fails
   **/
  static StatusOr<std::unique_ptr<PIRDatabase>> Create(
      const std::unique_ptr<PIRContext>& context,
      const std::vector<std::uint64_t>& /*database*/);

  /**
   * Multiplies the database with a ciphertext and returns a new ciphertext.
   * @param[in] Ciphertext
   * @returns InvalidArgument if the multiplication fails
   **/
  StatusOr<seal::Ciphertext> multiply(
      const std::shared_ptr<seal::Evaluator>& eval, const seal::Ciphertext& op);

 private:
  PIRDatabase(seal::Plaintext& db, std::size_t size) : db_(db), size_(size) {}
  seal::Plaintext db_;
  std::size_t size_;
};

}  // namespace pir

#endif  // PIR_DATABASE_H_
