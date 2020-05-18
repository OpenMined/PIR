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

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "util/statusor.h"

namespace pir {

using ::std::optional;
using ::std::size_t;

using ::seal::EncryptionParameters;

seal::EncryptionParameters generateEncryptionParams(
    uint32_t poly_modulus_degree = 4096);

class PIRParameters {
 public:
  static std::shared_ptr<PIRParameters> Create(size_t dbsize) {
    return absl::WrapUnique(new PIRParameters(dbsize));
  }
  size_t DBSize() const { return database_size_; }
  const EncryptionParameters& GetEncryptionParams() const { return parms_; }

 private:
  PIRParameters(size_t dbsize)
      : database_size_(dbsize), parms_(generateEncryptionParams()) {}

  // Database parameters
  size_t database_size_;

  // Encryption parameters&helpers
  EncryptionParameters parms_;
};

}  // namespace pir

#endif  // PIR_PARAMETERS_H_
