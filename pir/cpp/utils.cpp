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
#include "utils.h"

#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

StatusOr<std::string> serializeParams(const seal::EncryptionParameters& parms) {
  std::stringstream stream;

  try {
    parms.save(stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }
  return stream.str();
}

StatusOr<seal::EncryptionParameters> deserializeParams(
    const std::string& input) {
  seal::EncryptionParameters parms;

  std::stringstream stream;
  stream << input;

  try {
    parms.load(stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return parms;
}
}  // namespace pir
