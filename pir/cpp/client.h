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

#ifndef PIR_CLIENT_H_
#define PIR_CLIENT_H_

#include <optional>
#include <string>

#include "seal/seal.h"

namespace pir {

class PIRClient {
 public:
  // Creates and returns a new client instance.
  static std::unique_ptr<PIRClient> Create(
      const seal::EncryptionParameters &params);

  std::optional<std::string> CreateRequest(uint64_t desiredIndex) const;

  std::optional<std::string> ProcessResponse(const std::string &response) const;

  PIRClient() = delete;

 private:
  PIRClient(const seal::EncryptionParameters &params);
};

}  // namespace pir

#endif  // PIR_CLIENT_H_
