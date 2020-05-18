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

#ifndef PIR_PAYLOAD_H_
#define PIR_PAYLOAD_H_

#include <string>

#include "seal/seal.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;
using buff_type = std::vector<seal::Ciphertext>;

class PIRPayload {
 public:
  static PIRPayload Load(buff_type plain);
  static StatusOr<PIRPayload> Load(
      const std::shared_ptr<seal::SEALContext>& ctx,
      const std::string& encoded);

  StatusOr<std::string> Save();
  const buff_type& Get() const;
  PIRPayload() = delete;

 private:
  PIRPayload(std::vector<seal::Ciphertext> buff) : buff_(buff){};
  buff_type buff_;
};

}  // namespace pir

#endif  // PIR_PAYLOAD_H_
