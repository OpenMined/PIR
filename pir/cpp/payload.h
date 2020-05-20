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

#include <optional>
#include <string>

#include "seal/seal.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;
using seal::GaloisKeys;
using std::optional;
using buff_type = std::vector<seal::Ciphertext>;

class PIRPayload {
 public:
  /**
   * Loads a PIR Payload.
   **/
  static PIRPayload Load(const buff_type& plain,
                         const optional<GaloisKeys>& keys = {});
  /**
   * Decodes and loads a PIR Payload.
   * @returns InvalidArgument if the decoding fails
   **/
  static StatusOr<PIRPayload> Load(
      const std::shared_ptr<seal::SEALContext>& ctx,
      const std::string& encoded);
  /**
   * Saves the PIR Payload to a string.
   * @returns InvalidArgument if the encoding fails
   **/
  StatusOr<std::string> Save();
  /**
   * Returns a reference to the internal buffer.
   **/
  const buff_type& Get() const;
  PIRPayload() = delete;

  const optional<GaloisKeys>& GetKeys() const { return keys_; }

 private:
  PIRPayload(const std::vector<seal::Ciphertext>& buff,
             const optional<GaloisKeys>& keys = {})
      : buff_(buff), keys_(keys){};

  buff_type buff_;
  optional<GaloisKeys> keys_;
};

}  // namespace pir

#endif  // PIR_PAYLOAD_H_
