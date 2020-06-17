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

#ifndef PIR_STRING_ENCODER_H_
#define PIR_STRING_ENCODER_H_

#include <string>

#include "seal/seal.h"

namespace pir {

using seal::Plaintext;
using std::shared_ptr;
using std::string;

class StringEncoder {
 public:
  // just for now / testing. Change this to factory later
  StringEncoder(shared_ptr<seal::SEALContext> context);

  /**
   * Encode a string of binary value into the destination using a
   * minimal amount of coefficients.
   * @param[in] value String to encode
   * @param[in] destination Plaintext to populate with encoded value
   */
  void encode(const string& value, Plaintext& destination) const;

  /**
   * Decode a plaintext assumed to be in packed form into a string.
   */
  string decode(const Plaintext& pt) const;

 private:
  shared_ptr<seal::SEALContext> context_;
  size_t poly_modulus_degree_;
  size_t bits_per_coeff_;
};

}  // namespace pir

#endif  // PIR_STRING_ENCODER_H_
