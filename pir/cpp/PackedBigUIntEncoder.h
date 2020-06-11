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

#ifndef PIR_PACKED_BIG_UINT_ENCODER_H_
#define PIR_PACKED_BIG_UINT_ENCODER_H_

#include "seal/seal.h"

namespace pir {

using seal::BigUInt;
using seal::Plaintext;
using std::shared_ptr;

/**
 * Utility class to pack a BigUInt into as few coefficients as possible in a
 * plaintext. Note that this works for PIR because the only operations expected
 * are multiplication with a ciphertext encryption of 0 or 1, and summation with
 * zero. Otherwise, even adding 1 to this value will produce wraparound and be
 * problematic.
 */
class PackedBigUIntEncoder {
 public:
  // just for now / testing. Change this to factory later
  PackedBigUIntEncoder(shared_ptr<seal::SEALContext> context)
      : context_(context) {}

  /**
   * Encode a BigUInt into a plaintext packed to use as few coefficients as
   * possible.
   * @param[in] value BigUInt value to encode
   * @param[out] destination Plaintext to populate with encoded value.
   */
  void encode(BigUInt value, Plaintext &destination) const;

  /**
   * Decode a BigUInt from a plaintext assumed to be in packed form.
   */
  BigUInt decode(const Plaintext &pt) const;

 private:
  shared_ptr<seal::SEALContext> context_;
};

}  // namespace pir

#endif  // PIR_PACKED_BIG_UINT_ENCODER_H_
