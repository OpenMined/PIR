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

#include "absl/status/statusor.h"
#include "seal/seal.h"

namespace pir {

using absl::Status;
using absl::StatusOr;
using seal::Plaintext;
using std::shared_ptr;
using std::string;
using std::vector;

class StringEncoder {
 public:
  // just for now / testing. Change this to factory later
  StringEncoder(shared_ptr<seal::SEALContext> context);

  /**
   * Calculate the number of items that can be encoded into a single plaintext.
   * @param[in] item_size Size of each item in database
   * @returns Number of items per plaintext
   */
  size_t num_items_per_plaintext(size_t item_size);

  /**
   * Calculate the maximum number of bytes that can be encded in a single pt.
   */
  size_t max_bytes_per_plaintext();

  /**
   * Encode a string of binary value into the destination using a
   * minimal amount of coefficients.
   * @param[in] value String to encode
   * @param[out] destination Plaintext to populate with encoded value
   * @returns Invalid argument if string is too big for plaintext polynomial
   */
  Status encode(const string& value, Plaintext& destination) const;

  /**
   * Encodes several strings into a plaintext using the
   * minimal amount of coefficients.
   * @param[in] v Iterator pointing to the start of values to encode
   * @param[in] end End of the sequence of values to
   * @param[out] destination Plaintext to populate with encoded value
   * @returns Invalid argument if total string length is too big for plaintext
   * polynomial
   */
  Status encode(vector<string>::const_iterator v,
                const vector<string>::const_iterator end,
                Plaintext& destination) const;

  /**
   * Decode a plaintext assumed to be in packed form into a string.
   * @param[in] pt The plaintext value to decode from.
   * @param[in] length The length in bytes of the string to decode. If not
   *     provided or set to zero, decodes the values from all significant
   * coefficients in plaintext polynomial.
   * @param[in] offset Offset in bytes from the start of the plaintext from
   *    which to decode.
   * @returns String decoded or Error
   */
  StatusOr<string> decode(const Plaintext& pt, size_t length = 0,
                          size_t offset = 0) const;

  /**
   * Allows overriding number of bits to pack per coefficient.
   */
  void set_bits_per_coeff(size_t bits_per_coeff) {
    bits_per_coeff_ = bits_per_coeff;
  }

  /**
   * Number of bits to use per coefficient.
   */
  size_t bits_per_coeff() { return bits_per_coeff_; }

 private:
  shared_ptr<seal::SEALContext> context_;
  size_t poly_modulus_degree_;
  size_t bits_per_coeff_;

  // Helper to calculate the number of coefficients needed to encode a number of
  // bytes of input in the current context, or InvalidArgumentError if the input
  // is too long.
  StatusOr<size_t> calc_num_coeff(size_t num_bytes) const;
};

}  // namespace pir

#endif  // PIR_STRING_ENCODER_H_
