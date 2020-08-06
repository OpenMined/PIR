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

#ifndef PIR_CT_REENCODER_H_
#define PIR_CT_REENCODER_H_

#include "seal/seal.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;

using seal::Ciphertext;
using seal::Plaintext;
using seal::SEALContext;
using ::std::shared_ptr;
using ::std::vector;

class CiphertextReencoder {
 public:
  static StatusOr<std::unique_ptr<CiphertextReencoder>> Create(
      shared_ptr<SEALContext> /*params*/);

  uint32_t ExpansionRatio() const;

  /**
   * Reencode a ciphertext as a set of plaintexts.
   * @param[in] ct Ciphertext to reencode.
   * @returns Vector of plaintexts created by decomposing CT.
   */
  vector<Plaintext> Encode(const Ciphertext& ct);

  /**
   * Reencode a set of ciphertext as a set of plaintexts.
   * @param[in] cts Vector of ciphertexts to reencode.
   * @returns Vector of vectors of plaintexts created by decomposing cts.
   */
  vector<vector<Plaintext>> Encode(const vector<Ciphertext>& cts);

  /**
   * Recompose a ciphertext from a set of plaintexts.
   * @param[in] pts Vector of plaintexts to decode.
   * @returns Ciphertext recomposed from plaintexts.
   */
  Ciphertext Decode(const vector<Plaintext>& pts);

  /**
   * Recompose a set of ciphertexts from a set of plaintext sets.
   * @param[in] pts Vector of vectors of plaintexts to decode.
   * @returns Vector of ciphertexts recomposed from plaintexts vectors.
   */
  vector<Ciphertext> Decode(const vector<vector<Plaintext>>& pts);

 private:
  CiphertextReencoder(shared_ptr<SEALContext> context) : context_(context) {}

  void Encode(const Ciphertext& ct, vector<Plaintext>::iterator pt_iter);

  shared_ptr<SEALContext> context_;
};

}  // namespace pir

#endif  // PIR_CT_REENCODER_H_
