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
#include "payload.h"

#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/status_macros.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

using seal::Ciphertext;

StatusOr<buff_type> LoadCiphertexts(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const Ciphertexts& input) {
  buff_type buff(input.ct_size());
  for (int idx = 0; idx < input.ct_size(); ++idx) {
    ASSIGN_OR_RETURN(buff[idx],
                     SEALDeserialize<Ciphertext>(sealctx, input.ct(idx)));
  }

  return buff;
}

StatusOr<Ciphertexts> SaveCiphertexts(const buff_type& ct_) {
  Ciphertexts output;
  for (size_t idx = 0; idx < ct_.size(); ++idx) {
    ASSIGN_OR_RETURN(auto ct, SEALSerialize<Ciphertext>(ct_[idx]));
    output.add_ct(ct);
  }

  return output;
}

};  // namespace pir
