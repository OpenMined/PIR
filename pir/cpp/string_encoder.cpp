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

#include "pir/cpp/string_encoder.h"

#include "pir/cpp/status_asserts.h"

namespace pir {

using absl::InvalidArgumentError;

size_t StringEncoder::num_items_per_plaintext(size_t item_size) {
  return poly_modulus_degree_ * bits_per_coeff_ / item_size / 8;
}

size_t StringEncoder::max_bytes_per_plaintext() {
  return poly_modulus_degree_ * bits_per_coeff_ / 8;
}

/**
 * Helper class for encoding strings to PT coefficients and keeping track of
 * where we are.
 */
class StringEncoderImpl {
 public:
  StringEncoderImpl(Plaintext& destination, size_t bits_per_coeff)
      : destination_(destination),
        bits_per_coeff_(bits_per_coeff),
        coeff_bits_(bits_per_coeff) {}

  StringEncoderImpl() = delete;

  void encode(const string& value);
  void terminate();

 private:
  Plaintext& destination_;
  size_t bits_per_coeff_;

  // temporary variables for encoding
  size_t coeff_index_ = 0;
  size_t coeff_bits_;
};

void StringEncoderImpl::encode(const string& value) {
  for (uint8_t c : value) {
    size_t remain_bits = 8;
    while (remain_bits > 0) {
      size_t n = std::min(coeff_bits_, remain_bits);
      destination_[coeff_index_] <<= n;
      destination_[coeff_index_] |= (c >> (8 - n));
      c <<= n;
      coeff_bits_ -= n;
      remain_bits -= n;
      if (coeff_bits_ <= 0) {
        ++coeff_index_;
        coeff_bits_ = bits_per_coeff_;
      }
    }
  }
}

void StringEncoderImpl::terminate() {
  if (coeff_bits_ < bits_per_coeff_ && coeff_bits_ > 0) {
    destination_[coeff_index_] <<= coeff_bits_;
  }
}
StringEncoder::StringEncoder(shared_ptr<seal::SEALContext> context)
    : context_(context) {
  const auto params = context_->first_context_data()->parms();
  poly_modulus_degree_ = params.poly_modulus_degree();
  bits_per_coeff_ = log2(params.plain_modulus().value());
}

StatusOr<size_t> StringEncoder::calc_num_coeff(size_t num_bytes) const {
  size_t num_coeff = ceil(static_cast<double>(num_bytes * 8) / bits_per_coeff_);
  if (num_coeff > poly_modulus_degree_) {
    return InvalidArgumentError(
        "Number of coefficients needed greater than poly modulus degree");
  }
  return num_coeff;
}

Status StringEncoder::encode(const string& value,
                             Plaintext& destination) const {
  ASSIGN_OR_RETURN(const auto num_coeff, calc_num_coeff(value.size()));
  destination.resize(num_coeff);
  destination.set_zero();
  StringEncoderImpl impl(destination, bits_per_coeff_);
  impl.encode(value);
  impl.terminate();
  return absl::OkStatus();
}

Status StringEncoder::encode(vector<string>::const_iterator v,
                             const vector<string>::const_iterator end,
                             Plaintext& destination) const {
  size_t total_size = std::accumulate(
      v, end, 0, [](int a, const string& b) { return a + b.size(); });
  ASSIGN_OR_RETURN(auto num_coeff, calc_num_coeff(total_size));
  destination.resize(num_coeff);
  destination.set_zero();
  StringEncoderImpl impl(destination, bits_per_coeff_);
  while (v != end) {
    impl.encode(*(v++));
  }
  impl.terminate();
  return absl::OkStatus();
}

StatusOr<string> StringEncoder::decode(const Plaintext& pt, size_t length,
                                       size_t byte_offset) const {
  if ((byte_offset + length) > (pt.coeff_count() * bits_per_coeff_ / 8)) {
    return InvalidArgumentError(
        "Requested decode beyond end of data in polynomial");
  }
  size_t start_coeff_index = byte_offset * 8 / bits_per_coeff_;
  size_t coeff_bits =
      ((start_coeff_index + 1) * bits_per_coeff_) - (byte_offset * 8);
  if (coeff_bits <= 0) {
    coeff_bits = bits_per_coeff_;
  }
  if (length <= 0) {
    length = pt.significant_coeff_count() * bits_per_coeff_ / 8;
  }
  string result(length, 0);
  size_t result_index = 0;
  size_t remain_bits = 8;
  for (size_t i = start_coeff_index; i < pt.coeff_count(); ++i) {
    while (coeff_bits > 0) {
      size_t n = std::min(coeff_bits, remain_bits);
      result[result_index] <<= n;
      result[result_index] |= (pt[i] >> (coeff_bits - n));

      coeff_bits -= n;
      remain_bits -= n;
      if (remain_bits <= 0) {
        if (++result_index >= length) return result;
        remain_bits = 8;
      }
    }
    coeff_bits = bits_per_coeff_;
  }
  return result;
}

}  // namespace pir
