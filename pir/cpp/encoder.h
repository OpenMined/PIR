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

#ifndef PIR_ENCODER_H
#define PIR_ENCODER_H

#include <any>
#include <map>
#include <typeindex>
#include <vector>

#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;
using std::vector;

using seal::Plaintext;
using seal::SEALContext;

/**
 * SEAL Encoder wrapper
 * */
class EncoderFactory {
 public:
  EncoderFactory() = delete;
  EncoderFactory(EncoderFactory&) = delete;
  EncoderFactory(std::shared_ptr<SEALContext> context) : context_(context){};

  template <typename T>
  StatusOr<std::shared_ptr<T>> get() {
    const std::type_index& tidx = std::type_index(typeid(T));
    try {
      if (encoders_.find(tidx) == encoders_.end()) return create<T>();
    } catch (const std::exception& e) {
      return InvalidArgumentError(e.what());
    }
    return std::any_cast<std::shared_ptr<T>>(encoders_[tidx]);
  }

  /*
  Template encoding functions to choose between the use of
  Integer/BatchEncoder or CKKSEncoder.
  */
  template <class T, class R>
  StatusOr<Plaintext> encode(const R& in) {
    auto encoderor = this->get<T>();
    if (!encoderor.ok()) return encoderor.status();
    auto encoder = encoderor.ValueOrDie();

    Plaintext pt;
    try {
      encoder->encode(in, pt);
    } catch (const std::exception& e) {
      return InvalidArgumentError(e.what());
    }

    return pt;
  }

  template <class CKKSEncoder>
  void encode(vector<double>& vec, Plaintext& pt,
              std::optional<double> optscale = {}) {
    double scale = 1.0;
    if (optscale.has_value())
      scale = optscale.value();
    else
      scale = global_scale();

    auto encoderor = this->get<CKKSEncoder>();
    if (!encoderor.ok()) return encoderor.status();
    auto encoder = encoderor.ValueOrDie();
    encoder->encode(vec, scale, pt);
  }

  /*
  Template decoding functions Integer/BatchEncoder/CKKSEncoder.
  */
  template <class T, class R>
  StatusOr<R> decode(const Plaintext& pt) {
    R result;
    auto encoderor = this->get<T>();
    if (!encoderor.ok()) return encoderor.status();
    auto encoder = encoderor.ValueOrDie();
    try {
      encoder->decode(pt, result);
    } catch (const std::exception& e) {
      return InvalidArgumentError(e.what());
    }

    return result;
  }
  template <class IntegerEncoder>
  StatusOr<std::int64_t> decode(const Plaintext& pt) {
    std::int64_t result;
    auto encoderor = this->get<IntegerEncoder>();
    if (!encoderor.ok()) return encoderor.status();
    auto encoder = encoderor.ValueOrDie();
    try {
      result = encoder->decode_int64(pt);
    } catch (const std::exception& e) {
      return InvalidArgumentError(e.what());
    }

    return result;
  }

  /*
  Template for slot count.
  */
  template <class T>
  size_t slot_count() {
    auto encoder = this->get<T>();
    return encoder->slot_count();
  }

  // Default scale for CKKS encoder
  void global_scale(double scale) {
    if (scale < 0) return;

    this->scale_ = scale;
  }
  StatusOr<double> global_scale() {
    if (!this->scale_.has_value())
      return InvalidArgumentError("no global scale");
    return this->scale_.value();
  }

 private:
  // Can throw exception in case of invalid parameters
  template <typename T>
  std::shared_ptr<T> create() {
    const std::type_index& tidx = std::type_index(typeid(T));

    encoders_[tidx] = std::make_shared<T>(this->context_);

    return std::any_cast<std::shared_ptr<T>>(encoders_[tidx]);
  }

  /*
  Stores a map of available encoders.
  */
  std::map<std::type_index, std::any> encoders_;

  /*
  Stores a shared_pointer to the SEAL Context.
  */
  std::shared_ptr<SEALContext> context_;

  /*
  Stores a global scale used across ciphertext encrypted using CKKS.
  */
  std::optional<double> scale_;
};

}  // namespace pir
#endif
