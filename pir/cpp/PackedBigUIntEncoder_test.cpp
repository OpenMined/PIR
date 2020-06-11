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

#include "pir/cpp/PackedBigUIntEncoder.h"

#include <iostream>
#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pir/cpp/parameters.h"

namespace pir {
namespace {

using std::cout;
using std::endl;
using std::unique_ptr;

using seal::SEALContext;

class PackedBigUIntEncoderTest : public ::testing::Test {
 protected:
  void SetUp() {
    auto params = GenerateEncryptionParams(4096);
    seal_context_ = seal::SEALContext::Create(params);
    if (!seal_context_->parameters_set()) {
      FAIL() << "Error setting encryption parameters: "
             << seal_context_->parameter_error_message();
    }

    encoder_ = std::make_unique<PackedBigUIntEncoder>(seal_context_);
  }

  shared_ptr<SEALContext> seal_context_;
  unique_ptr<PackedBigUIntEncoder> encoder_;
};

TEST_F(PackedBigUIntEncoderTest, TestEncodeDecode) {
  BigUInt value("DEADBEEF12345678909876543210010BEEFDEAD");
  Plaintext pt;
  encoder_->encode(value, pt);
  cout << "Got PT " << pt.to_string() << endl;
  BigUInt result = encoder_->decode(pt);
  EXPECT_EQ(result, value);
}

}  // namespace
}  // namespace pir
