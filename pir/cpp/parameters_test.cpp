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

#include "pir/cpp/parameters.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pir/cpp/serialization.h"

namespace pir {
namespace {

using std::cout;
using std::endl;
using std::get;
using std::make_tuple;
using std::make_unique;
using std::shared_ptr;
using std::string;
using std::tuple;
using std::unique_ptr;
using std::vector;

using seal::Ciphertext;
using seal::GaloisKeys;
using seal::Plaintext;

using namespace seal;
using namespace ::testing;
using std::int64_t;
using std::vector;

TEST(PIRParametersTest, SanityCheck) {
  // make sure we can actually initialize SEAL and that defaults are sane
  auto pir_params = CreatePIRParameters(100);
  EXPECT_THAT(pir_params.database_size(), Eq(100));
  EXPECT_THAT(pir_params.dimensions(), ElementsAre(100));
  auto encryptionParams = GenerateEncryptionParams(pir_params.he_parameters());
  auto context = seal::SEALContext::Create(encryptionParams);
  EXPECT_THAT(context->parameters_set(), IsTrue())
      << "Error setting encryption parameters: "
      << context->parameter_error_message();
}

TEST(PIRParametersTest, CreateMultiDim) {
  auto pir_params = CreatePIRParameters(1001, 3);
  EXPECT_THAT(pir_params.database_size(), Eq(1001));
  EXPECT_THAT(pir_params.dimensions(), ElementsAre(11, 10, 10));
  auto encryptionParams = GenerateEncryptionParams(pir_params.he_parameters());
  auto context = seal::SEALContext::Create(encryptionParams);
  EXPECT_THAT(context->parameters_set(), IsTrue())
      << "Error setting encryption parameters: "
      << context->parameter_error_message();
}

TEST(PIRParametersTest, EncryptionParamsSerialization) {
  // use something other than defaults
  auto params = GenerateEncryptionParams(GenerateHEParams(8192));
  std::string serial;
  auto status = SEALSerialize<EncryptionParameters>(params, &serial);
  ASSERT_THAT(status.ok(), IsTrue())
      << "Error serializing encryption params: " << status.ToString();
  auto new_params_or = SEALDeserialize<EncryptionParameters>(serial);
  ASSERT_THAT(new_params_or.ok(), IsTrue())
      << "Error deserializing encryption params: "
      << new_params_or.status().ToString();
  ASSERT_THAT(new_params_or.ValueOrDie(), Eq(params));
}

class CalculateDimensionsTest
    : public testing::TestWithParam<
          tuple<uint32_t, uint32_t, vector<uint32_t>>> {};

TEST_P(CalculateDimensionsTest, dimensionsExamples) {
  EXPECT_THAT(CalculateDimensions(get<0>(GetParam()), get<1>(GetParam())),
              ContainerEq(get<2>(GetParam())));
}

INSTANTIATE_TEST_SUITE_P(
    CalculateDimensions, CalculateDimensionsTest,
    testing::Values(make_tuple(100, 1, vector<uint32_t>{100}),
                    make_tuple(100, 2, vector<uint32_t>{10, 10}),
                    make_tuple(82, 2, vector<uint32_t>{10, 9}),
                    make_tuple(975, 2, vector<uint32_t>{32, 31}),
                    make_tuple(1000, 3, vector<uint32_t>{10, 10, 10}),
                    make_tuple(1001, 3, vector<uint32_t>{11, 10, 10}),
                    make_tuple(1000001, 3, vector<uint32_t>{101, 100, 100})));

}  // namespace
}  // namespace pir
