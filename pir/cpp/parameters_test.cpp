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
#include "pir/cpp/status_asserts.h"

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
  ASSIGN_OR_FAIL(auto pir_params, CreatePIRParameters(1026, 256));
  EXPECT_THAT(pir_params->num_items(), Eq(1026));
  EXPECT_THAT(pir_params->num_pt(), Eq(27));
  EXPECT_THAT(pir_params->bytes_per_item(), Eq(256));
  EXPECT_THAT(pir_params->items_per_plaintext(), Eq(38));
  EXPECT_THAT(pir_params->dimensions(), ElementsAre(27));
  ASSIGN_OR_FAIL(auto encryptionParams,
                 SEALDeserialize<EncryptionParameters>(
                     pir_params->encryption_parameters()));
  auto context = seal::SEALContext::Create(encryptionParams);
  EXPECT_THAT(context->parameters_set(), IsTrue())
      << "Error setting encryption parameters: "
      << context->parameter_error_message();
}

TEST(PIRParametersTest, CreateMultiDim) {
  ASSIGN_OR_FAIL(auto pir_params, CreatePIRParameters(19011, 500, 3));
  EXPECT_THAT(pir_params->num_items(), Eq(19011));
  EXPECT_THAT(pir_params->num_pt(), Eq(1001));
  EXPECT_THAT(pir_params->bytes_per_item(), Eq(500));
  EXPECT_THAT(pir_params->items_per_plaintext(), Eq(19));
  EXPECT_THAT(pir_params->dimensions(), ElementsAre(11, 10, 10));
  ASSIGN_OR_FAIL(auto encryption_params,
                 SEALDeserialize<EncryptionParameters>(
                     pir_params->encryption_parameters()));
  auto context = seal::SEALContext::Create(encryption_params);
  EXPECT_THAT(context->parameters_set(), IsTrue())
      << "Error setting encryption parameters: "
      << context->parameter_error_message();
}

TEST(PIRParametersTest, CreateAllParams) {
  ASSIGN_OR_FAIL(auto pir_params,
                 CreatePIRParameters(77412, 777, 2,
                                     GenerateEncryptionParams(8192), true, 12));
  EXPECT_THAT(pir_params->num_items(), Eq(77412));
  EXPECT_THAT(pir_params->num_pt(), Eq(5161));
  EXPECT_THAT(pir_params->bytes_per_item(), Eq(777));
  EXPECT_THAT(pir_params->items_per_plaintext(), Eq(15));
  EXPECT_THAT(pir_params->dimensions(), ElementsAre(72, 72));
  EXPECT_THAT(pir_params->use_ciphertext_multiplication(), IsTrue());
  EXPECT_THAT(pir_params->bits_per_coeff(), Eq(12));
  ASSIGN_OR_FAIL(auto encryption_params,
                 SEALDeserialize<EncryptionParameters>(
                     pir_params->encryption_parameters()));
  auto context = seal::SEALContext::Create(encryption_params);
  EXPECT_THAT(context->parameters_set(), IsTrue())
      << "Error setting encryption parameters: "
      << context->parameter_error_message();
}

TEST(PIRParametersTest, EncryptionParamsSerialization) {
  // use something other than defaults
  auto params = GenerateEncryptionParams(8192);
  std::string serial;
  ASSERT_OK(SEALSerialize<EncryptionParameters>(params, &serial));
  ASSIGN_OR_FAIL(auto new_params,
                 SEALDeserialize<EncryptionParameters>(serial));
  ASSERT_THAT(new_params, Eq(params));
}

}  // namespace
}  // namespace pir
