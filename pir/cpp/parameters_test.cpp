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
  auto pir_params_or = CreatePIRParameters(1026, 256);
  ASSERT_THAT(pir_params_or.ok(), IsTrue())
      << "Error creating PIR params: " << pir_params_or.status().ToString();
  auto pir_params = pir_params_or.ValueOrDie();
  EXPECT_THAT(pir_params->num_items(), Eq(1026));
  EXPECT_THAT(pir_params->num_pt(), Eq(27));
  EXPECT_THAT(pir_params->bytes_per_item(), Eq(256));
  EXPECT_THAT(pir_params->items_per_plaintext(), Eq(38));
  EXPECT_THAT(pir_params->dimensions(), ElementsAre(27));
  auto encryptionParams =
      SEALDeserialize<EncryptionParameters>(pir_params->encryption_parameters())
          .ValueOrDie();
  auto context = seal::SEALContext::Create(encryptionParams);
  EXPECT_THAT(context->parameters_set(), IsTrue())
      << "Error setting encryption parameters: "
      << context->parameter_error_message();
}

TEST(PIRParametersTest, CreateMultiDim) {
  auto pir_params = CreatePIRParameters(19011, 500, 3).ValueOrDie();
  EXPECT_THAT(pir_params->num_items(), Eq(19011));
  EXPECT_THAT(pir_params->num_pt(), Eq(1001));
  EXPECT_THAT(pir_params->bytes_per_item(), Eq(500));
  EXPECT_THAT(pir_params->items_per_plaintext(), Eq(19));
  EXPECT_THAT(pir_params->dimensions(), ElementsAre(11, 10, 10));
  auto encryption_params_or = SEALDeserialize<EncryptionParameters>(
      pir_params->encryption_parameters());
  ASSERT_THAT(encryption_params_or.ok(), IsTrue())
      << "Error creating encryption params: "
      << encryption_params_or.status().ToString();
  auto encryption_params = encryption_params_or.ValueOrDie();
  auto context = seal::SEALContext::Create(encryption_params);
  EXPECT_THAT(context->parameters_set(), IsTrue())
      << "Error setting encryption parameters: "
      << context->parameter_error_message();
}

TEST(PIRParametersTest, EncryptionParamsSerialization) {
  // use something other than defaults
  auto params = GenerateEncryptionParams(8192);
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

}  // namespace
}  // namespace pir
