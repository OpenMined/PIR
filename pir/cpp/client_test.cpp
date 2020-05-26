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

#include "client.h"

#include "gtest/gtest.h"
#include "utils.h"

namespace pir {

using namespace seal;
using std::make_unique;

class PIRClientTest : public ::testing::Test {
 protected:
  static constexpr std::size_t dbsize = 10;
  void SetUp() {
    pir_params_ = PIRParameters::Create(dbsize);
    client_ = PIRClient::Create(pir_params_).ValueOrDie();
    ASSERT_TRUE(client_ != nullptr);
  }

  PIRContext* Context() { return client_->context_.get(); }
  std::shared_ptr<seal::Decryptor> Decryptor() { return client_->decryptor_; }
  std::shared_ptr<seal::Encryptor> Encryptor() { return client_->encryptor_; }

  std::shared_ptr<PIRParameters> pir_params_;
  std::unique_ptr<PIRClient> client_;
};

TEST_F(PIRClientTest, TestCreateRequest) {
  int64_t index = 5;

  auto payload = client_->CreateRequest(index).ValueOrDie();
  Plaintext pt;
  ASSERT_EQ(payload.Get().size(), 1);
  Decryptor()->decrypt(payload.Get()[0], pt);

  const auto plain_mod =
      pir_params_->GetEncryptionParams().plain_modulus().value();
  EXPECT_EQ((pt[index] * next_power_two(dbsize)) % plain_mod, 1);
}

TEST_F(PIRClientTest, TestProcessResponse) {
  int64_t value = 987654321;

  // Create a fake payload.
  Plaintext pt;
  Context()->Encoder()->encode(value, pt);
  vector<Ciphertext> ct(1);
  Encryptor()->encrypt(pt, ct[0]);
  PIRPayload payload = PIRPayload::Load(ct);

  auto result = client_->ProcessResponse(payload).ValueOrDie();
  ASSERT_EQ(result, value);
}

TEST_F(PIRClientTest, TestPayloadSerialization) {
  int64_t value = 987654321;
  Plaintext pt;
  Context()->Encoder()->encode(value, pt);
  vector<Ciphertext> ct(1);
  Encryptor()->encrypt(pt, ct[0]);

  auto keygen_ = make_unique<KeyGenerator>(Context()->SEALContext());
  GaloisKeys gal_keys = keygen_->galois_keys_local(
      generate_galois_elts(DEFAULT_POLY_MODULUS_DEGREE));

  auto payload = PIRPayload::Load(ct, gal_keys);

  auto dump = payload.Save().ValueOrDie();
  std::cout << "dump " << dump << std::endl;
  auto raw = PIRPayload::Load(Context()->SEALContext(), dump);
  if (!raw.ok()) {
    std::cout << raw.status().message() << std::endl;
  }
  auto reloaded = raw.ValueOrDie();

  ASSERT_EQ(reloaded.Get().size(), 1);
  // ASSERT_TRUE(reloaded.GetKeys().has_value());
}

}  // namespace pir
