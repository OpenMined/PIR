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
#include "server.h"
#include "utils.h"

namespace pir {

using namespace seal;
using std::make_unique;

class PIRClientTest : public ::testing::Test {
 protected:
  static constexpr std::size_t DB_SIZE = 100;
  static constexpr std::size_t SESSION = 1234;
  void SetUp() {
    pir_params_ = PIRParameters::Create(DB_SIZE);
    client_ = PIRClient::Create(pir_params_).ValueOrDie();

    ASSERT_TRUE(client_ != nullptr);

    vector<std::int64_t> db_;
    db_.resize(DB_SIZE);
    std::generate(db_.begin(), db_.end(), [n = 0]() mutable {
      ++n;
      return 4 * n + 2600;
    });

    auto pirdb = PIRDatabase::Create(db_, pir_params_).ValueOrDie();
    server_ = PIRServer::Create(pirdb, pir_params_).ValueOrDie();
  }

  PIRContext* Context() { return client_->context_.get(); }
  std::shared_ptr<seal::Decryptor> Decryptor() { return client_->decryptor_; }
  std::shared_ptr<seal::Encryptor> Encryptor() { return client_->encryptor_; }

  std::shared_ptr<PIRParameters> pir_params_;
  std::unique_ptr<PIRClient> client_;
  std::unique_ptr<PIRServer> server_;
};

TEST_F(PIRClientTest, TestCreateRequest) {
  int64_t index = 5;

  auto payload = client_->CreateRequest(index).ValueOrDie();
  Plaintext pt;
  ASSERT_EQ(payload.Get().size(), 1);
  Decryptor()->decrypt(payload.Get()[0], pt);

  const auto plain_mod =
      pir_params_->GetEncryptionParams().plain_modulus().value();
  EXPECT_EQ((pt[index] * next_power_two(DB_SIZE)) % plain_mod, 1);
}

TEST_F(PIRClientTest, TestProcessResponse) {
  int64_t value = 987654321;

  // Create a fake payload.
  Plaintext pt;
  Context()->Encoder()->encode(value, pt);
  vector<Ciphertext> ct(1);
  Encryptor()->encrypt(pt, ct[0]);
  PIRPayload payload = PIRPayload::Load(ct, SESSION).ValueOrDie();

  auto result = client_->ProcessResponse(payload).ValueOrDie();
  ASSERT_EQ(result, value);
}

TEST_F(PIRClientTest, TestPayloadSerialization) {
  int64_t value = 987654321;
  Plaintext pt;
  Context()->Encoder()->encode(value, pt);
  vector<Ciphertext> ct(1);
  Encryptor()->encrypt(pt, ct[0]);

  auto payload = PIRPayload::Load(ct, SESSION).ValueOrDie();
  auto dump = payload.Save().ValueOrDie();
  auto reloaded = PIRPayload::Load(Context()->SEALContext(), dump).ValueOrDie();

  ASSERT_EQ(reloaded.Get().size(), 1);
  ASSERT_EQ(reloaded.GetID(), SESSION);

  auto keygen_ = make_unique<KeyGenerator>(Context()->SEALContext());
  auto elts = generate_galois_elts(DEFAULT_POLY_MODULUS_DEGREE);
  GaloisKeys gal_keys = keygen_->galois_keys_local(elts);

  auto fullpayload = PIRPayload::Load(ct, gal_keys).ValueOrDie();
  dump = fullpayload.Save().ValueOrDie();
  auto fullreloaded =
      PIRPayload::Load(Context()->SEALContext(), dump).ValueOrDie();

  ASSERT_EQ(fullreloaded.Get().size(), 1);
  for (auto& elt : elts) {
    ASSERT_TRUE(fullreloaded.GetKeys()->has_key(elt));
  }
}

TEST_F(PIRClientTest, TestSessionReuse) {
  int64_t index = 5;

  int64_t total_bytes = 0;
  int64_t total_bytes_session = 0;
  int64_t payload_bytes = 0;

  for (size_t iter = 0; iter < 10; ++iter) {
    auto full_payload = client_->CreateRequest(index).ValueOrDie();
    total_bytes += full_payload.Save().ValueOrDie().size();

    auto payload = static_cast<PIRPayloadData>(full_payload);
    payload_bytes += payload.Save().ValueOrDie().size();
  }

  for (size_t iter = 0; iter < 10; ++iter) {
    auto full_payload = client_->CreateRequest(index).ValueOrDie();
    total_bytes_session += full_payload.Save().ValueOrDie().size();
    ASSERT_EQ(full_payload.GetKeys().has_value(), iter == 0);

    auto response = server_->ProcessRequest(full_payload).ValueOrDie();
    auto output = client_->ProcessResponse(response).ValueOrDie();
    ASSERT_EQ(output, 2624);
  }

  std::cout << "Total comm size " << total_bytes << " needed " << payload_bytes
            << std::endl;
  ASSERT_LT(35 * (double)payload_bytes, total_bytes);
  ASSERT_LT(total_bytes_session, 0.15 * (double)total_bytes);
  ASSERT_LT(total_bytes_session, 5 * (double)payload_bytes);
}
}  // namespace pir
