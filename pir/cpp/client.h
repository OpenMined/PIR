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

#ifndef PIR_CLIENT_H_
#define PIR_CLIENT_H_

#include <string>

#include "absl/status/statusor.h"
#include "pir/cpp/context.h"
#include "pir/cpp/database.h"
#include "pir/cpp/serialization.h"

namespace pir {

using absl::StatusOr;

class PIRClient {
  friend class PIRClientTest;

 public:
  /**
   * Creates and returns a new client instance, from existing parameters
   * @param[in] params PIR parameters
   * @returns InvalidArgument if the parameters cannot be loaded
   **/
  static StatusOr<std::unique_ptr<PIRClient>> Create(
      shared_ptr<PIRParameters> params);
  /**
   * Creates a new request to query the database for the given index. Note that
   * if more than one dimension is specified in context, then the request
   * generated will include multiple selection vectors concatenated into one set
   * of ciphertexts. It is expected that the server will first expand the
   * request ciphertexts, and then split them into vectors by the dimensions
   * given in context.
   * @param[in] desiredIndex Expected database value from an index
   * @returns InvalidArgument if the index is invalid or if the encryption fails
   **/
  StatusOr<Request> CreateRequest(
      const std::vector<std::size_t>& /*indexes*/) const;

  /**
   * Extracts database value from server response message. Needs the indices
   * from the original request since multiple values may be packed into each
   * reply ciphertext.
   * @param[in] indexes Original indices when request was created.
   * @param[in] response Server response.
   * @returns List of resulting strings of DB values, or an error.
   */
  StatusOr<std::vector<std::string>> ProcessResponse(
      const std::vector<std::size_t>& indexes, const Response& response) const;

  /**
   * Extracts server response as an integer encoded in the plaintext.
   * Should only be used for testing.
   * @param[in] response Server output
   * @returns InvalidArgument if the decryption fails
   **/
  StatusOr<std::vector<int64_t>> ProcessResponseInteger(
      const Response& response) const;

  PIRClient() = delete;

 private:
  PIRClient(std::unique_ptr<PIRContext>);
  Status initialize();
  Status createQueryFor(size_t desired_index, vector<Ciphertext>& query) const;

  std::unique_ptr<PIRContext> context_;
  std::shared_ptr<PIRDatabase> db_;

  std::unique_ptr<seal::KeyGenerator> keygen_;
  std::shared_ptr<seal::Encryptor> encryptor_;
  std::shared_ptr<seal::Decryptor> decryptor_;
  std::unique_ptr<Request> request_proto_;

  StatusOr<seal::Plaintext> ProcessReply(const Ciphertexts& reply_proto) const;
  StatusOr<seal::Plaintext> ProcessReplyCiphertextMult(
      const Ciphertexts& reply_proto) const;
  StatusOr<seal::Plaintext> ProcessReplyCiphertextDecomp(
      const Ciphertexts& reply_proto) const;
};

}  // namespace pir

#endif  // PIR_CLIENT_H_
