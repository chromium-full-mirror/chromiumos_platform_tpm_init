// Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Contains the implementation of class Crypto

#include "crypto.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <base/file_util.h>
#include <base/logging.h>
#include <chromeos/utility.h>

using std::string;

namespace tpm_init {

const std::string kDefaultEntropySource = "/dev/urandom";
const int kWellKnownExponent = 65537;

Crypto::Crypto()
    : entropy_source_(kDefaultEntropySource) {
}

Crypto::~Crypto() {
}

bool Crypto::Init() {
  SeedRng();
  return true;
}

void Crypto::SeedRng() const {
  // TODO(fes): Get assistance from the TPM?
  while (!RAND_status()) {
    char buffer[256];
    file_util::ReadFile(FilePath(entropy_source_), buffer, sizeof(buffer));
    RAND_add(buffer, sizeof(buffer), sizeof(buffer));
  }
}

void Crypto::GetSecureRandom(unsigned char *rand, int length) const {
  SeedRng();
  // Have OpenSSL generate the random bytes
  RAND_bytes(rand, length);
}

void Crypto::GetSha1(const chromeos::Blob& data, int start, int count,
                     SecureBlob* hash) const {
  SHA_CTX sha_ctx;
  unsigned char md_value[SHA_DIGEST_LENGTH];

  SHA1_Init(&sha_ctx);
  SHA1_Update(&sha_ctx, &data[start], count);
  SHA1_Final(md_value, &sha_ctx);
  hash->resize(sizeof(md_value));
  memcpy(hash->data(), md_value, sizeof(md_value));
}

bool Crypto::CreateRsaKey(int key_bits, SecureBlob* n, SecureBlob* p) const {
  SeedRng();

  RSA* rsa = RSA_generate_key(key_bits, kWellKnownExponent, NULL, NULL);

  if (rsa == NULL) {
    LOG(ERROR) << "RSA key generation failed.";
    return false;
  }

  SecureBlob local_n(BN_num_bytes(rsa->n));
  if (BN_bn2bin(rsa->n, static_cast<unsigned char*>(local_n.data())) <= 0) {
    LOG(ERROR) << "Unable to get modulus from RSA key.";
    RSA_free(rsa);
    return false;
  }

  SecureBlob local_p(BN_num_bytes(rsa->p));
  if (BN_bn2bin(rsa->p, static_cast<unsigned char*>(local_p.data())) <= 0) {
    LOG(ERROR) << "Unable to get private key from RSA key.";
    RSA_free(rsa);
    return false;
  }

  RSA_free(rsa);
  n->swap(local_n);
  p->swap(local_p);
  return true;
}

void Crypto::AsciiEncodeToBuffer(const chromeos::Blob& blob, char* buffer,
                                 int buffer_length) {
  const char hex_chars[] = "0123456789abcdef";
  int i = 0;
  for (chromeos::Blob::const_iterator it = blob.begin();
      it < blob.end() && (i + 1) < buffer_length; ++it) {
    buffer[i++] = hex_chars[((*it) >> 4) & 0x0f];
    buffer[i++] = hex_chars[(*it) & 0x0f];
  }
  if (i < buffer_length) {
    buffer[i] = '\0';
  }
}

} // namespace tpm_init
