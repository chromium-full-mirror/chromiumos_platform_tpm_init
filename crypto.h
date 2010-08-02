// Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Crypto - class for handling some OpenSSL crypto functions

#ifndef TPM_INIT_CRYPTO_H_
#define TPM_INIT_CRYPTO_H_

#include <base/basictypes.h>
#include <base/file_path.h>

#include "secure_blob.h"

namespace tpm_init {

// Default entropy source is used to seed openssl's random number generator
extern const std::string kDefaultEntropySource;

class Crypto {
 public:

  // Default constructor, using the default entropy source
  Crypto();

  virtual ~Crypto();

  // Initializes Crypto
  bool Init();

  // Seeds the random number generator
  void SeedRng() const;

  // Returns random bytes of the given length
  //
  // Parameters
  //   rand (OUT) - Where to store the random bytes
  //   length - The number of random bytes to store in rand
  void GetSecureRandom(unsigned char *rand, int length) const;

  // Creates a new RSA key
  //
  // Parameters
  //   key_bits - The key size to generate
  //   n (OUT) - the modulus
  //   p (OUT) - the private key
  bool CreateRsaKey(int key_bits, SecureBlob* n, SecureBlob *p) const;

  // Gets the SHA1 hash of the data provided
  void GetSha1(const chromeos::Blob& data, int start, int count,
               SecureBlob* hash) const;

  void AsciiEncodeToBuffer(const chromeos::Blob& blob, char* buffer,
                           int buffer_length);

 private:
  std::string entropy_source_;

  DISALLOW_COPY_AND_ASSIGN(Crypto);
};

}  // namespace tpm_init

#endif  // TPM_INIT_CRYPTO_H_
