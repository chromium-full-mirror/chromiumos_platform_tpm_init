// Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_INIT_PLATFORM_H_
#define TPM_INIT_PLATFORM_H_

#include <base/basictypes.h>
#include <string>
#include <vector>

namespace tpm_init {

// Default umask
extern const int kDefaultUmask;

// Class Platform exists to be able to mock platform calls (in this case, just
// umask).
// TODO(fes): Remove this class altogether if tpm_init is merged with
// cryptohome, or put it in a separate, common library.
class Platform {
 public:

  Platform();

  virtual ~Platform();

  // Sets the current umask, returning the old mask
  //
  // Parameters
  //   new_mask - The mask to set
  virtual int SetMask(int new_mask);

 private:
  int umask_;

  DISALLOW_COPY_AND_ASSIGN(Platform);
};

}  // namespace tpm_init

#endif  // TPM_INIT_PLATFORM_H_
