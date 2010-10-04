// Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Contains the implementation of class Platform

#include "platform.h"

#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

namespace tpm_init {

const int kDefaultUmask = S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH
                               | S_IXOTH;

Platform::Platform()
    : umask_(kDefaultUmask) {
}

Platform::~Platform() {
}

int Platform::SetMask(int new_mask) {
  return umask(new_mask);
}

} // namespace tpm_init
