// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// TPM client for initialization

#include <base/command_line.h>
#include <iostream>

#include "secure_blob.h"
#include "tpm.h"

namespace switches {
  static const char kActionSwitch[] = "action";
  static const char *kActions[] = {
    "initialize",
    NULL };
  enum ActionEnum {
    ACTION_INITIALIZE };
}  // namespace switches

int main(int argc, char **argv) {
  CommandLine::Init(argc, argv);

  CommandLine *cl = CommandLine::ForCurrentProcess();
  std::string action = cl->GetSwitchValueASCII(switches::kActionSwitch);

  if (!strcmp(switches::kActions[switches::ACTION_INITIALIZE],
              action.c_str())) {
    tpm_init::Tpm tpm;
    tpm.Init();
    if (tpm.InitializeTpm()) {
      tpm_init::SecureBlob password;
      tpm.GetOwnerPassword(&password);
      std::string str_password(static_cast<const char*>(password.const_data()),
                               password.size());
      printf("TPM Owner Password: %s\n", str_password.c_str());
    } else {
      printf("Failed to initialize the TPM\n");
    }
  } else {
    printf("Unknown action or no action given.  Available actions: \n");
    for(int i = 0; /* loop forever */; i++) {
      if(!switches::kActions[i]) {
        break;
      }
      printf("  --action=%s\n", switches::kActions[i]);
    }
  }
  return 0;
}
