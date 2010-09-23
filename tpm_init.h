// Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TpmInit - public interface class for initializing the TPM

#include <base/scoped_ptr.h>
#include <base/platform_thread.h>
#include <chromeos/utility.h>

#ifndef TPM_INIT_TPM_INIT_H_
#define TPM_INIT_TPM_INIT_H_

namespace tpm_init {

class TpmInitTask;

class TpmInit {
 public:

  class TpmInitCallback {
   public:
    virtual void InitializeTpmComplete(bool status, bool took_ownership) = 0;
  };

  // Default constructor
  TpmInit();

  virtual ~TpmInit();

  virtual void Init(TpmInitCallback* notify_callback);

  // Gets random data from the TPM
  //
  // Parameters
  //   length - The number of bytes to get
  //   data (OUT) - Receives the random bytes
  virtual bool GetRandomData(int length, chromeos::Blob* data);

  // Starts asynchronous initialization of the TPM
  virtual bool StartInitializeTpm();

  // Returns true if the TPM is initialized and ready for use
  virtual bool IsTpmReady();

  // Returns true if the TPM is enabled
  virtual bool IsTpmEnabled();

  // Returns true if the TPM is owned
  virtual bool IsTpmOwned();

  // Returns true if the TPM is being owned
  virtual bool IsTpmBeingOwned();

  // Gets the TPM password if the TPM initialization took ownership
  //
  // Parameters
  //   password (OUT) - The owner password used for the TPM
  virtual bool GetTpmPassword(chromeos::Blob* password);

  // Returns the number of milliseconds it took to initialize the TPM
  virtual long GetInitializationMillis();

 private:
  // The background task for initializing the TPM, implemented as a
  // PlatformThread::Delegate
  scoped_ptr<TpmInitTask> tpm_init_task_;

  TpmInitCallback* notify_callback_;

  DISALLOW_COPY_AND_ASSIGN(TpmInit);
};

}  // namespace tpm_init

#endif  // TPM_INIT_TPM_INIT_H_
