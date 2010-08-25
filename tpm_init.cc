// Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Contains the implementation of class TpmInit

#include "tpm_init.h"

#include <base/logging.h>
#include <base/time.h>

#include "tpm.h"

namespace tpm_init {

// TpmInitTask is a private class used to handle asynchronous initialization of
// the TPM.
class TpmInitTask : public PlatformThread::Delegate {
 public:
  TpmInitTask();
  virtual ~TpmInitTask();

  void Init();

  virtual void ThreadMain();

  bool IsTpmReady();
  bool IsTpmEnabled();
  bool GetTpmPassword(chromeos::Blob* password);
  long GetInitializationMillis();
  bool GetRandomData(int length, chromeos::Blob* data);

 private:
  scoped_ptr<tpm_init::Tpm> default_tpm_;
  tpm_init::Tpm* tpm_;
  bool initialize_status_;
  bool task_done_;
  long initialization_time_;
};

TpmInit::TpmInit()
    : tpm_init_(new TpmInitTask()) {
}

TpmInit::~TpmInit() {
}

bool TpmInit::GetRandomData(int length, chromeos::Blob* data) {
  return tpm_init_->GetRandomData(length, data);
}

bool TpmInit::StartInitializeTpm() {
  tpm_init_->Init();
  if (!PlatformThread::CreateNonJoinable(0, tpm_init_.get())) {
    LOG(ERROR) << "Unable to create TPM initialization background thread.";
    return false;
  }
  return true;
}

bool TpmInit::IsTpmReady() {
  return tpm_init_->IsTpmReady();
}

bool TpmInit::IsTpmEnabled() {
  return tpm_init_->IsTpmEnabled();
}

bool TpmInit::GetTpmPassword(chromeos::Blob* password) {
  return tpm_init_->GetTpmPassword(password);
}

long TpmInit::GetInitializationMillis() {
  return tpm_init_->GetInitializationMillis();
}

TpmInitTask::TpmInitTask()
    : default_tpm_(new tpm_init::Tpm()),
      tpm_(default_tpm_.get()),
      initialize_status_(false),
      task_done_(false),
      initialization_time_(-1) {
}

TpmInitTask::~TpmInitTask() {
}

void TpmInitTask::Init() {
  tpm_->Init();
}

void TpmInitTask::ThreadMain() {
  base::TimeTicks start = base::TimeTicks::Now();
  initialize_status_ = tpm_->InitializeTpm();
  base::TimeDelta delta = (base::TimeTicks::Now() - start);
  initialization_time_ = delta.InMilliseconds();
  if (initialize_status_) {
    LOG(ERROR) << "TPM initialization took " << initialization_time_ << "ms";
  }
  task_done_ = true;
}

bool TpmInitTask::IsTpmReady() {
  // The TPM is not "ready" if the init call has not completed.  It may be in
  // the middle of taking ownership.
  if (!task_done_) {
    return false;
  }
  // If initialize_status_ is true, then the TPM went through a full succesful
  // ownership cycle in InitializeTpm()
  if (initialize_status_) {
    return true;
  }
  // If we get here, then the call to InitializeTpm() is complete and it
  // returned false.  That merely means that it did not successfully take
  // ownership, which is the common case after ownership is established on OOBE.
  // In that case, the TPM is ready if it is enabled and owned.
  return (tpm_->IsEnabled() && tpm_->IsOwned());
}

bool TpmInitTask::IsTpmEnabled() {
  return tpm_->IsEnabled();
}

bool TpmInitTask::GetTpmPassword(chromeos::Blob* password) {
  return tpm_->GetOwnerPassword(password);
}

long TpmInitTask::GetInitializationMillis() {
  return initialization_time_;
}

bool TpmInitTask::GetRandomData(int length, chromeos::Blob* data) {
  return tpm_->GetRandomData(length, data);
}

}  // namespace tpm_init
