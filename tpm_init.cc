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

  void Init(TpmInit::TpmInitCallback* notify_callback);

  virtual void ThreadMain();

  bool IsTpmReady();
  bool IsTpmEnabled();
  bool IsTpmOwned();
  bool IsTpmBeingOwned();
  bool GetTpmPassword(chromeos::Blob* password);
  long GetInitializationMillis();
  bool GetRandomData(int length, chromeos::Blob* data);

 private:
  scoped_ptr<tpm_init::Tpm> default_tpm_;
  tpm_init::Tpm* tpm_;
  bool initialize_took_ownership_;
  bool task_done_;
  long initialization_time_;
  TpmInit::TpmInitCallback* notify_callback_;
};

TpmInit::TpmInit()
    : tpm_init_task_(new TpmInitTask()),
      notify_callback_(NULL) {
}

TpmInit::~TpmInit() {
}

void TpmInit::Init(TpmInitCallback* notify_callback) {
  notify_callback_ = notify_callback;
}

bool TpmInit::GetRandomData(int length, chromeos::Blob* data) {
  return tpm_init_task_->GetRandomData(length, data);
}

bool TpmInit::StartInitializeTpm() {
  tpm_init_task_->Init(notify_callback_);
  if (!PlatformThread::CreateNonJoinable(0, tpm_init_task_.get())) {
    LOG(ERROR) << "Unable to create TPM initialization background thread.";
    return false;
  }
  return true;
}

bool TpmInit::IsTpmReady() {
  return tpm_init_task_->IsTpmReady();
}

bool TpmInit::IsTpmEnabled() {
  return tpm_init_task_->IsTpmEnabled();
}

bool TpmInit::IsTpmOwned() {
  return tpm_init_task_->IsTpmOwned();
}

bool TpmInit::IsTpmBeingOwned() {
  return tpm_init_task_->IsTpmBeingOwned();
}

bool TpmInit::GetTpmPassword(chromeos::Blob* password) {
  return tpm_init_task_->GetTpmPassword(password);
}

long TpmInit::GetInitializationMillis() {
  return tpm_init_task_->GetInitializationMillis();
}

TpmInitTask::TpmInitTask()
    : default_tpm_(new tpm_init::Tpm()),
      tpm_(default_tpm_.get()),
      initialize_took_ownership_(false),
      task_done_(false),
      initialization_time_(-1),
      notify_callback_(NULL) {
}

TpmInitTask::~TpmInitTask() {
}

void TpmInitTask::Init(TpmInit::TpmInitCallback* notify_callback) {
  notify_callback_ = notify_callback;
  tpm_->Init();
}

void TpmInitTask::ThreadMain() {
  base::TimeTicks start = base::TimeTicks::Now();
  bool initialize_result = tpm_->InitializeTpm(&initialize_took_ownership_);
  base::TimeDelta delta = (base::TimeTicks::Now() - start);
  initialization_time_ = delta.InMilliseconds();
  if (initialize_took_ownership_) {
    LOG(ERROR) << "TPM initialization took " << initialization_time_ << "ms";
  }
  task_done_ = true;
  if (notify_callback_) {
    notify_callback_->InitializeTpmComplete(initialize_result,
                                            initialize_took_ownership_);
  }
}

bool TpmInitTask::IsTpmReady() {
  // The TPM is not "ready" if the init call has not completed.  It may be in
  // the middle of taking ownership.
  if (!task_done_) {
    return false;
  }
  // If initialize_took_ownership_ is true, then the TPM went through a full
  // succesful ownership cycle in InitializeTpm()
  if (initialize_took_ownership_) {
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

bool TpmInitTask::IsTpmOwned() {
  return tpm_->IsOwned();
}

bool TpmInitTask::IsTpmBeingOwned() {
  return tpm_->IsBeingOwned();
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
