// Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Contains the implementation of class Tpm

#include "tpm.h"

#include <base/file_util.h>
#include <base/platform_thread.h>
#include <base/time.h>
#include <openssl/rsa.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>

namespace tpm_init {

const char* kWellKnownSrkTmp = "1234567890";
const int kOwnerPasswordLength = 12;
const int kMaxTimeoutRetries = 5;
const char* kTpmCheckEnabledFile = "/sys/class/misc/tpm0/device/enabled";
const char* kTpmCheckOwnedFile = "/sys/class/misc/tpm0/device/owned";
const char* kTpmOwnedFile = "/var/lib/.tpm_owned";
const char* kOpenCryptokiPath = "/var/lib/opencryptoki";
const int kTpmConnectRetries = 10;
const int kTpmConnectIntervalMs = 100;

Tpm::Tpm()
    : context_handle_(0),
      default_crypto_(new Crypto()),
      crypto_(default_crypto_.get()),
      owner_password_(),
      password_sync_lock_(),
      is_disabled_(true),
      is_owned_(false) {
}

Tpm::~Tpm() {
  Disconnect();
}

bool Tpm::Init() {
  // Checking disabled and owned either via sysfs or via TSS calls will block if
  // ownership is being taken by another thread or process.  So for this to work
  // well, Tpm::Init() needs to be called before InitializeTpm() is called.  At
  // that point, the public API for Tpm only checks these booleans, so other
  // threads can check without being blocked.  InitializeTpm() will reset the
  // is_owned_ bit on success.
  is_disabled_ = IsDisabledCheckViaSysfs();
  is_owned_ = IsOwnedCheckViaSysfs();
  return true;
}

bool Tpm::Connect() {
  if (context_handle_ == 0) {
    TSS_HCONTEXT context_handle;
    if (!OpenAndConnectTpm(&context_handle)) {
      return false;
    }

    context_handle_ = context_handle;
  }

  return true;
}

bool Tpm::IsConnected() {
  return (context_handle_ != 0);
}

void Tpm::Disconnect() {
  if (context_handle_) {
    Tspi_Context_Close(context_handle_);
    context_handle_ = 0;
  }
}

int Tpm::GetMaxRsaKeyCount() {
  if (context_handle_ == 0) {
    return -1;
  }

  return GetMaxRsaKeyCountForContext(context_handle_);
}

int Tpm::GetMaxRsaKeyCountForContext(TSS_HCONTEXT context_handle) {
  int count = -1;
  TSS_RESULT result;
  TSS_HTPM tpm_handle;
  if (!GetTpm(context_handle, &tpm_handle)) {
    return count;
  }

  UINT32 cap_length = 0;
  BYTE* cap = NULL;
  UINT32 subcap = TSS_TPMCAP_PROP_MAXKEYS;
  if ((result = Tspi_TPM_GetCapability(tpm_handle, TSS_TPMCAP_PROPERTY,
                                       sizeof(subcap),
                                       reinterpret_cast<BYTE*>(&subcap),
                                       &cap_length, &cap))) {
    LOG(ERROR) << "Error calling Tspi_TPM_GetCapability: " << result;
    return count;
  }
  if (cap_length == sizeof(int)) {
    count = *(reinterpret_cast<int*>(cap));
  }
  Tspi_Context_FreeMemory(context_handle, cap);
  return count;
}

bool Tpm::OpenAndConnectTpm(TSS_HCONTEXT* context_handle) {
  TSS_RESULT result;
  TSS_HCONTEXT local_context_handle;
  if ((result = Tspi_Context_Create(&local_context_handle))) {
    LOG(ERROR) << "Error calling Tspi_Context_Create";
    return false;
  }

  for (int i = 0; i < kTpmConnectRetries; i++) {
    if ((result = Tspi_Context_Connect(local_context_handle, NULL))) {
      if (result == TSS_E_COMM_FAILURE) {
        PlatformThread::Sleep(kTpmConnectIntervalMs);
      } else {
        LOG(ERROR) << "Error calling Tspi_Context_Connect: " << result;
        Tspi_Context_Close(local_context_handle);
        return false;
      }
    } else {
      break;
    }
  }

  if (result) {
    LOG(ERROR) << "Error calling Tspi_Context_Connect: " << result;
    Tspi_Context_Close(local_context_handle);
    return false;
  }

  *context_handle = local_context_handle;
  return true;
}

bool Tpm::IsDisabledCheckViaSysfs() {
  std::string contents;
  if (!file_util::ReadFileToString(FilePath(kTpmCheckEnabledFile), &contents)) {
    return false;
  }
  if (contents.size() < 1) {
    return false;
  }
  return (contents[0] == '0');
}

bool Tpm::IsOwnedCheckViaSysfs() {
  std::string contents;
  if (!file_util::ReadFileToString(FilePath(kTpmCheckOwnedFile), &contents)) {
    return false;
  }
  if (contents.size() < 1) {
    return false;
  }
  return (contents[0] != '0');
}

bool Tpm::IsDisabledCheckViaContext(TSS_HCONTEXT context_handle) {
  bool value = true;
  TSS_RESULT result;
  TSS_HTPM tpm_handle;
  if (!GetTpm(context_handle, &tpm_handle)) {
    return value;
  }

  UINT32 cap_length = 0;
  BYTE* cap = NULL;
  if ((result = Tspi_TPM_GetCapability(tpm_handle, TSS_TPMCAP_FLAG,
                                       0, NULL, &cap_length, &cap))) {
    LOG(ERROR) << "Error calling Tspi_TPM_GetCapability: " << result;
    return value;
  }
  if (cap_length >= (2 * sizeof(int))) {
    value = (((*(reinterpret_cast<int*>(cap))) & TPM_PF_DISABLE) != 0);
  }
  Tspi_Context_FreeMemory(context_handle, cap);
  return value;
}

bool Tpm::IsOwnedCheckViaContext(TSS_HCONTEXT context_handle) {
  bool value = true;
  TSS_RESULT result;
  TSS_HTPM tpm_handle;
  if (!GetTpm(context_handle, &tpm_handle)) {
    LOG(ERROR) << "Error calling Tspi_Context_GetTpmObject: " << result;
    return value;
  }

  UINT32 cap_length = 0;
  BYTE* cap = NULL;
  if ((result = Tspi_TPM_GetCapability(tpm_handle, TSS_TPMCAP_FLAG,
                                       0, NULL, &cap_length, &cap))) {
    LOG(ERROR) << "Error calling Tspi_TPM_GetCapability: " << result;
    return value;
  }
  if (cap_length >= (2 * sizeof(int))) {
    value = (((*(reinterpret_cast<int*>(cap))) & TPM_PF_OWNERSHIP) != 0);
  }
  Tspi_Context_FreeMemory(context_handle, cap);
  return value;
}

bool Tpm::CreateEndorsementKey(TSS_HCONTEXT context_handle) {
  TSS_RESULT result;
  TSS_HTPM tpm_handle;
  if (!GetTpm(context_handle, &tpm_handle)) {
    return false;
  }

  TSS_HKEY local_key_handle;
  TSS_FLAG init_flags = TSS_KEY_TYPE_LEGACY | TSS_KEY_SIZE_2048;
  if ((result = Tspi_Context_CreateObject(context_handle,
                                          TSS_OBJECT_TYPE_RSAKEY,
                                          init_flags, &local_key_handle))) {
    LOG(ERROR) << "Error calling Tspi_Context_CreateObject: " << result;
    return false;
  }

  if ((result = Tspi_TPM_CreateEndorsementKey(tpm_handle, local_key_handle,
                                              NULL))) {
    LOG(ERROR) << "Error calling Tspi_TPM_CreateEndorsementKey: " << result;
    Tspi_Context_CloseObject(context_handle, local_key_handle);
    return false;
  }

  return true;
}

bool Tpm::IsEndorsementKeyAvailable(TSS_HCONTEXT context_handle) {
  TSS_RESULT result;
  TSS_HTPM tpm_handle;
  if (!GetTpm(context_handle, &tpm_handle)) {
    return false;
  }

  TSS_HKEY local_key_handle;
  if ((result = Tspi_TPM_GetPubEndorsementKey(tpm_handle, false, NULL,
                                              &local_key_handle))) {
    LOG(ERROR) << "Error calling Tspi_Context_CreateObject: " << result;
    return false;
  }

  Tspi_Context_CloseObject(context_handle, local_key_handle);

  return true;
}

void Tpm::CreateOwnerPassword(SecureBlob* password) {
  SecureBlob random(kOwnerPasswordLength);
  crypto_->GetSecureRandom(static_cast<unsigned char*>(random.data()),
                           random.size());
  SecureBlob tpm_password(kOwnerPasswordLength);
  crypto_->AsciiEncodeToBuffer(random, static_cast<char*>(tpm_password.data()),
                               tpm_password.size());
  password->swap(tpm_password);
}

bool Tpm::TakeOwnership(TSS_HCONTEXT context_handle, int max_timeout_tries) {
  SecureBlob owner_password;
  CreateOwnerPassword(&owner_password);

  TSS_RESULT result;
  TSS_HTPM tpm_handle;
  if (!GetTpmWithAuth(context_handle, owner_password, &tpm_handle)) {
    return false;
  }

  TSS_HKEY srk_handle;
  TSS_FLAG init_flags = TSS_KEY_TSP_SRK | TSS_KEY_AUTHORIZATION;
  if ((result = Tspi_Context_CreateObject(context_handle,
                                          TSS_OBJECT_TYPE_RSAKEY,
                                          init_flags, &srk_handle))) {
    LOG(ERROR) << "Error calling Tspi_Context_CreateObject: " << result;
    return false;
  }

  TSS_HPOLICY srk_usage_policy;
  if ((result = Tspi_GetPolicyObject(srk_handle, TSS_POLICY_USAGE,
                                     &srk_usage_policy))) {
    LOG(ERROR) << "Error calling Tspi_GetPolicyObject: " << result;
    Tspi_Context_CloseObject(context_handle, srk_handle);
    return false;
  }

  if ((result = Tspi_Policy_SetSecret(srk_usage_policy,
      TSS_SECRET_MODE_PLAIN,
      strlen(kWellKnownSrkTmp),
      const_cast<BYTE *>(reinterpret_cast<const BYTE *>(kWellKnownSrkTmp))))) {
    LOG(ERROR) << "Error calling Tspi_Policy_SetSecret: " << result;
    Tspi_Context_CloseObject(context_handle, srk_handle);
    return false;
  }

  int retry_count = 0;
  do {
    result = Tspi_TPM_TakeOwnership(tpm_handle, srk_handle, 0);
    retry_count++;
  } while(((result == TDDL_E_TIMEOUT) ||
           (result == (TSS_LAYER_TDDL | TDDL_E_TIMEOUT)) ||
           (result == (TSS_LAYER_TDDL | TDDL_E_IOERROR))) &&
          (retry_count < max_timeout_tries));

  if (result) {
    LOG(ERROR) << "Error calling Tspi_TPM_TakeOwnership: " << result
               << ", attempts: " << retry_count;
    Tspi_Context_CloseObject(context_handle, srk_handle);
    return false;
  }

  Tspi_Context_CloseObject(context_handle, srk_handle);

  password_sync_lock_.Acquire();
  owner_password_.swap(owner_password);
  password_sync_lock_.Release();

  return true;
}

bool Tpm::ZeroSrkPassword(TSS_HCONTEXT context_handle,
                          const SecureBlob& owner_password) {
  TSS_RESULT result;
  TSS_HTPM tpm_handle;
  if (!GetTpmWithAuth(context_handle, owner_password, &tpm_handle)) {
    return false;
  }

  TSS_HKEY srk_handle;
  TSS_UUID SRK_UUID = TSS_UUID_SRK;
  if ((result = Tspi_Context_LoadKeyByUUID(context_handle, TSS_PS_TYPE_SYSTEM,
                                           SRK_UUID, &srk_handle))) {
    LOG(ERROR) << "Couldn't load SRK: " << result;
    return false;
  }

  TSS_HPOLICY policy_handle;
  if ((result = Tspi_Context_CreateObject(context_handle,
                                          TSS_OBJECT_TYPE_POLICY,
                                          TSS_POLICY_USAGE,
                                          &policy_handle))) {
    LOG(ERROR) << "Error creating policy object: " << result;
    Tspi_Context_CloseObject(context_handle, srk_handle);
    return false;
  }

  BYTE new_password[0];
  if ((result = Tspi_Policy_SetSecret(policy_handle, TSS_SECRET_MODE_PLAIN,
                                      0, new_password))) {
    LOG(ERROR) << "Error setting srk password: " << result;
    Tspi_Context_CloseObject(context_handle, policy_handle);
    Tspi_Context_CloseObject(context_handle, srk_handle);
    return false;
  }

  if ((result = Tspi_ChangeAuth(srk_handle,
                                tpm_handle,
                                policy_handle))) {
    LOG(ERROR) << "Error creating policy object: " << result;
    Tspi_Context_CloseObject(context_handle, policy_handle);
    Tspi_Context_CloseObject(context_handle, srk_handle);
    return false;
  }

  Tspi_Context_CloseObject(context_handle, policy_handle);
  Tspi_Context_CloseObject(context_handle, srk_handle);
  return true;
}

bool Tpm::UnrestrictSrk(TSS_HCONTEXT context_handle,
                          const SecureBlob& owner_password) {
  TSS_RESULT result;
  TSS_HTPM tpm_handle;
  if (!GetTpmWithAuth(context_handle, owner_password, &tpm_handle)) {
    return false;
  }

  if ((result = Tspi_TPM_SetStatus(tpm_handle,
                                   TSS_TPMSTATUS_DISABLEPUBSRKREAD,
                                   false))) {
    LOG(ERROR) << "Error calling Tspi_TPM_SetStatus: " << result;
    return false;
  }

  return true;
}

bool Tpm::GetTpm(TSS_HCONTEXT context_handle, TSS_HTPM* tpm_handle) {
  TSS_RESULT result;
  TSS_HTPM local_tpm_handle;
  if ((result = Tspi_Context_GetTpmObject(context_handle, &local_tpm_handle))) {
    LOG(ERROR) << "Error calling Tspi_Context_GetTpmObject: " << result;
    return false;
  }

  *tpm_handle = local_tpm_handle;
  return true;
}

bool Tpm::GetTpmWithAuth(TSS_HCONTEXT context_handle,
                         const SecureBlob& owner_password,
                         TSS_HTPM* tpm_handle) {
  TSS_RESULT result;
  TSS_HTPM local_tpm_handle;
  if (!GetTpm(context_handle, &local_tpm_handle)) {
    LOG(ERROR) << "Error getting TPM handle";
    return false;
  }

  TSS_HPOLICY tpm_usage_policy;
  if ((result = Tspi_GetPolicyObject(local_tpm_handle, TSS_POLICY_USAGE,
                                     &tpm_usage_policy))) {
    LOG(ERROR) << "Error calling Tspi_GetPolicyObject: " << result;
    return false;
  }

  if ((result = Tspi_Policy_SetSecret(tpm_usage_policy, TSS_SECRET_MODE_PLAIN,
      owner_password.size(),
      const_cast<BYTE *>(static_cast<const BYTE *>(
          owner_password.const_data()))))) {
    LOG(ERROR) << "Error calling Tspi_Policy_SetSecret: " << result;
    return false;
  }

  *tpm_handle = local_tpm_handle;
  return true;
}

bool Tpm::GetOwnerPassword(chromeos::Blob* owner_password) {
  bool result = false;
  if (password_sync_lock_.Try()) {
    if (owner_password_.size() != 0) {
      owner_password->assign(owner_password_.begin(), owner_password_.end());
      result = true;
    }
    password_sync_lock_.Release();
  }
  return result;
}

bool Tpm::InitializeTpm() {
  if (!IsConnected()) {
    Connect();
  }

  if (!IsConnected()) {
    LOG(ERROR) << "Failed to connect to TPM";
    return false;
  }

  if (is_disabled_) {
    LOG(ERROR) << "Error TPM is disabled";
    return false;
  }

  if (is_owned_) {
    return false;
  }

  file_util::Delete(FilePath(kOpenCryptokiPath), true);
  file_util::Delete(FilePath(kTpmOwnedFile), false);

  if (!IsEndorsementKeyAvailable(context_handle_)) {
    if (!CreateEndorsementKey(context_handle_)) {
      LOG(ERROR) << "Failed to create endorsement key";
      return false;
    }
  }

  if (!IsEndorsementKeyAvailable(context_handle_)) {
    LOG(ERROR) << "Endorsement key is not available";
    return false;
  }

  if (!TakeOwnership(context_handle_, kMaxTimeoutRetries)) {
    LOG(ERROR) << "Take Ownership failed";
    return false;
  }

  SecureBlob owner_password;
  password_sync_lock_.Acquire();
  owner_password.assign(owner_password_.begin(), owner_password_.end());
  password_sync_lock_.Release();

  if (!ZeroSrkPassword(context_handle_, owner_password)) {
    LOG(ERROR) << "Couldn't zero SRK password";
    return false;
  }

  if (!UnrestrictSrk(context_handle_, owner_password)) {
    LOG(ERROR) << "Couldn't unrestrict the SRK";
    return false;
  }

  is_owned_ = true;

  file_util::WriteFile(FilePath(kTpmOwnedFile), NULL, 0);

 return true;
}

} // namespace tpm_init
