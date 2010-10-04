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
#define TPM_LOG(severity, result) \
  LOG(severity) << "TPM error 0x" << std::hex << result \
                << " (" << Trspi_Error_String(result) << "): "


const char* kWellKnownSrkTmp = "1234567890";
const int kOwnerPasswordLength = 12;
const int kMaxTimeoutRetries = 5;
const char* kTpmCheckEnabledFile = "/sys/class/misc/tpm0/device/enabled";
const char* kTpmCheckOwnedFile = "/sys/class/misc/tpm0/device/owned";
const char* kTpmOwnedFile = "/var/lib/.tpm_owned";
const char* kTpmStatusFile = "/var/lib/.tpm_status";
const char* kOpenCryptokiPath = "/var/lib/opencryptoki";
const int kTpmConnectRetries = 10;
const int kTpmConnectIntervalMs = 100;
const char kTpmWellKnownPassword[] = TSS_WELL_KNOWN_SECRET;
const char kTpmOwnedWithWellKnown = 'W';
const char kTpmOwnedWithRandom = 'R';

Tpm::Tpm()
    : default_crypto_(new Crypto()),
      crypto_(default_crypto_.get()),
      default_platform_(new Platform()),
      platform_(default_platform_.get()),
      owner_password_(),
      password_sync_lock_(),
      is_disabled_(true),
      is_owned_(false),
      is_srk_available_(false),
      is_being_owned_(false) {
}

Tpm::~Tpm() {
}

bool Tpm::Init() {
  // Checking disabled and owned either via sysfs or via TSS calls will block if
  // ownership is being taken by another thread or process.  So for this to work
  // well, Tpm::Init() needs to be called before InitializeTpm() is called.  At
  // that point, the public API for Tpm only checks these booleans, so other
  // threads can check without being blocked.  InitializeTpm() will reset the
  // is_owned_ bit on success.
  bool successful_check = false;
  if (file_util::PathExists(FilePath(kTpmCheckEnabledFile))) {
    is_disabled_ = IsDisabledCheckViaSysfs();
    is_owned_ = IsOwnedCheckViaSysfs();
    successful_check = true;
  } else {
    TSS_HCONTEXT context_handle;
    if (OpenAndConnectTpm(&context_handle)) {
      bool enabled = false;
      bool owned = false;
      IsEnabledOwnedCheckViaContext(context_handle, &enabled, &owned);
      is_disabled_ = !enabled;
      is_owned_ = owned;
      Tspi_Context_Close(context_handle);
      successful_check = true;
    }
  }
  if (successful_check && !is_owned_) {
    file_util::Delete(FilePath(kOpenCryptokiPath), true);
    file_util::Delete(FilePath(kTpmOwnedFile), false);
    file_util::Delete(FilePath(kTpmStatusFile), false);
  }
  TpmStatus tpm_status;
  if (LoadTpmStatus(&tpm_status)) {
    if (tpm_status.has_owner_password()) {
      SecureBlob local_owner_password;
      if (LoadOwnerPassword(tpm_status, &local_owner_password)) {
        password_sync_lock_.Acquire();
        owner_password_.assign(local_owner_password.begin(),
                               local_owner_password.end());
        password_sync_lock_.Release();
      }
    }
  }

  return true;
}

TSS_HCONTEXT Tpm::Connect() {
  TSS_HCONTEXT context_handle;
  if (!OpenAndConnectTpm(&context_handle)) {
    return NULL;
  }

  return context_handle;
}

void Tpm::Disconnect(TSS_HCONTEXT context_handle) {
  if (context_handle) {
    Tspi_Context_Close(context_handle);
  }
}

int Tpm::GetMaxRsaKeyCount() {
  TSS_HCONTEXT context_handle = Connect();
  if (!context_handle) {
    return -1;
  }
  int count = GetMaxRsaKeyCountForContext(context_handle);
  Disconnect(context_handle);
  return count;
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
    TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_GetCapability";
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
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_Create";
    return false;
  }

  for (int i = 0; i < kTpmConnectRetries; i++) {
    if ((result = Tspi_Context_Connect(local_context_handle, NULL))) {
      if (result == TSS_E_COMM_FAILURE) {
        PlatformThread::Sleep(kTpmConnectIntervalMs);
      } else {
        TPM_LOG(ERROR, result) << "Error calling Tspi_Context_Connect";
        Tspi_Context_Close(local_context_handle);
        return false;
      }
    } else {
      break;
    }
  }

  if (result) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_Connect";
    Tspi_Context_Close(local_context_handle);
    return false;
  }

  *context_handle = local_context_handle;
  return true;
}

void Tpm::IsEnabledOwnedCheckViaContext(TSS_HCONTEXT context_handle,
                                        bool* enabled, bool* owned) {
  *enabled = false;
  *owned = false;

  TSS_RESULT result;
  TSS_HTPM tpm_handle;
  if (!GetTpm(context_handle, &tpm_handle)) {
    return;
  }

  UINT32 sub_cap = TSS_TPMCAP_PROP_OWNER;
  UINT32 cap_length = 0;
  BYTE* cap = NULL;
  if ((result = Tspi_TPM_GetCapability(tpm_handle, TSS_TPMCAP_PROPERTY,
                                       sizeof(sub_cap),
                                       reinterpret_cast<BYTE*>(&sub_cap),
                                       &cap_length, &cap)) == 0) {
    if (cap_length >= (sizeof(TSS_BOOL))) {
      *enabled = true;
      *owned = ((*(reinterpret_cast<TSS_BOOL*>(cap))) != 0);
    }
    Tspi_Context_FreeMemory(context_handle, cap);
  } else if(ERROR_CODE(result) == TPM_E_DISABLED) {
    *enabled = false;
  }
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
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_CreateObject";
    return false;
  }

  if ((result = Tspi_TPM_CreateEndorsementKey(tpm_handle, local_key_handle,
                                              NULL))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_CreateEndorsementKey";
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
    TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_GetPubEndorsementKey";
    return false;
  }

  Tspi_Context_CloseObject(context_handle, local_key_handle);

  return true;
}

void Tpm::CreateOwnerPassword(SecureBlob* password) {
  // Generate a random owner password.  The default is a 12-character,
  // hex-encoded password created from 6 bytes of random data.
  SecureBlob random(kOwnerPasswordLength / 2);
  crypto_->GetSecureRandom(static_cast<unsigned char*>(random.data()),
                           random.size());
  SecureBlob tpm_password(kOwnerPasswordLength);
  crypto_->AsciiEncodeToBuffer(random, static_cast<char*>(tpm_password.data()),
                               tpm_password.size());
  password->swap(tpm_password);
}

bool Tpm::TakeOwnership(TSS_HCONTEXT context_handle, int max_timeout_tries,
                        const SecureBlob& owner_password) {
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
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_CreateObject";
    return false;
  }

  TSS_HPOLICY srk_usage_policy;
  if ((result = Tspi_GetPolicyObject(srk_handle, TSS_POLICY_USAGE,
                                     &srk_usage_policy))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_GetPolicyObject";
    Tspi_Context_CloseObject(context_handle, srk_handle);
    return false;
  }

  if ((result = Tspi_Policy_SetSecret(srk_usage_policy,
      TSS_SECRET_MODE_PLAIN,
      strlen(kWellKnownSrkTmp),
      const_cast<BYTE *>(reinterpret_cast<const BYTE *>(kWellKnownSrkTmp))))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Policy_SetSecret";
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
    TPM_LOG(ERROR, result)
        << "Error calling Tspi_TPM_TakeOwnership, attempts: " << retry_count;
    Tspi_Context_CloseObject(context_handle, srk_handle);
    return false;
  }

  Tspi_Context_CloseObject(context_handle, srk_handle);

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
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_LoadKeyByUUID";
    return false;
  }

  TSS_HPOLICY policy_handle;
  if ((result = Tspi_Context_CreateObject(context_handle,
                                          TSS_OBJECT_TYPE_POLICY,
                                          TSS_POLICY_USAGE,
                                          &policy_handle))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_CreateObject";
    Tspi_Context_CloseObject(context_handle, srk_handle);
    return false;
  }

  BYTE new_password[0];
  if ((result = Tspi_Policy_SetSecret(policy_handle, TSS_SECRET_MODE_PLAIN,
                                      0, new_password))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Policy_SetSecret";
    Tspi_Context_CloseObject(context_handle, policy_handle);
    Tspi_Context_CloseObject(context_handle, srk_handle);
    return false;
  }

  if ((result = Tspi_ChangeAuth(srk_handle,
                                tpm_handle,
                                policy_handle))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_ChangeAuth";
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

  TSS_BOOL current_status = false;

  if ((result = Tspi_TPM_GetStatus(tpm_handle,
                                   TSS_TPMSTATUS_DISABLEPUBSRKREAD,
                                   &current_status))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_GetStatus";
    return false;
  }

  // If it is currently owner auth (true), set it to SRK auth
  if (current_status) {
    if ((result = Tspi_TPM_SetStatus(tpm_handle,
                                     TSS_TPMSTATUS_DISABLEPUBSRKREAD,
                                     false))) {
      TPM_LOG(ERROR, result) << "Error calling Tspi_TPM_SetStatus";
      return false;
    }
  }

  return true;
}

bool Tpm::ChangeOwnerPassword(TSS_HCONTEXT context_handle,
                              const SecureBlob& previous_owner_password,
                              const SecureBlob& owner_password) {
  TSS_RESULT result;
  TSS_HTPM tpm_handle;
  if (!GetTpmWithAuth(context_handle, previous_owner_password, &tpm_handle)) {
    return false;
  }

  TSS_HPOLICY policy_handle;
  if ((result = Tspi_Context_CreateObject(context_handle,
                                          TSS_OBJECT_TYPE_POLICY,
                                          TSS_POLICY_USAGE,
                                          &policy_handle))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_CreateObject";
    return false;
  }

  if ((result = Tspi_Policy_SetSecret(policy_handle,
      TSS_SECRET_MODE_PLAIN,
      owner_password.size(),
      const_cast<BYTE *>(static_cast<const BYTE *>(
          owner_password.const_data()))))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Policy_SetSecret";
    Tspi_Context_CloseObject(context_handle, policy_handle);
    return false;
  }

  if ((result = Tspi_ChangeAuth(tpm_handle, 0, policy_handle))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_ChangeAuth";
    Tspi_Context_CloseObject(context_handle, policy_handle);
    return false;
  }

  Tspi_Context_CloseObject(context_handle, policy_handle);
  return true;
}

// TODO(fes): This method is borrowed from cryptohome.  When the tpm_init
// library is merged into cryptohome, these duplicate methods need to be
// removed.  Either that, or they should be moved into a separate library.
bool Tpm::LoadFileBytes(const FilePath& path, chromeos::Blob* blob) {
  int64 file_size;
  if (!file_util::PathExists(path)) {
    return false;
  }
  if (!file_util::GetFileSize(path, &file_size)) {
    LOG(ERROR) << "Could not get size of " << path.value();
    return false;
  }
  // Compare to the max of a 32-bit signed integer
  if (file_size > static_cast<int64>(INT_MAX)) {
    LOG(ERROR) << "File " << path.value() << " is too large: " << file_size;
    return false;
  }
  SecureBlob buf(file_size);
  int data_read = file_util::ReadFile(path, reinterpret_cast<char*>(&buf[0]),
                                      file_size);
  // Cast is okay because of comparison to INT_MAX above
  if (data_read != static_cast<int>(file_size)) {
    LOG(ERROR) << "Could not read entire file " << file_size;
    return false;
  }
  blob->swap(buf);
  return true;
}

bool Tpm::LoadOwnerPassword(const TpmStatus& tpm_status,
                            chromeos::Blob* owner_password) {
  if (!(tpm_status.flags() & TpmStatus::OWNED_BY_THIS_INSTALL)) {
    return false;
  }
  if ((tpm_status.flags() & TpmStatus::USES_WELL_KNOWN_OWNER)) {
    SecureBlob default_owner_password(sizeof(kTpmWellKnownPassword));
    memcpy(default_owner_password.data(), kTpmWellKnownPassword,
           sizeof(kTpmWellKnownPassword));
    owner_password->swap(default_owner_password);
    return true;
  }
  if (!(tpm_status.flags() & TpmStatus::USES_RANDOM_OWNER) ||
      !tpm_status.has_owner_password()) {
    return false;
  }

  TSS_HCONTEXT context_handle;
  if (!OpenAndConnectTpm(&context_handle)) {
    return false;
  }

  TSS_RESULT result;
  TSS_HKEY srk_handle;
  if (!LoadSrk(context_handle, &srk_handle, &result)) {
    LOG(ERROR) << "Error loading the SRK";
    Tspi_Context_Close(context_handle);
    return false;
  }

  TSS_FLAG init_flags = TSS_ENCDATA_SEAL;
  TSS_HKEY enc_handle;
  if ((result = Tspi_Context_CreateObject(context_handle,
                                          TSS_OBJECT_TYPE_ENCDATA,
                                          init_flags, &enc_handle))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_CreateObject";
    Tspi_Context_CloseObject(context_handle, srk_handle);
    Tspi_Context_Close(context_handle);
    return false;
  }

  SecureBlob local_owner_password(tpm_status.owner_password().length());
  tpm_status.owner_password().copy(
      static_cast<char*>(local_owner_password.data()),
      tpm_status.owner_password().length(), 0);

  if ((result = Tspi_SetAttribData(enc_handle,
      TSS_TSPATTRIB_ENCDATA_BLOB,
      TSS_TSPATTRIB_ENCDATABLOB_BLOB,
      local_owner_password.size(),
      static_cast<BYTE *>(local_owner_password.data())))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_SetAttribData";
    Tspi_Context_CloseObject(context_handle, enc_handle);
    Tspi_Context_CloseObject(context_handle, srk_handle);
    Tspi_Context_Close(context_handle);
    return false;
  }

  unsigned char* dec_data = NULL;
  UINT32 dec_data_length = 0;
  if ((result = Tspi_Data_Unseal(enc_handle, srk_handle, &dec_data_length,
                                 &dec_data))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Data_Unseal";
    Tspi_Context_CloseObject(context_handle, enc_handle);
    Tspi_Context_CloseObject(context_handle, srk_handle);
    Tspi_Context_Close(context_handle);
    return false;
  }

  Tspi_Context_CloseObject(context_handle, enc_handle);

  SecureBlob local_data(dec_data_length);
  memcpy(static_cast<char*>(local_data.data()), dec_data, dec_data_length);
  Tspi_Context_FreeMemory(context_handle, dec_data);

  Tspi_Context_CloseObject(context_handle, srk_handle);
  Tspi_Context_Close(context_handle);

  owner_password->swap(local_data);

  return true;
}

bool Tpm::StoreOwnerPassword(const chromeos::Blob& owner_password,
                             TpmStatus* tpm_status) {
  TSS_HCONTEXT context_handle;
  if (!OpenAndConnectTpm(&context_handle)) {
    return false;
  }

  TSS_RESULT result;
  TSS_HKEY srk_handle;
  if (!LoadSrk(context_handle, &srk_handle, &result)) {
    LOG(ERROR) << "Error loading the SRK";
    Tspi_Context_Close(context_handle);
    return false;
  }

  // Check the SRK public key
  unsigned int size_n;
  BYTE *public_srk;
  if ((result = Tspi_Key_GetPubKey(srk_handle, &size_n, &public_srk))) {
    TPM_LOG(ERROR, result) << "Unable to get the SRK public key";
    Tspi_Context_CloseObject(context_handle, srk_handle);
    Tspi_Context_Close(context_handle);
    return false;
  }
  Tspi_Context_FreeMemory(context_handle, public_srk);

  TSS_HTPM tpm_handle;
  if (!GetTpm(context_handle, &tpm_handle)) {
    LOG(ERROR) << "Unable to get a handle to the TPM";
    Tspi_Context_CloseObject(context_handle, srk_handle);
    Tspi_Context_Close(context_handle);
    return false;
  }

  // Use PCR0 when sealing the data so that the owner password is only
  // available in the current boot mode.  This helps protect the password from
  // offline attacks until it has been presented and cleared.
  TSS_HPCRS pcrs_handle;
  if ((result = Tspi_Context_CreateObject(context_handle, TSS_OBJECT_TYPE_PCRS,
                                          0, &pcrs_handle))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_CreateObject";
    Tspi_Context_CloseObject(context_handle, srk_handle);
    Tspi_Context_Close(context_handle);
    return false;
  }

  UINT32 pcr_len;
  BYTE* pcr_value;
  Tspi_TPM_PcrRead(tpm_handle, 0, &pcr_len, &pcr_value);
  Tspi_PcrComposite_SetPcrValue(pcrs_handle, 0, pcr_len, pcr_value);
  Tspi_Context_FreeMemory(context_handle, pcr_value);

  TSS_FLAG init_flags = TSS_ENCDATA_SEAL;
  TSS_HKEY enc_handle;
  if ((result = Tspi_Context_CreateObject(context_handle,
                                          TSS_OBJECT_TYPE_ENCDATA,
                                          init_flags, &enc_handle))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_CreateObject";
    Tspi_Context_CloseObject(context_handle, pcrs_handle);
    Tspi_Context_CloseObject(context_handle, srk_handle);
    Tspi_Context_Close(context_handle);
    return false;
  }

  if ((result = Tspi_Data_Seal(enc_handle, srk_handle, owner_password.size(),
                               const_cast<BYTE *>(&owner_password[0]),
                               pcrs_handle))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Data_Seal";
    Tspi_Context_CloseObject(context_handle, pcrs_handle);
    Tspi_Context_CloseObject(context_handle, enc_handle);
    Tspi_Context_CloseObject(context_handle, srk_handle);
    Tspi_Context_Close(context_handle);
    return false;
  }
  Tspi_Context_CloseObject(context_handle, pcrs_handle);

  unsigned char* enc_data = NULL;
  UINT32 enc_data_length = 0;
  if ((result = Tspi_GetAttribData(enc_handle, TSS_TSPATTRIB_ENCDATA_BLOB,
                                   TSS_TSPATTRIB_ENCDATABLOB_BLOB,
                                   &enc_data_length, &enc_data))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_GetAttribData";
    Tspi_Context_CloseObject(context_handle, enc_handle);
    Tspi_Context_CloseObject(context_handle, srk_handle);
    Tspi_Context_Close(context_handle);
    return false;
  }
  Tspi_Context_CloseObject(context_handle, enc_handle);

  tpm_status->set_owner_password(enc_data, enc_data_length);

  Tspi_Context_FreeMemory(context_handle, enc_data);
  Tspi_Context_CloseObject(context_handle, srk_handle);
  Tspi_Context_Close(context_handle);

  return true;
}

bool Tpm::GetTpm(TSS_HCONTEXT context_handle, TSS_HTPM* tpm_handle) {
  TSS_RESULT result;
  TSS_HTPM local_tpm_handle;
  if ((result = Tspi_Context_GetTpmObject(context_handle, &local_tpm_handle))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_GetTpmObject";
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
    return false;
  }

  TSS_HPOLICY tpm_usage_policy;
  if ((result = Tspi_GetPolicyObject(local_tpm_handle, TSS_POLICY_USAGE,
                                     &tpm_usage_policy))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_GetPolicyObject";
    return false;
  }

  if ((result = Tspi_Policy_SetSecret(tpm_usage_policy, TSS_SECRET_MODE_PLAIN,
      owner_password.size(),
      const_cast<BYTE *>(static_cast<const BYTE *>(
          owner_password.const_data()))))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_Policy_SetSecret";
    return false;
  }

  *tpm_handle = local_tpm_handle;
  return true;
}

bool Tpm::TestTpmAuth(TSS_HTPM tpm_handle) {
  // Call Tspi_TPM_GetStatus to test the authentication
  TSS_RESULT result;
  TSS_BOOL current_status = false;
  if ((result = Tspi_TPM_GetStatus(tpm_handle,
                                   TSS_TPMSTATUS_DISABLED,
                                   &current_status))) {
    return false;
  }
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

bool Tpm::InitializeTpm(bool* OUT_took_ownership) {
  TpmStatus tpm_status;

  if (!LoadTpmStatus(&tpm_status)) {
    tpm_status.Clear();
    tpm_status.set_flags(TpmStatus::NONE);
  }

  if (OUT_took_ownership) {
    *OUT_took_ownership = false;
  }

  if (is_disabled_) {
    return false;
  }

  TSS_HCONTEXT context_handle = Connect();

  if (!context_handle) {
    LOG(ERROR) << "Failed to connect to TPM";
    return false;
  }

  SecureBlob default_owner_password(sizeof(kTpmWellKnownPassword));
  memcpy(default_owner_password.data(), kTpmWellKnownPassword,
         sizeof(kTpmWellKnownPassword));

  bool took_ownership = false;
  if (!is_owned_) {
    is_being_owned_ = true;
    file_util::Delete(FilePath(kOpenCryptokiPath), true);
    file_util::Delete(FilePath(kTpmOwnedFile), false);
    file_util::Delete(FilePath(kTpmStatusFile), false);

    if (!IsEndorsementKeyAvailable(context_handle)) {
      if (!CreateEndorsementKey(context_handle)) {
        LOG(ERROR) << "Failed to create endorsement key";
        is_being_owned_ = false;
        Disconnect(context_handle);
        return false;
      }
    }

    if (!IsEndorsementKeyAvailable(context_handle)) {
      LOG(ERROR) << "Endorsement key is not available";
      is_being_owned_ = false;
      Disconnect(context_handle);
      return false;
    }

    if (!TakeOwnership(context_handle, kMaxTimeoutRetries,
                       default_owner_password)) {
      LOG(ERROR) << "Take Ownership failed";
      is_being_owned_ = false;
      Disconnect(context_handle);
      return false;
    }

    is_owned_ = true;
    took_ownership = true;

    tpm_status.set_flags(TpmStatus::OWNED_BY_THIS_INSTALL |
                         TpmStatus::USES_WELL_KNOWN_OWNER);
    tpm_status.clear_owner_password();
    StoreTpmStatus(tpm_status);
  }

  if (OUT_took_ownership) {
    *OUT_took_ownership = took_ownership;
  }

  // Ensure the SRK is available
  TSS_RESULT result;
  TSS_HKEY srk_handle;
  TSS_UUID SRK_UUID = TSS_UUID_SRK;
  if ((result = Tspi_Context_LoadKeyByUUID(context_handle, TSS_PS_TYPE_SYSTEM,
                                           SRK_UUID, &srk_handle))) {
    is_srk_available_ = false;
  } else {
    Tspi_Context_CloseObject(context_handle, srk_handle);
    is_srk_available_ = true;
  }

  // If we can open the TPM with the default password, then we still need to
  // zero the SRK password and unrestrict it, then change the owner password.
  TSS_HTPM tpm_handle;
  if (!file_util::PathExists(FilePath(kTpmOwnedFile)) &&
      GetTpmWithAuth(context_handle, default_owner_password, &tpm_handle) &&
      TestTpmAuth(tpm_handle)) {
    if (!ZeroSrkPassword(context_handle, default_owner_password)) {
      LOG(ERROR) << "Couldn't zero SRK password";
      is_being_owned_ = false;
      Disconnect(context_handle);
      return false;
    }

    if (!UnrestrictSrk(context_handle, default_owner_password)) {
      LOG(ERROR) << "Couldn't unrestrict the SRK";
      is_being_owned_ = false;
      Disconnect(context_handle);
      return false;
    }

    SecureBlob owner_password;
    CreateOwnerPassword(&owner_password);

    tpm_status.set_flags(TpmStatus::OWNED_BY_THIS_INSTALL |
                         TpmStatus::USES_RANDOM_OWNER);
    if (!StoreOwnerPassword(owner_password, &tpm_status)) {
      tpm_status.clear_owner_password();
    }
    StoreTpmStatus(tpm_status);

    if ((result = ChangeOwnerPassword(context_handle, default_owner_password,
                                      owner_password))) {
      password_sync_lock_.Acquire();
      owner_password_.assign(owner_password.begin(), owner_password.end());
      password_sync_lock_.Release();
    }

    file_util::WriteFile(FilePath(kTpmOwnedFile), NULL, 0);
  } else {
    // If we fall through here, then the TPM owned file doesn't exist, but we
    // couldn't auth with the well-known password.  In this case, we must assume
    // that the TPM has already been owned and set to a random password, so
    // touch the TPM owned file.
    if (!file_util::PathExists(FilePath(kTpmOwnedFile))) {
      file_util::WriteFile(FilePath(kTpmOwnedFile), NULL, 0);
    }
  }

  is_being_owned_ = false;
  Disconnect(context_handle);
  return true;
}

bool Tpm::GetRandomData(size_t length, chromeos::Blob* data) {
  TSS_HCONTEXT context_handle;
  if (!OpenAndConnectTpm(&context_handle)) {
    LOG(ERROR) << "Could not open the TPM";
    return false;
  }

  TSS_HTPM tpm_handle;
  if (!GetTpm(context_handle, &tpm_handle)) {
    LOG(ERROR) << "Could not get a handle to the TPM.";
    Tspi_Context_Close(context_handle);
    return false;
  }

  TSS_RESULT result;
  SecureBlob random(length);
  BYTE* tpm_data = NULL;
  if ((result = Tspi_TPM_GetRandom(tpm_handle, random.size(), &tpm_data))) {
    TPM_LOG(ERROR, result) << "Could not get random data from the TPM";
    Tspi_Context_Close(context_handle);
    return false;
  }
  memcpy(random.data(), tpm_data, random.size());
  Tspi_Context_FreeMemory(context_handle, tpm_data);
  chromeos::SecureMemset(tpm_data, 0, random.size());
  Tspi_Context_Close(context_handle);
  data->swap(random);
  return true;
}

bool Tpm::LoadSrk(TSS_HCONTEXT context_handle, TSS_HKEY* srk_handle,
                  TSS_RESULT* result) {
  *result = TSS_SUCCESS;

  // Load the Storage Root Key
  TSS_UUID SRK_UUID = TSS_UUID_SRK;
  TSS_HKEY local_srk_handle;
  if ((*result = Tspi_Context_LoadKeyByUUID(context_handle,
                                            TSS_PS_TYPE_SYSTEM,
                                            SRK_UUID,
                                            &local_srk_handle))) {
    return false;
  }

  // Check if the SRK wants a password
  UINT32 srk_authusage;
  if ((*result = Tspi_GetAttribUint32(local_srk_handle,
                                      TSS_TSPATTRIB_KEY_INFO,
                                      TSS_TSPATTRIB_KEYINFO_AUTHUSAGE,
                                      &srk_authusage))) {
    Tspi_Context_CloseObject(context_handle,
                             local_srk_handle);
    return false;
  }

  // Give it the password if needed
  if (srk_authusage) {
    TSS_HPOLICY srk_usage_policy;
    if ((*result = Tspi_GetPolicyObject(local_srk_handle,
                                        TSS_POLICY_USAGE,
                                        &srk_usage_policy))) {
      Tspi_Context_CloseObject(context_handle, local_srk_handle);
      return false;
    }

    BYTE new_password[0];
    if ((*result = Tspi_Policy_SetSecret(srk_usage_policy,
                                         TSS_SECRET_MODE_PLAIN,
                                         0, new_password))) {
      Tspi_Context_CloseObject(context_handle, local_srk_handle);
      return false;
    }
  }

  *srk_handle = local_srk_handle;
  return true;
}

void Tpm::ClearStoredOwnerPassword() {
  TpmStatus tpm_status;
  if (LoadTpmStatus(&tpm_status)) {
    if (tpm_status.has_owner_password()) {
      tpm_status.clear_owner_password();
      StoreTpmStatus(tpm_status);
    }
  }
  password_sync_lock_.Acquire();
  owner_password_.resize(0);
  password_sync_lock_.Release();
}

bool Tpm::LoadTpmStatus(TpmStatus* serialized) {
  FilePath tpm_status_file(kTpmStatusFile);
  if (!file_util::PathExists(tpm_status_file)) {
    return false;
  }
  SecureBlob file_data;
  if (!LoadFileBytes(tpm_status_file, &file_data)) {
    return false;
  }
  if (!serialized->ParseFromArray(
           static_cast<const unsigned char*>(file_data.data()),
           file_data.size())) {
    return false;
  }
  return true;
}

bool Tpm::StoreTpmStatus(const TpmStatus& serialized) {
  int old_mask = platform_->SetMask(kDefaultUmask);
  FilePath tpm_status_file(kTpmStatusFile);
  if (file_util::PathExists(tpm_status_file)) {
    do {
      int64 file_size;
      if (!file_util::GetFileSize(tpm_status_file, &file_size)) {
        break;
      }
      SecureBlob random;
      if (!GetRandomData(file_size, &random)) {
        break;
      }
      FILE* file = file_util::OpenFile(tpm_status_file, "wb+");
      if (!file) {
        break;
      }
      if (fwrite(random.const_data(), 1, random.size(), file) !=
          random.size()) {
        file_util::CloseFile(file);
        break;
      }
      file_util::CloseFile(file);
    } while(false);
    file_util::Delete(tpm_status_file, false);
  }
  SecureBlob final_blob(serialized.ByteSize());
  serialized.SerializeWithCachedSizesToArray(
      static_cast<google::protobuf::uint8*>(final_blob.data()));
  unsigned int data_written = file_util::WriteFile(
      tpm_status_file,
      static_cast<const char*>(final_blob.const_data()),
      final_blob.size());

  if (data_written != final_blob.size()) {
    platform_->SetMask(old_mask);
    return false;
  }
  platform_->SetMask(old_mask);
  return true;
}

} // namespace tpm_init
