// Copyright (c) 2009-2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Tpm - class for handling init TPM initialization for Chrome OS

#include <base/lock.h>
#include <base/logging.h>
#include <base/scoped_ptr.h>
#include <chromeos/utility.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>

#include "crypto.h"
#include "secure_blob.h"

#ifndef TPM_INIT_TPM_H_
#define TPM_INIT_TPM_H_

namespace tpm_init {

class Tpm {
 public:

  // Default constructor
  Tpm();

  virtual ~Tpm();

  // Initializes the Tpm instance
  //
  // Parameters
  virtual bool Init();

  // Tries to connect to the TPM
  virtual bool Connect();

  // Returns true if this instance is connected to the TPM
  virtual bool IsConnected();

  // Disconnects from the TPM
  virtual void Disconnect();

  // Returns the number of simultaneously-loaded RSA keys that this TPM supports
  int GetMaxRsaKeyCount();

  // Returns the owner password if this instance was used to take ownership.
  // This will only occur when the TPM is unowned, which will be on OOBE
  //
  // Parameters
  //   owner_password (OUT) - The random owner password used
  bool GetOwnerPassword(chromeos::Blob* owner_password);

  // Returns whether or not the TPM is enabled.  This method call returns a
  // cached result because querying the TPM directly will block if ownership is
  // currently being taken (such as on a separate thread).
  bool IsEnabled() const { return !is_disabled_; }

  // Returns whether or not the TPM is owned.  This method call returns a cached
  // result because querying the TPM directly will block if ownership is
  // currently being taken (such as on a separate thread).
  bool IsOwned() const { return is_owned_; }

  // Returns whether or not the SRK is available
  bool IsSrkAvailable() const { return is_srk_available_; }

  // Runs the TPM initialization sequence.  This may take a long time due to the
  // call to Tspi_TPM_TakeOwnership.
  bool InitializeTpm();

 private:
  // Attempts to connect to tcsd
  //
  // Parameters
  //   context_handle (OUT) - The context handle to the session on success
  bool OpenAndConnectTpm(TSS_HCONTEXT* context_handle);

  // Returns the maximum simultaneously-loaded RSA key count for the TPM
  // specified by the context handle
  //
  // Parameters
  //   context_handle - The context handle for the TPM session
  int GetMaxRsaKeyCountForContext(TSS_HCONTEXT context_handle);

  // Returns whether or not the TPM is disabled by checking a flag in the TPM's
  // entry in /sys/class/misc
  bool IsDisabledCheckViaSysfs();

  // Returns whether or not the TPM is owned by checking a flag in the TPM's
  // entry in /sys/class/misc
  bool IsOwnedCheckViaSysfs();

  // Returns whether or not the TPM is enabled and owned using a call to
  // Tspi_TPM_GetCapability
  //
  // Parameters
  //   context_handle - The context handle for the TPM session
  //   enabled (OUT) - Whether the TPM is enabled
  //   owned (OUT) - Whether the TPM is owned
  void IsEnabledOwnedCheckViaContext(TSS_HCONTEXT context_handle,
                                     bool* enabled, bool* owned);

  // Attempts to create the endorsement key in the TPM
  //
  // Parameters
  //   context_handle - The context handle for the TPM session
  bool CreateEndorsementKey(TSS_HCONTEXT context_handle);

  // Checks to see if the endorsement key is available by attempting to get its
  // public key
  //
  // Parameters
  //   context_handle - The context handle for the TPM session
  bool IsEndorsementKeyAvailable(TSS_HCONTEXT context_handle);

  // Creates a random owner password
  //
  // Parameters
  //   password (OUT) - the generated password
  void CreateOwnerPassword(SecureBlob* password);

  // Attempts to take ownership of the TPM
  //
  // Parameters
  //   context_handle - The context handle for the TPM session
  //   max_timeout_tries - The maximum number of attempts to make if the call
  //                       times out, which it may occasionally do
  bool TakeOwnership(TSS_HCONTEXT context_handle, int max_timeout_tries,
                     const SecureBlob& owner_password);

  // Zeros the SRK password (sets it to an empty string)
  //
  // Parameters
  //   context_handle - The context handle for the TPM session
  //   owner_password - The owner password for the TPM
  bool ZeroSrkPassword(TSS_HCONTEXT context_handle,
                       const SecureBlob& owner_password);

  // Removes usage restrictions on the SRK
  //
  // Parameters
  //   context_handle - The context handle for the TPM session
  //   owner_password - The owner password for the TPM
  bool UnrestrictSrk(TSS_HCONTEXT context_handle,
                     const SecureBlob& owner_password);

  // Changes the owner password
  //
  // Parameters
  //   context_handle - The context handle for the TPM session
  //   previous_owner_password - The previous owner password for the TPM
  //   owner_password - The owner password for the TPM
  bool ChangeOwnerPassword(TSS_HCONTEXT context_handle,
                           const SecureBlob& previous_owner_password,
                           const SecureBlob& owner_password);

  // Gets a handle to the TPM from the specified context
  //
  // Parameters
  //   context_handle - The context handle for the TPM session
  //   tpm_handle (OUT) - The handle for the TPM on success
  bool GetTpm(TSS_HCONTEXT context_handle, TSS_HTPM* tpm_handle);

  // Gets a handle to the TPM from the specified context with the given owner
  // password
  //
  // Parameters
  //   context_handle - The context handle for the TPM session
  //   owner_password - The owner password to use when getting the handle
  //   tpm_handle (OUT) - The handle for the TPM on success
  bool GetTpmWithAuth(TSS_HCONTEXT context_handle,
                      const SecureBlob& owner_password,
                      TSS_HTPM* tpm_handle);

  // Test the TPM auth by calling Tspi_TPM_GetStatus
  //
  // Parameters
  //   tpm_handle = The TPM handle
  bool TestTpmAuth(TSS_HTPM tpm_handle);

  // The context handle for this TPM session
  TSS_HCONTEXT context_handle_;

  // The default Crypto instance to use (for generating the random owner
  // password)
  scoped_ptr<Crypto> default_crypto_;

  // The actual Crypto instance to use
  Crypto* crypto_;

  // If TPM ownership is taken, owner_password_ contains the password used
  SecureBlob owner_password_;

  // Used to provide thread-safe access to owner_password_, as it is set in the
  // initialization background thread.
  Lock password_sync_lock_;

  // Indicates if the TPM is disabled
  bool is_disabled_;

  // Indicates if the TPM is owned
  bool is_owned_;

  // Indicates if the SRK is available
  bool is_srk_available_;

  DISALLOW_COPY_AND_ASSIGN(Tpm);
};

}  // namespace tpm_init

#endif  // TPM_INIT_TPM_H_
