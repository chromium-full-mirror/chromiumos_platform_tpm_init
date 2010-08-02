# Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import os
import sys

env = Environment()

# setup sources
lib_sources = env.Split("""crypto.cc
                           secure_blob.cc
                           tpm.cc
                           tpm_init.cc
                           """)
client_sources = env.Split("""main.cc
                           """) + lib_sources

env.Append(
    CPPPATH=['.', '..'],
    CPPFLAGS=['-pie', '-fstack-protector-all', '-fPIC',
              '-fno-exceptions', '-O2', '-Wall', '-Werror'],
    LIBS = ['base', 'chromeos', 'crypto', 'rt', 'pthread', 'tspi'],
)
for key in Split('CC CXX AR RANLIB LD NM CFLAGS CCFLAGS'):
  value = os.environ.get(key)
  if value != None:
    env[key] = value

# Fix issue with scons not passing some vars through the environment.
for key in Split('PKG_CONFIG_LIBDIR PKG_CONFIG_PATH SYSROOT'):
  if os.environ.has_key(key):
    env['ENV'][key] = os.environ[key]

env.Append(LIBPATH = ['.'])

env_lib = env.Clone()
env_lib.Library('tpm_init', lib_sources)

